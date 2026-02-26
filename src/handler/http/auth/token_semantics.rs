// Copyright 2026 OpenObserve Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use config::{
    TokenSemanticsMode, get_config,
    meta::user::UserRole,
    utils::{base64, json},
};

use crate::{
    common::meta::{
        token::{TokenIntrospectionResponse, TokenRoleSource, TokenType},
        user::AuthTokens,
    },
    service::db,
};

#[cfg(feature = "enterprise")]
use super::token::get_user_name_from_token;

/// 描述认证字符串在运行时的解析结果，供鉴权与自省接口共用。
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RuntimeAuthContext {
    pub from_session: bool,
    pub normalized_auth: String,
    pub token_type_hint: TokenType,
}

/// 按兼容模式解析认证上下文，作为 legacy/new 双栈入口。
pub fn resolve_runtime_auth_context(mode: TokenSemanticsMode, raw_auth: &str) -> RuntimeAuthContext {
    match mode {
        TokenSemanticsMode::Legacy => parse_session_wrapped_auth(raw_auth, false),
        TokenSemanticsMode::New => parse_session_wrapped_auth(raw_auth, true),
    }
}

/// 从请求头中提取可用于自省的认证字符串，优先使用 Authorization。
pub fn extract_auth_from_request_headers(
    auth_header: Option<&str>,
    cookie_header: Option<&str>,
) -> Option<String> {
    if let Some(auth) = auth_header {
        let trimmed = auth.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    cookie_header.and_then(extract_auth_from_cookie_header)
}

/// 对输入认证串执行最小自省，返回 token 类型、scope 与角色来源等核心字段。
pub async fn introspect_auth_token(auth: &str) -> TokenIntrospectionResponse {
    let cfg = get_config();
    let mode = cfg.auth.token_semantics_mode.clone();
    let runtime_auth = resolve_runtime_auth_context(mode.clone(), auth);
    let mut response = TokenIntrospectionResponse::new(mode.as_str());
    response.token_type = runtime_auth.token_type_hint.clone();
    if runtime_auth.from_session {
        response.role_source = TokenRoleSource::Session;
    }

    if runtime_auth.normalized_auth.starts_with("Basic ") {
        if let Some((user_id, secret)) = decode_basic_credentials(&runtime_auth.normalized_auth) {
            response.subject = Some(user_id.clone());
            if let Some((org_id, role)) = resolve_role_from_basic_credentials(&user_id, &secret).await
            {
                response.scope.push(format!("org:{org_id}"));
                response.scope.push(format!("role:{role}"));
                response.org_id = Some(org_id);
                response.role = Some(role.clone());
                if !runtime_auth.from_session {
                    response.role_source = TokenRoleSource::OrgUserRecord;
                }
                response.token_type = resolve_token_type_from_role(Some(&role), runtime_auth.from_session);
            } else {
                response.token_type = resolve_token_type_from_role(None, runtime_auth.from_session);
            }
        } else {
            response.token_type = TokenType::Unknown;
            response.role_source = TokenRoleSource::Unknown;
        }
    } else if runtime_auth.normalized_auth.starts_with("Bearer ") {
        response.token_type = resolve_token_type_from_role(None, runtime_auth.from_session);
        #[cfg(feature = "enterprise")]
        if let Some(user_id) = get_user_name_from_token(&runtime_auth.normalized_auth).await {
            response.subject = Some(user_id);
            if !runtime_auth.from_session {
                response.role_source = TokenRoleSource::JwtClaim;
            }
        }
    } else if runtime_auth.normalized_auth.starts_with("session ") {
        response.token_type = TokenType::SessionBearer;
        response.role_source = TokenRoleSource::Session;
    } else {
        response.token_type = TokenType::Unknown;
    }

    response
}

/// 解析 Session 包装格式，并在 new 模式下识别明文 session 前缀。
fn parse_session_wrapped_auth(
    raw_auth: &str,
    support_plain_session_prefix: bool,
) -> RuntimeAuthContext {
    let trimmed = raw_auth.trim();
    if let Some(rest) = trimmed.strip_prefix("Session::")
        && let Some((_session_id, token)) = rest.split_once("::")
    {
        return RuntimeAuthContext {
            from_session: true,
            normalized_auth: token.to_string(),
            token_type_hint: TokenType::SessionBearer,
        };
    }

    if support_plain_session_prefix && trimmed.starts_with("session ") {
        return RuntimeAuthContext {
            from_session: true,
            normalized_auth: trimmed.to_string(),
            token_type_hint: TokenType::SessionBearer,
        };
    }

    RuntimeAuthContext {
        from_session: false,
        normalized_auth: trimmed.to_string(),
        token_type_hint: infer_token_type_hint(trimmed),
    }
}

/// 基于认证头基础形态给出 token 类型提示，后续会结合 DB 信息做细化。
fn infer_token_type_hint(auth: &str) -> TokenType {
    if auth.starts_with("Basic ") || auth.starts_with("Bearer ") {
        TokenType::Pat
    } else {
        TokenType::Unknown
    }
}

/// 从 Basic 认证中解码用户与密钥，用于后续角色来源判断。
fn decode_basic_credentials(auth: &str) -> Option<(String, String)> {
    let encoded = auth.strip_prefix("Basic ")?;
    let decoded = base64::decode(encoded.trim()).ok()?;
    decoded
        .split_once(':')
        .map(|(user, secret)| (user.to_string(), secret.to_string()))
}

/// 根据角色与 session 来源解析最终 token 类型，保证三类语义稳定输出。
fn resolve_token_type_from_role(role: Option<&UserRole>, from_session: bool) -> TokenType {
    if from_session {
        TokenType::SessionBearer
    } else if matches!(role, Some(UserRole::ServiceAccount)) {
        TokenType::ServiceToken
    } else {
        TokenType::Pat
    }
}

/// 通过 Basic 凭证在用户组织信息中定位角色与组织，作为最小自省依据。
async fn resolve_role_from_basic_credentials(
    user_id: &str,
    secret: &str,
) -> Option<(String, UserRole)> {
    let db_user = db::user::get_db_user(user_id).await.ok()?;
    db_user
        .organizations
        .into_iter()
        .find(|org| org.token == secret)
        .map(|org| (org.name, org.role))
}

/// 从 auth_tokens Cookie 中读取 access_token，供没有 Authorization 头时回退使用。
fn extract_auth_from_cookie_header(cookie_header: &str) -> Option<String> {
    let cookie_value = parse_cookie_value(cookie_header, "auth_tokens")?;
    let decoded_cookie = base64::decode(cookie_value.trim()).ok()?;
    let auth_tokens: AuthTokens = json::from_str(&decoded_cookie).ok()?;
    if auth_tokens.access_token.trim().is_empty() {
        None
    } else {
        Some(auth_tokens.access_token)
    }
}

/// 从标准 Cookie 头中提取指定 cookie 值，不依赖额外解析器以便复用到轻量场景。
fn parse_cookie_value(cookie_header: &str, cookie_name: &str) -> Option<String> {
    cookie_header
        .split(';')
        .filter_map(|kv| kv.trim().split_once('='))
        .find_map(|(name, value)| (name == cookie_name).then(|| value.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 验证 legacy 模式可以解析 Session:: 前缀，并提取内部真实认证信息。
    #[test]
    fn test_resolve_runtime_auth_context_legacy_session_wrapper() {
        let context = resolve_runtime_auth_context(
            TokenSemanticsMode::Legacy,
            "Session::sid::Basic dGVzdDp0b2tlbg==",
        );
        assert!(context.from_session);
        assert_eq!(context.normalized_auth, "Basic dGVzdDp0b2tlbg==");
        assert_eq!(context.token_type_hint, TokenType::SessionBearer);
    }

    /// 验证 legacy 模式不会把明文 session 前缀当作新语义处理，保持兼容。
    #[test]
    fn test_resolve_runtime_auth_context_legacy_plain_session() {
        let context = resolve_runtime_auth_context(TokenSemanticsMode::Legacy, "session abc");
        assert!(!context.from_session);
        assert_eq!(context.normalized_auth, "session abc");
        assert_eq!(context.token_type_hint, TokenType::Unknown);
    }

    /// 验证 new 模式会识别明文 session 前缀，用于后续统一语义收敛。
    #[test]
    fn test_resolve_runtime_auth_context_new_plain_session() {
        let context = resolve_runtime_auth_context(TokenSemanticsMode::New, "session abc");
        assert!(context.from_session);
        assert_eq!(context.normalized_auth, "session abc");
        assert_eq!(context.token_type_hint, TokenType::SessionBearer);
    }

    /// 验证请求头提取策略优先 Authorization，避免 Cookie 覆盖显式输入。
    #[test]
    fn test_extract_auth_from_request_headers_priority() {
        let auth = extract_auth_from_request_headers(
            Some("Bearer test-token"),
            Some("auth_tokens=dGVzdA=="),
        );
        assert_eq!(auth, Some("Bearer test-token".to_string()));
    }

    /// 验证能从 auth_tokens Cookie 中解码 access_token，满足无头场景自省需求。
    #[test]
    fn test_extract_auth_from_cookie_header() {
        let token_json = json::to_string(&AuthTokens {
            access_token: "session sid-001".to_string(),
            refresh_token: String::new(),
        })
        .expect("serialize auth tokens");
        let cookie_header = format!("auth_tokens={}", base64::encode(&token_json));
        let auth = extract_auth_from_request_headers(None, Some(&cookie_header));
        assert_eq!(auth, Some("session sid-001".to_string()));
    }

    /// 验证角色驱动的 token 类型映射，确保 PAT 与 Service Token 可稳定区分。
    #[test]
    fn test_resolve_token_type_from_role() {
        assert_eq!(
            resolve_token_type_from_role(Some(&UserRole::ServiceAccount), false),
            TokenType::ServiceToken
        );
        assert_eq!(
            resolve_token_type_from_role(Some(&UserRole::Admin), false),
            TokenType::Pat
        );
        assert_eq!(
            resolve_token_type_from_role(Some(&UserRole::Admin), true),
            TokenType::SessionBearer
        );
    }
}
