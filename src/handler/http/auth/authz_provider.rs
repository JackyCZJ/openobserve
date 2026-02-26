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

#[cfg(feature = "enterprise")]
use async_trait::async_trait;

#[cfg(feature = "enterprise")]
const AUTHZ_PROVIDER_ENV_KEY: &str = "ZO_AUTHZ_PROVIDER";

/// 定义鉴权 provider 类型，当前只落地 Local 实现，便于后续扩展其他 provider。
#[cfg(any(feature = "enterprise", test))]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum AuthzProviderKind {
    Local,
}

/// 将配置值解析为 provider 类型；未知值统一回退到 Local，保证线上行为稳定。
#[cfg(any(feature = "enterprise", test))]
fn parse_authz_provider_kind(value: Option<&str>) -> AuthzProviderKind {
    match value.map(str::trim).filter(|v| !v.is_empty()) {
        Some(provider) if provider.eq_ignore_ascii_case("local") => AuthzProviderKind::Local,
        _ => AuthzProviderKind::Local,
    }
}

/// 从环境变量读取 provider 选择结果；若未配置或配置非法则使用 Local。
#[cfg(feature = "enterprise")]
fn authz_provider_kind_from_env() -> AuthzProviderKind {
    parse_authz_provider_kind(std::env::var(AUTHZ_PROVIDER_ENV_KEY).ok().as_deref())
}

/// 描述一次权限判定所需的最小上下文，统一给不同鉴权 provider 使用。
#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, Copy)]
pub(crate) struct IsAllowedRequest<'a> {
    pub org_id: &'a str,
    pub user_id: &'a str,
    pub permission: &'a str,
    pub object: &'a str,
    pub parent: &'a str,
    pub role: &'a str,
}

/// 描述一次对象列表查询请求，保证 list_objects 语义在 provider 间一致。
#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, Copy)]
pub(crate) struct ListObjectsRequest<'a> {
    pub user_id: &'a str,
    pub permission: &'a str,
    pub object_type: &'a str,
    pub org_id: &'a str,
    pub role: &'a str,
}

/// 描述一次关系展开请求，用于未来支持按关系树展开可访问对象。
#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, Copy)]
pub(crate) struct ExpandRelationsRequest<'a> {
    pub user_id: &'a str,
    pub permission: &'a str,
    pub object_type: &'a str,
    pub org_id: &'a str,
    pub role: &'a str,
}

/// 定义鉴权 provider 能力边界，覆盖权限判定、对象列表和关系展开三类核心语义。
#[cfg(feature = "enterprise")]
#[async_trait]
pub(crate) trait AuthzProvider: Send + Sync {
    /// 执行单对象权限判定，返回当前用户在上下文中的最终允许结果。
    async fn is_allowed(&self, request: IsAllowedRequest<'_>) -> bool;

    /// 列出用户在指定对象类型下可访问的对象集合。
    async fn list_objects(
        &self,
        request: ListObjectsRequest<'_>,
    ) -> Result<Vec<String>, anyhow::Error>;

    /// 展开用户与对象类型之间的关系，返回可直接用于过滤的对象集合。
    async fn expand_relations(
        &self,
        request: ExpandRelationsRequest<'_>,
    ) -> Result<Vec<String>, anyhow::Error>;
}

/// Local provider 复用当前 OpenFGA 逻辑，作为 M2 阶段默认实现。
#[cfg(feature = "enterprise")]
pub(crate) struct LocalAuthzProvider;

#[cfg(feature = "enterprise")]
#[async_trait]
impl AuthzProvider for LocalAuthzProvider {
    /// 使用现有 OpenFGA is_allowed 逻辑完成权限判定，确保行为与改造前一致。
    async fn is_allowed(&self, request: IsAllowedRequest<'_>) -> bool {
        o2_openfga::authorizer::authz::is_allowed(
            request.org_id,
            request.user_id,
            request.permission,
            request.object,
            request.parent,
            request.role,
        )
        .await
    }

    /// 直接复用现有 OpenFGA list_objects 行为，不改变返回结果语义。
    async fn list_objects(
        &self,
        request: ListObjectsRequest<'_>,
    ) -> Result<Vec<String>, anyhow::Error> {
        o2_openfga::authorizer::authz::list_objects(
            request.user_id,
            request.permission,
            request.object_type,
            request.org_id,
            request.role,
        )
        .await
    }

    /// 当前 Local provider 暂无独立关系展开能力，返回空集合并让调用方回退到 list_objects。
    async fn expand_relations(
        &self,
        _request: ExpandRelationsRequest<'_>,
    ) -> Result<Vec<String>, anyhow::Error> {
        Ok(Vec::new())
    }
}

#[cfg(feature = "enterprise")]
static LOCAL_AUTHZ_PROVIDER: LocalAuthzProvider = LocalAuthzProvider;

/// 根据 provider 类型返回对应实现；当前仅支持 Local。
#[cfg(feature = "enterprise")]
fn resolve_authz_provider(kind: AuthzProviderKind) -> &'static dyn AuthzProvider {
    match kind {
        AuthzProviderKind::Local => &LOCAL_AUTHZ_PROVIDER,
    }
}

/// 返回默认鉴权 provider；当前固定为 Local，后续可在此扩展按配置路由。
#[cfg(feature = "enterprise")]
pub(crate) fn default_authz_provider() -> &'static dyn AuthzProvider {
    resolve_authz_provider(authz_provider_kind_from_env())
}

#[cfg(test)]
mod tests {
    use super::{AuthzProviderKind, parse_authz_provider_kind};

    /// 验证显式配置 local 时能正确解析到 Local provider，避免分发路径偏离预期。
    #[test]
    fn test_parse_authz_provider_kind_with_local() {
        assert_eq!(
            parse_authz_provider_kind(Some("local")),
            AuthzProviderKind::Local
        );
    }

    /// 验证非法 provider 配置会回退到 Local，确保兼容旧行为且不影响线上鉴权。
    #[test]
    fn test_parse_authz_provider_kind_with_invalid_value() {
        assert_eq!(
            parse_authz_provider_kind(Some("unknown-provider")),
            AuthzProviderKind::Local
        );
    }

    /// 验证空字符串和缺失配置都回退到 Local，保证默认值策略稳定。
    #[test]
    fn test_parse_authz_provider_kind_with_empty_value() {
        assert_eq!(parse_authz_provider_kind(Some("   ")), AuthzProviderKind::Local);
        assert_eq!(parse_authz_provider_kind(None), AuthzProviderKind::Local);
    }
}
