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

use config::meta::user::UserRole;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// 表示认证令牌在 M4 重构中的语义类型，用于区分不同认证来源。
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TokenType {
    SessionBearer,
    Pat,
    ServiceToken,
    Unknown,
}

/// 表示角色信息来源，便于后续与策略引擎做统一对接。
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TokenRoleSource {
    Session,
    OrgUserRecord,
    JwtClaim,
    Unknown,
}

/// 令牌自省接口的最小稳定返回体。
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct TokenIntrospectionResponse {
    pub semantics_mode: String,
    pub token_type: TokenType,
    #[serde(default)]
    pub scope: Vec<String>,
    pub role_source: TokenRoleSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<UserRole>,
}

impl TokenIntrospectionResponse {
    /// 根据语义模式初始化响应骨架，确保接口字段稳定且向后兼容。
    pub fn new(semantics_mode: &str) -> Self {
        Self {
            semantics_mode: semantics_mode.to_string(),
            token_type: TokenType::Unknown,
            scope: Vec::new(),
            role_source: TokenRoleSource::Unknown,
            subject: None,
            org_id: None,
            role: None,
        }
    }
}
