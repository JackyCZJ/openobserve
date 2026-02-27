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

use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};

/// M1 冻结的权限动作集合。
///
/// 该枚举是后续 RBAC/ReBAC 实现的统一动作词汇，
/// 用于隔离 HTTP Method 与权限动作语义，避免链路中出现动作别名漂移。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RbacAction {
    Read,
    List,
    Write,
    Delete,
    Admin,
}

impl RbacAction {
    /// 返回动作在语义层的标准字符串。
    ///
    /// 该函数用于日志、配置导出与权限快照输出，确保同一动作在所有上下文中
    /// 都保持一致的可比对文本值。
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "READ",
            Self::List => "LIST",
            Self::Write => "WRITE",
            Self::Delete => "DELETE",
            Self::Admin => "ADMIN",
        }
    }

    /// 将历史动作 token（含 HTTP verb）转换为 M1 冻结动作。
    ///
    /// 该函数只负责语义归一化，不承担最终权限判定逻辑，
    /// 主要用于迁移期将旧 token/旧规则映射到统一动作空间。
    pub fn from_legacy_scope_token(token: &str) -> Option<Self> {
        let normalized = token.trim().to_ascii_uppercase();
        match normalized.as_str() {
            "READ" | "GET" => Some(Self::Read),
            "LIST" => Some(Self::List),
            "WRITE" | "POST" | "PUT" | "PATCH" => Some(Self::Write),
            "DELETE" => Some(Self::Delete),
            "ADMIN" => Some(Self::Admin),
            _ => None,
        }
    }
}

impl fmt::Display for RbacAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for RbacAction {
    type Err = ();

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_legacy_scope_token(input).ok_or(())
    }
}

/// M1 冻结的资源类型字典。
///
/// 该枚举定义了权限模型的资源主键空间，路由中的复数、别名会映射到这些标准 key。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RbacResource {
    Org,
    Stream,
    Dashboard,
    Folder,
    Alert,
    Pipeline,
    Destination,
    Template,
    Report,
    Function,
    Settings,
    User,
    ServiceAccount,
    Role,
    Action,
}

impl RbacResource {
    /// 返回资源类型在语义冻结文档中的标准 key。
    ///
    /// 该函数用于跨模块共享同一资源命名，避免使用路由片段直接参与权限计算。
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Org => "org",
            Self::Stream => "stream",
            Self::Dashboard => "dashboard",
            Self::Folder => "folder",
            Self::Alert => "alert",
            Self::Pipeline => "pipeline",
            Self::Destination => "destination",
            Self::Template => "template",
            Self::Report => "report",
            Self::Function => "function",
            Self::Settings => "settings",
            Self::User => "user",
            Self::ServiceAccount => "service_account",
            Self::Role => "role",
            Self::Action => "action",
        }
    }

    /// 将路由段（单数/复数/历史别名）转换为冻结资源类型。
    ///
    /// 该函数用于统一入口层解析结果，避免每个调用点重复维护字符串匹配分支。
    pub fn from_route_segment(segment: &str) -> Option<Self> {
        let normalized = segment.trim().to_ascii_lowercase();
        match normalized.as_str() {
            "org" | "organization" | "organizations" => Some(Self::Org),
            "stream" | "streams" => Some(Self::Stream),
            "dashboard" | "dashboards" => Some(Self::Dashboard),
            "folder" | "folders" => Some(Self::Folder),
            "alert" | "alerts" => Some(Self::Alert),
            "pipeline" | "pipelines" => Some(Self::Pipeline),
            "destination" | "destinations" => Some(Self::Destination),
            "template" | "templates" => Some(Self::Template),
            "report" | "reports" => Some(Self::Report),
            "function" | "functions" => Some(Self::Function),
            "setting" | "settings" => Some(Self::Settings),
            "user" | "users" => Some(Self::User),
            "service_account" | "service_accounts" => Some(Self::ServiceAccount),
            "role" | "roles" => Some(Self::Role),
            "action" | "actions" => Some(Self::Action),
            _ => None,
        }
    }

    /// 校验对象 ID 是否满足 M1 统一约束。
    ///
    /// 约束目标是保证跨存储与跨接口的一致可解析性：
    /// - 长度 1..=256
    /// - 禁止路径分隔符与控制字符
    /// - 允许 `_all_` 这类保留前缀用于组织级聚合语义
    pub fn is_valid_object_id(self, object_id: &str) -> bool {
        let candidate = object_id.trim();
        !candidate.is_empty()
            && candidate.len() <= 256
            && !candidate
                .as_bytes()
                .iter()
                .any(|byte| *byte == b'/' || *byte == b'\\' || (*byte).is_ascii_control())
    }
}

impl fmt::Display for RbacResource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// M1 冻结的基线角色集合。
///
/// 该角色集用于定义默认权限上限，并为后续 custom role 约束提供统一参考。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RbacBaselineRole {
    Root,
    Admin,
    Editor,
    Viewer,
}

const FULL_ACTIONS: [RbacAction; 5] = [
    RbacAction::Read,
    RbacAction::List,
    RbacAction::Write,
    RbacAction::Delete,
    RbacAction::Admin,
];

const EDITOR_ACTIONS: [RbacAction; 3] = [RbacAction::Read, RbacAction::List, RbacAction::Write];

const VIEWER_ACTIONS: [RbacAction; 2] = [RbacAction::Read, RbacAction::List];

const CUSTOM_ROLE_ACTIONS: [RbacAction; 4] = [
    RbacAction::Read,
    RbacAction::List,
    RbacAction::Write,
    RbacAction::Delete,
];

const INGEST_ACTIONS: [RbacAction; 1] = [RbacAction::Write];

/// 旧 token 语义兼容窗口（天）。
///
/// 默认值与 M1 冻结文档保持一致，可在后续里程碑改为配置项读取。
pub const LEGACY_TOKEN_COMPAT_WINDOW_DAYS: u16 = 90;

impl RbacBaselineRole {
    /// 返回角色在语义层的标准名称。
    ///
    /// 该函数用于角色快照、审计日志和迁移报告，确保角色标识稳定。
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::Admin => "admin",
            Self::Editor => "editor",
            Self::Viewer => "viewer",
        }
    }

    /// 返回基线角色允许的动作集合。
    ///
    /// 该函数表达的是“默认能力上限”，不包含未来的 deny/条件策略，
    /// 便于在 M2 引擎层直接作为初始策略模板。
    pub fn allowed_actions(self) -> &'static [RbacAction] {
        match self {
            Self::Root | Self::Admin => &FULL_ACTIONS,
            Self::Editor => &EDITOR_ACTIONS,
            Self::Viewer => &VIEWER_ACTIONS,
        }
    }
}

impl fmt::Display for RbacBaselineRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 返回 custom role 可配置的动作白名单。
///
/// 按 M1 冻结约束，custom role 不允许直接授予 `ADMIN`，
/// 该白名单可用于 API 层输入校验和前端可选项生成。
pub const fn custom_role_action_whitelist() -> &'static [RbacAction] {
    &CUSTOM_ROLE_ACTIONS
}

/// 将旧 token scope 文本映射为 M1 动作集合。
///
/// 映射策略采用“兼容优先”原则：未知 scope 默认回落到 `READ/LIST/WRITE`，
/// 以避免迁移窗口内出现大面积误拒绝。
pub fn map_legacy_scope_to_actions(scope: &str) -> &'static [RbacAction] {
    let normalized = scope.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "ingest" => &INGEST_ACTIONS,
        "read" => &VIEWER_ACTIONS,
        "read_write" | "rw" => &EDITOR_ACTIONS,
        "admin" => &FULL_ACTIONS,
        _ => &EDITOR_ACTIONS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_from_legacy_scope_token() {
        assert_eq!(RbacAction::from_legacy_scope_token("GET"), Some(RbacAction::Read));
        assert_eq!(RbacAction::from_legacy_scope_token("list"), Some(RbacAction::List));
        assert_eq!(RbacAction::from_legacy_scope_token("PATCH"), Some(RbacAction::Write));
        assert_eq!(
            RbacAction::from_legacy_scope_token("DELETE"),
            Some(RbacAction::Delete)
        );
        assert_eq!(
            RbacAction::from_legacy_scope_token("ADMIN"),
            Some(RbacAction::Admin)
        );
        assert_eq!(RbacAction::from_legacy_scope_token("UNKNOWN"), None);
    }

    #[test]
    fn test_resource_from_route_segment() {
        assert_eq!(
            RbacResource::from_route_segment("organizations"),
            Some(RbacResource::Org)
        );
        assert_eq!(
            RbacResource::from_route_segment("streams"),
            Some(RbacResource::Stream)
        );
        assert_eq!(
            RbacResource::from_route_segment("service_accounts"),
            Some(RbacResource::ServiceAccount)
        );
        assert_eq!(RbacResource::from_route_segment("unknown"), None);
    }

    #[test]
    fn test_resource_object_id_validation() {
        assert!(RbacResource::Dashboard.is_valid_object_id("dash-prod-01"));
        assert!(RbacResource::Org.is_valid_object_id("_all_default"));
        assert!(!RbacResource::Alert.is_valid_object_id(""));
        assert!(!RbacResource::Alert.is_valid_object_id(" / "));
        assert!(!RbacResource::Alert.is_valid_object_id("alert/name"));
        assert!(!RbacResource::Alert.is_valid_object_id("alert\\name"));
    }

    #[test]
    fn test_baseline_role_actions() {
        assert_eq!(
            RbacBaselineRole::Viewer.allowed_actions(),
            [RbacAction::Read, RbacAction::List]
        );
        assert_eq!(
            RbacBaselineRole::Editor.allowed_actions(),
            [RbacAction::Read, RbacAction::List, RbacAction::Write]
        );
        assert_eq!(
            RbacBaselineRole::Admin.allowed_actions(),
            [
                RbacAction::Read,
                RbacAction::List,
                RbacAction::Write,
                RbacAction::Delete,
                RbacAction::Admin,
            ]
        );
    }

    #[test]
    fn test_custom_role_whitelist() {
        assert_eq!(
            custom_role_action_whitelist(),
            [
                RbacAction::Read,
                RbacAction::List,
                RbacAction::Write,
                RbacAction::Delete,
            ]
        );
    }

    #[test]
    fn test_legacy_scope_mapping() {
        assert_eq!(map_legacy_scope_to_actions("ingest"), [RbacAction::Write]);
        assert_eq!(
            map_legacy_scope_to_actions("read"),
            [RbacAction::Read, RbacAction::List]
        );
        assert_eq!(
            map_legacy_scope_to_actions("rw"),
            [RbacAction::Read, RbacAction::List, RbacAction::Write]
        );
        assert_eq!(
            map_legacy_scope_to_actions("admin"),
            [
                RbacAction::Read,
                RbacAction::List,
                RbacAction::Write,
                RbacAction::Delete,
                RbacAction::Admin,
            ]
        );
        assert_eq!(
            map_legacy_scope_to_actions("unknown_scope"),
            [RbacAction::Read, RbacAction::List, RbacAction::Write]
        );
    }

    #[test]
    fn test_legacy_compat_window_default() {
        assert_eq!(LEGACY_TOKEN_COMPAT_WINDOW_DAYS, 90);
    }
}
