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

#![cfg(not(feature = "enterprise"))]

use std::collections::{HashMap, HashSet};

use axum::{Json, response::{IntoResponse, Response}};
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::common::meta::{
    http::HttpResponse as MetaHttpResponse,
    user::{UserGroup, UserGroupRequest, UserRoleRequest, get_roles as get_builtin_roles},
};

/// 兼容 OSS 的最小 RBAC 存储：按组织保存角色、组与权限关系。
static OSS_AUTHZ_STORE: Lazy<RwLock<HashMap<String, OssOrgAuthzStore>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

#[derive(Clone, Debug, Default)]
struct OssOrgAuthzStore {
    roles: HashMap<String, OssRoleRecord>,
    groups: HashMap<String, UserGroup>,
}

#[derive(Clone, Debug, Default)]
struct OssRoleRecord {
    users: HashSet<String>,
    permissions: HashSet<OssRolePermission>,
}

/// 对齐 enterprise `update_role` 的最小权限项结构。
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize, ToSchema)]
pub struct OssRolePermission {
    pub object: String,
    pub permission: String,
}

/// 对齐 enterprise `RoleRequest` 的最小请求结构。
#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema)]
pub struct OssRoleRequest {
    #[serde(default)]
    pub add: Vec<OssRolePermission>,
    #[serde(default)]
    pub remove: Vec<OssRolePermission>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub add_users: Option<HashSet<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remove_users: Option<HashSet<String>>,
}

/// 权限模拟器请求：主体 + 资源 + 动作。
#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema)]
pub struct PermissionSimulationRequest {
    pub subject: String,
    pub resource: String,
    pub action: String,
}

/// 权限模拟器单步决策信息，用于解释链路来源。
#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema)]
pub struct PermissionSimulationStep {
    pub stage: String,
    pub decision: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matched: Vec<String>,
}

/// 权限模拟器基础响应，返回最终决策和决策链。
#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema)]
pub struct PermissionSimulationResponse {
    pub allowed: bool,
    pub decision: String,
    pub decision_chain: Vec<PermissionSimulationStep>,
}

/// 统一角色名格式，确保存储与查询时大小写和符号行为一致。
fn normalize_name(name: &str) -> String {
    name
        .trim()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>()
}

/// 将输入主体规范化成内部用户标识，支持 `user:` 前缀。
fn normalize_subject(subject: &str) -> String {
    subject
        .trim()
        .strip_prefix("user:")
        .unwrap_or(subject.trim())
        .to_string()
}

/// 判断是否是内置角色，内置角色不允许通过自定义角色 API 覆盖。
fn is_builtin_role(role_name: &str) -> bool {
    get_builtin_roles()
        .iter()
        .any(|role| role.to_string().eq_ignore_ascii_case(role_name))
}

/// 获取组织级存储并执行写操作，集中处理组织初始化逻辑。
fn with_org_store_mut<R>(org_id: &str, f: impl FnOnce(&mut OssOrgAuthzStore) -> R) -> R {
    let mut guard = OSS_AUTHZ_STORE.write();
    let store = guard.entry(org_id.to_string()).or_default();
    f(store)
}

/// 获取组织级存储并执行只读操作，简化读取路径。
fn with_org_store<R>(org_id: &str, f: impl FnOnce(Option<&OssOrgAuthzStore>) -> R) -> R {
    let guard = OSS_AUTHZ_STORE.read();
    f(guard.get(org_id))
}

/// 聚合某个用户的直接角色与组继承角色，供列表与模拟器复用。
fn collect_roles_for_user(store: &OssOrgAuthzStore, user_id: &str) -> (HashSet<String>, HashSet<String>) {
    let direct_roles = store
        .roles
        .iter()
        .filter_map(|(role_name, role)| {
            if role.users.contains(user_id) {
                Some(role_name.clone())
            } else {
                None
            }
        })
        .collect::<HashSet<_>>();

    let inherited_roles = store
        .groups
        .values()
        .filter(|group| {
            group
                .users
                .as_ref()
                .is_some_and(|users| users.contains(user_id))
        })
        .flat_map(|group| group.roles.clone().unwrap_or_default().into_iter())
        .map(|role| normalize_name(&role))
        .collect::<HashSet<_>>();

    (direct_roles, inherited_roles)
}

/// 权限效果类型：仅区分允许与拒绝，供模拟器执行“deny 优先”判定。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PermissionEffect {
    Allow,
    Deny,
}

/// 将外部动作词统一映射到内部动作语义，避免 GET/POST/PATCH 等别名分散在匹配逻辑里。
///
/// 映射规则遵循“兼容优先”：
/// - `GET/READ` 统一到 `read`
/// - `POST/PUT/PATCH/WRITE` 统一到 `write`
/// - `LIST/DELETE/ADMIN` 保持独立
/// - 未知动作保留归一化后的原值，方便后续扩展。
fn normalize_action_keyword(action: &str) -> String {
    match normalize_name(action).as_str() {
        "get" | "read" => "read".to_string(),
        "post" | "put" | "patch" | "write" => "write".to_string(),
        "list" => "list".to_string(),
        "delete" => "delete".to_string(),
        "admin" => "admin".to_string(),
        other => other.to_string(),
    }
}

/// 判断资源是否命中权限 scope，支持精确匹配、全局匹配与带边界的前缀匹配。
///
/// 边界前缀规则用于避免 `stream_prod` 误匹配 `stream_production`：
/// 仅当资源以 `scope + "_"` 开头时才视为 scope 继承命中。
fn matches_resource_scope(scope: &str, resource: &str) -> bool {
    if scope == "*" || resource == "*" || scope == resource {
        return true;
    }
    resource
        .strip_prefix(scope)
        .is_some_and(|suffix| suffix.starts_with('_'))
}

/// 将权限文本解析为动作匹配结果与权限效果，用于统一处理 allow/deny/历史动作写法。
///
/// 支持三类写法：
/// - 全局效果：`allow` / `deny` / `*`
/// - 显式动作效果：`allow_<action>` / `deny_<action>`
/// - 历史动作写法：`get/post/patch/...`（默认按 allow 处理）
fn resolve_permission_effect(permission: &str, request_action: &str) -> Option<PermissionEffect> {
    let normalized_permission = normalize_name(permission);
    let normalized_action = normalize_action_keyword(request_action);

    match normalized_permission.as_str() {
        "*" | "allow" => return Some(PermissionEffect::Allow),
        "deny" => return Some(PermissionEffect::Deny),
        _ => {}
    }

    if let Some(action) = normalized_permission.strip_prefix("allow_") {
        if normalize_action_keyword(action) == normalized_action {
            return Some(PermissionEffect::Allow);
        }
        return None;
    }

    if let Some(action) = normalized_permission.strip_prefix("deny_") {
        if normalize_action_keyword(action) == normalized_action {
            return Some(PermissionEffect::Deny);
        }
        return None;
    }

    if normalize_action_keyword(&normalized_permission) == normalized_action {
        return Some(PermissionEffect::Allow);
    }

    None
}

/// OSS 角色创建最小实现：支持角色名和基础自定义权限保存。
pub async fn create_role(org_id: String, user_req: UserRoleRequest) -> Response {
    let role_name = normalize_name(&user_req.role);

    if role_name.is_empty() {
        return MetaHttpResponse::bad_request("Role name cannot be empty");
    }
    if is_builtin_role(&role_name) {
        return MetaHttpResponse::bad_request("Cannot create built-in role");
    }

    let custom_permissions = user_req
        .custom
        .unwrap_or_default()
        .into_iter()
        .map(|permission| OssRolePermission {
            object: normalize_name(&permission),
            permission: "allow".to_string(),
        })
        .collect::<HashSet<_>>();

    let inserted = with_org_store_mut(&org_id, |store| {
        if store.roles.contains_key(&role_name) {
            false
        } else {
            store.roles.insert(
                role_name.clone(),
                OssRoleRecord {
                    users: HashSet::new(),
                    permissions: custom_permissions,
                },
            );
            true
        }
    });

    if inserted {
        MetaHttpResponse::ok("Role created successfully")
    } else {
        MetaHttpResponse::bad_request("Role already exists")
    }
}

/// OSS 角色删除最小实现：同步移除组内关联，保证关系数据不悬空。
pub async fn delete_role(org_id: String, role_name: String) -> Response {
    let role_name = normalize_name(&role_name);

    with_org_store_mut(&org_id, |store| {
        store.roles.remove(&role_name);
        for group in store.groups.values_mut() {
            if let Some(roles) = group.roles.as_mut() {
                roles.remove(&role_name);
            }
        }
    });

    MetaHttpResponse::ok(serde_json::json!({"successful": "true"}))
}

/// OSS 角色批量删除最小实现：逐个执行并返回批处理结果。
pub async fn delete_role_bulk(
    org_id: String,
    req: crate::handler::http::request::BulkDeleteRequest,
) -> Response {
    let mut successful = Vec::new();
    let mut unsuccessful = Vec::new();

    for role in req.ids {
        let role_name = normalize_name(&role);
        let deleted = with_org_store_mut(&org_id, |store| {
            let existed = store.roles.remove(&role_name).is_some();
            if existed {
                for group in store.groups.values_mut() {
                    if let Some(roles) = group.roles.as_mut() {
                        roles.remove(&role_name);
                    }
                }
            }
            existed
        });

        if deleted {
            successful.push(role);
        } else {
            unsuccessful.push(role);
        }
    }

    MetaHttpResponse::json(crate::handler::http::request::BulkDeleteResponse {
        successful,
        unsuccessful,
        err: None,
    })
}

/// OSS 角色列表最小实现：返回内置角色 + 当前组织自定义角色。
pub async fn get_roles(org_id: String) -> Response {
    let mut roles = get_builtin_roles()
        .into_iter()
        .map(|role| role.to_string().to_lowercase())
        .collect::<HashSet<_>>();

    with_org_store(&org_id, |store| {
        if let Some(store) = store {
            for role in store.roles.keys() {
                roles.insert(role.clone());
            }
        }
    });

    let mut sorted_roles = roles.into_iter().collect::<Vec<_>>();
    sorted_roles.sort();

    Json(sorted_roles).into_response()
}

/// OSS 角色更新最小实现：支持权限增删和用户绑定增删。
pub async fn update_role(org_id: String, role_id: String, update_role: OssRoleRequest) -> Response {
    let role_name = normalize_name(&role_id);

    with_org_store_mut(&org_id, |store| {
        let role = store.roles.entry(role_name).or_default();

        for add in update_role.add {
            role.permissions.insert(OssRolePermission {
                object: normalize_name(&add.object),
                permission: normalize_name(&add.permission),
            });
        }
        for remove in update_role.remove {
            role.permissions.remove(&OssRolePermission {
                object: normalize_name(&remove.object),
                permission: normalize_name(&remove.permission),
            });
        }

        if let Some(add_users) = update_role.add_users {
            role.users.extend(add_users.into_iter().map(|user| user.to_lowercase()));
        }
        if let Some(remove_users) = update_role.remove_users {
            for user in remove_users {
                role.users.remove(&user.to_lowercase());
            }
        }
    });

    MetaHttpResponse::ok("Role updated successfully")
}

/// OSS 角色权限查询最小实现：按资源前缀筛选返回权限项。
pub async fn get_role_permissions(org_id: String, role_id: String, resource: String) -> Response {
    let role_name = normalize_name(&role_id);
    let resource = normalize_name(&resource);

    let permissions = with_org_store(&org_id, |store| {
        store
            .and_then(|store| store.roles.get(&role_name))
            .map(|role| {
                role.permissions
                    .iter()
                    .filter(|permission| {
                        resource.is_empty()
                            || permission.object == resource
                            || permission.object.starts_with(&resource)
                    })
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    });

    Json(permissions).into_response()
}

/// OSS 查询角色绑定用户最小实现：包含直接绑定和组继承来源。
pub async fn get_users_with_role(org_id: String, role_id: String) -> Response {
    let role_name = normalize_name(&role_id);

    let mut users = with_org_store(&org_id, |store| {
        if let Some(store) = store {
            let mut users = HashSet::new();

            if let Some(role) = store.roles.get(&role_name) {
                users.extend(role.users.iter().cloned());
            }

            for group in store.groups.values() {
                let has_role = group
                    .roles
                    .as_ref()
                    .is_some_and(|roles| roles.iter().any(|role| normalize_name(role) == role_name));
                if has_role {
                    users.extend(group.users.clone().unwrap_or_default());
                }
            }

            users.into_iter().collect::<Vec<_>>()
        } else {
            Vec::new()
        }
    });

    users.sort();
    Json(users).into_response()
}

/// OSS 查询用户角色最小实现：返回直接角色与组继承角色并去重。
pub async fn get_roles_for_user(org_id: String, user_email: String) -> Response {
    let user_id = normalize_subject(&user_email);
    let mut roles = with_org_store(&org_id, |store| {
        if let Some(store) = store {
            let (direct_roles, inherited_roles) = collect_roles_for_user(store, &user_id);
            direct_roles
                .into_iter()
                .chain(inherited_roles)
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        }
    });

    roles.sort();
    Json(roles).into_response()
}

/// OSS 查询用户组最小实现：按用户成员关系筛选组名。
pub async fn get_groups_for_user(org_id: String, user_email: String) -> Response {
    let user_id = normalize_subject(&user_email);
    let mut groups = with_org_store(&org_id, |store| {
        store
            .map(|store| {
                store
                    .groups
                    .values()
                    .filter_map(|group| {
                        if group
                            .users
                            .as_ref()
                            .is_some_and(|users| users.contains(&user_id))
                        {
                            Some(group.name.clone())
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    });

    groups.sort();
    Json(groups).into_response()
}

/// OSS 组创建最小实现：保存组名、成员与角色关系。
pub async fn create_group(org_id: String, user_group: UserGroup) -> Response {
    let mut group = user_group;
    group.name = normalize_name(&group.name);

    if group.name.is_empty() {
        return MetaHttpResponse::bad_request("Group name cannot be empty");
    }

    let inserted = with_org_store_mut(&org_id, |store| {
        if store.groups.contains_key(&group.name) {
            false
        } else {
            if let Some(users) = group.users.as_mut() {
                *users = users.iter().map(|user| normalize_subject(user)).collect();
            }
            if let Some(roles) = group.roles.as_mut() {
                *roles = roles.iter().map(|role| normalize_name(role)).collect();
            }
            store.groups.insert(group.name.clone(), group);
            true
        }
    });

    if inserted {
        MetaHttpResponse::ok("Group created successfully")
    } else {
        MetaHttpResponse::bad_request("Group already exists")
    }
}

/// OSS 组更新最小实现：支持成员与角色增删。
pub async fn update_group(org_id: String, group_name: String, user_group: UserGroupRequest) -> Response {
    let group_name = normalize_name(&group_name);

    with_org_store_mut(&org_id, |store| {
        let group = store.groups.entry(group_name.clone()).or_insert_with(|| UserGroup {
            name: group_name.clone(),
            users: Some(HashSet::new()),
            roles: Some(HashSet::new()),
        });

        if let Some(add_users) = user_group.add_users {
            group
                .users
                .get_or_insert_with(HashSet::new)
                .extend(add_users.into_iter().map(|user| normalize_subject(&user)));
        }
        if let Some(remove_users) = user_group.remove_users {
            for user in remove_users {
                group
                    .users
                    .get_or_insert_with(HashSet::new)
                    .remove(&normalize_subject(&user));
            }
        }

        if let Some(add_roles) = user_group.add_roles {
            group
                .roles
                .get_or_insert_with(HashSet::new)
                .extend(add_roles.into_iter().map(|role| normalize_name(&role)));
        }
        if let Some(remove_roles) = user_group.remove_roles {
            for role in remove_roles {
                group
                    .roles
                    .get_or_insert_with(HashSet::new)
                    .remove(&normalize_name(&role));
            }
        }
    });

    MetaHttpResponse::ok("Group updated successfully")
}

/// OSS 组列表最小实现：返回组织内所有组名。
pub async fn get_groups(org_id: String) -> Response {
    let mut groups = with_org_store(&org_id, |store| {
        store
            .map(|store| store.groups.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default()
    });

    groups.sort();
    Json(groups).into_response()
}

/// OSS 组详情最小实现：未命中时返回空成员组结构，保证前端可直接渲染。
pub async fn get_group_details(org_id: String, group_name: String) -> Response {
    let group_name = normalize_name(&group_name);

    let group = with_org_store(&org_id, |store| {
        store
            .and_then(|store| store.groups.get(&group_name))
            .cloned()
            .unwrap_or(UserGroup {
                name: group_name,
                users: Some(HashSet::new()),
                roles: Some(HashSet::new()),
            })
    });

    Json(group).into_response()
}

/// OSS 资源字典最小实现：提供权限模拟器与 UI 的可选资源提示。
pub async fn get_resources() -> Response {
    Json(vec![
        serde_json::json!({"key": "role", "actions": ["GET", "POST", "PUT", "DELETE"]}),
        serde_json::json!({"key": "group", "actions": ["GET", "POST", "PUT", "DELETE"]}),
        serde_json::json!({"key": "stream", "actions": ["GET", "POST", "PUT", "DELETE"]}),
        serde_json::json!({"key": "dashboard", "actions": ["GET", "POST", "PUT", "DELETE"]}),
    ])
    .into_response()
}

/// OSS 组删除最小实现：按组名删除并返回统一成功格式。
pub async fn delete_group(org_id: String, group_name: String) -> Response {
    let group_name = normalize_name(&group_name);
    with_org_store_mut(&org_id, |store| {
        store.groups.remove(&group_name);
    });

    MetaHttpResponse::ok(serde_json::json!({"successful": "true"}))
}

/// OSS 组批量删除最小实现：逐个删除并汇总成功/失败结果。
pub async fn delete_group_bulk(
    org_id: String,
    req: crate::handler::http::request::BulkDeleteRequest,
) -> Response {
    let mut successful = Vec::new();
    let mut unsuccessful = Vec::new();

    for group in req.ids {
        let group_name = normalize_name(&group);
        let deleted = with_org_store_mut(&org_id, |store| store.groups.remove(&group_name).is_some());
        if deleted {
            successful.push(group);
        } else {
            unsuccessful.push(group);
        }
    }

    MetaHttpResponse::json(crate::handler::http::request::BulkDeleteResponse {
        successful,
        unsuccessful,
        err: None,
    })
}

/// OSS 权限模拟器最小实现：基于直接角色、组继承和权限项生成可解释决策链。
///
/// 执行顺序固定为：
/// 1. 动作映射（HTTP 动词 -> 统一动作语义）
/// 2. 主体关系收敛（直绑角色 + 组继承角色）
/// 3. scope 匹配（精确/边界前缀/全局）
/// 4. 冲突裁决（deny 优先覆盖 allow）
///
/// 该顺序保证调试时可以直接从 `decision_chain` 还原每一步决策依据。
pub async fn simulate_permissions(org_id: String, req: PermissionSimulationRequest) -> Response {
    let subject = normalize_subject(&req.subject);
    let resource = normalize_name(&req.resource);
    let normalized_action = normalize_action_keyword(&req.action);

    let mut decision_chain = Vec::new();
    decision_chain.push(PermissionSimulationStep {
        stage: "action_mapping".to_string(),
        decision: "mapped".to_string(),
        reason: "将请求动作映射到统一动作语义，避免 GET/POST 等别名导致判定漂移".to_string(),
        matched: vec![format!("{} -> {}", req.action, normalized_action)],
    });

    let (direct_roles, inherited_roles, matched_allow_permissions, matched_deny_permissions) =
        with_org_store(&org_id, |store| {
        if let Some(store) = store {
            let (direct_roles, inherited_roles) = collect_roles_for_user(store, &subject);
            let all_roles = direct_roles
                .iter()
                .cloned()
                .chain(inherited_roles.iter().cloned())
                .collect::<HashSet<_>>();

            let mut matched_allow_permissions = Vec::new();
            let mut matched_deny_permissions = Vec::new();
            for role in &all_roles {
                if let Some(record) = store.roles.get(role) {
                    for permission in &record.permissions {
                        if !matches_resource_scope(&permission.object, &resource) {
                            continue;
                        }
                        match resolve_permission_effect(&permission.permission, &normalized_action) {
                            Some(PermissionEffect::Allow) => matched_allow_permissions.push(format!(
                                "{role}:{}:{}",
                                permission.object, permission.permission
                            )),
                            Some(PermissionEffect::Deny) => matched_deny_permissions.push(format!(
                                "{role}:{}:{}",
                                permission.object, permission.permission
                            )),
                            None => {}
                        }
                    }
                }
            }

            (
                direct_roles,
                inherited_roles,
                matched_allow_permissions,
                matched_deny_permissions,
            )
        } else {
            (HashSet::new(), HashSet::new(), Vec::new(), Vec::new())
        }
    });

    let mut direct_roles_sorted = direct_roles.iter().cloned().collect::<Vec<_>>();
    direct_roles_sorted.sort();
    decision_chain.push(PermissionSimulationStep {
        stage: "direct_role_binding".to_string(),
        decision: if direct_roles_sorted.is_empty() {
            "miss".to_string()
        } else {
            "hit".to_string()
        },
        reason: "检查主体是否被直接绑定到角色".to_string(),
        matched: direct_roles_sorted,
    });

    let mut inherited_roles_sorted = inherited_roles.iter().cloned().collect::<Vec<_>>();
    inherited_roles_sorted.sort();
    decision_chain.push(PermissionSimulationStep {
        stage: "group_role_inheritance".to_string(),
        decision: if inherited_roles_sorted.is_empty() {
            "miss".to_string()
        } else {
            "hit".to_string()
        },
        reason: "检查主体是否通过组继承角色".to_string(),
        matched: inherited_roles_sorted,
    });

    let mut matched_allow_permissions_sorted = matched_allow_permissions;
    matched_allow_permissions_sorted.sort();
    let mut matched_deny_permissions_sorted = matched_deny_permissions;
    matched_deny_permissions_sorted.sort();

    let has_admin_role = direct_roles
        .iter()
        .chain(inherited_roles.iter())
        .any(|role| role == "admin" || role == "root");

    if has_admin_role {
        decision_chain.push(PermissionSimulationStep {
            stage: "admin_shortcut".to_string(),
            decision: "allow".to_string(),
            reason: "命中内置管理角色，放行请求".to_string(),
            matched: vec!["admin/root".to_string()],
        });
    } else {
        decision_chain.push(PermissionSimulationStep {
            stage: "permission_match".to_string(),
            decision: if matched_allow_permissions_sorted.is_empty() {
                "miss".to_string()
            } else {
                "hit".to_string()
            },
            reason: "检查角色是否命中 allow 权限".to_string(),
            matched: matched_allow_permissions_sorted.clone(),
        });
        decision_chain.push(PermissionSimulationStep {
            stage: "deny_priority".to_string(),
            decision: if matched_deny_permissions_sorted.is_empty() {
                "miss".to_string()
            } else {
                "hit".to_string()
            },
            reason: "若命中 deny 权限则覆盖 allow，确保拒绝策略优先".to_string(),
            matched: matched_deny_permissions_sorted.clone(),
        });
    }

    let allowed = has_admin_role
        || (matched_deny_permissions_sorted.is_empty() && !matched_allow_permissions_sorted.is_empty());
    decision_chain.push(PermissionSimulationStep {
        stage: "final_decision".to_string(),
        decision: if allowed {
            "allow".to_string()
        } else {
            "deny".to_string()
        },
        reason: if allowed {
            if has_admin_role {
                "命中内置管理角色，直接放行".to_string()
            } else {
                "命中 allow 且未被 deny 覆盖".to_string()
            }
        } else {
            "命中 deny 或未命中可用 allow，按默认拒绝返回".to_string()
        },
        matched: Vec::new(),
    });

    Json(PermissionSimulationResponse {
        allowed,
        decision: if allowed {
            "allow".to_string()
        } else {
            "deny".to_string()
        },
        decision_chain,
    })
    .into_response()
}

#[cfg(test)]
/// 测试辅助：重置内存存储，避免用例之间互相污染。
fn reset_store() {
    OSS_AUTHZ_STORE.write().clear();
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use http_body_util::BodyExt;

    use super::*;

    /// 读取响应体 JSON，避免在测试里重复样板代码。
    async fn read_json<T: serde::de::DeserializeOwned>(resp: Response) -> T {
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    /// 验证用户直绑角色 + 权限后，模拟器能够给出 allow 决策链。
    async fn test_simulator_allow_with_direct_role() {
        reset_store();

        let create_resp = create_role(
            "org1".to_string(),
            UserRoleRequest {
                role: "custom_writer".to_string(),
                custom: None,
            },
        )
        .await;
        assert_eq!(create_resp.status(), StatusCode::OK);

        let update_resp = update_role(
            "org1".to_string(),
            "custom_writer".to_string(),
            OssRoleRequest {
                add: vec![OssRolePermission {
                    object: "stream".to_string(),
                    permission: "post".to_string(),
                }],
                remove: vec![],
                add_users: Some(HashSet::from(["alice@example.com".to_string()])),
                remove_users: None,
            },
        )
        .await;
        assert_eq!(update_resp.status(), StatusCode::OK);

        let resp = simulate_permissions(
            "org1".to_string(),
            PermissionSimulationRequest {
                subject: "alice@example.com".to_string(),
                resource: "stream".to_string(),
                action: "post".to_string(),
            },
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        let payload: PermissionSimulationResponse = read_json(resp).await;
        assert!(payload.allowed);
        assert_eq!(payload.decision, "allow");
        assert!(payload
            .decision_chain
            .iter()
            .any(|step| step.stage == "direct_role_binding" && step.decision == "hit"));
    }

    #[tokio::test]
    /// 验证无绑定关系时，模拟器默认返回 deny。
    async fn test_simulator_deny_without_bindings() {
        reset_store();

        let resp = simulate_permissions(
            "org2".to_string(),
            PermissionSimulationRequest {
                subject: "bob@example.com".to_string(),
                resource: "dashboard".to_string(),
                action: "get".to_string(),
            },
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        let payload: PermissionSimulationResponse = read_json(resp).await;
        assert!(!payload.allowed);
        assert_eq!(payload.decision, "deny");
    }

    #[tokio::test]
    /// 验证用户角色查询会合并直接角色和组继承角色。
    async fn test_get_roles_for_user_merges_direct_and_group_roles() {
        reset_store();

        let _ = create_role(
            "org3".to_string(),
            UserRoleRequest {
                role: "custom_reader".to_string(),
                custom: None,
            },
        )
        .await;
        let _ = create_role(
            "org3".to_string(),
            UserRoleRequest {
                role: "custom_writer".to_string(),
                custom: None,
            },
        )
        .await;

        let _ = update_role(
            "org3".to_string(),
            "custom_reader".to_string(),
            OssRoleRequest {
                add: vec![],
                remove: vec![],
                add_users: Some(HashSet::from(["carol@example.com".to_string()])),
                remove_users: None,
            },
        )
        .await;

        let _ = create_group(
            "org3".to_string(),
            UserGroup {
                name: "dev_group".to_string(),
                users: Some(HashSet::from(["carol@example.com".to_string()])),
                roles: Some(HashSet::from(["custom_writer".to_string()])),
            },
        )
        .await;

        let resp = get_roles_for_user("org3".to_string(), "carol@example.com".to_string()).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let roles: Vec<String> = read_json(resp).await;
        assert!(roles.contains(&"custom_reader".to_string()));
        assert!(roles.contains(&"custom_writer".to_string()));
    }

    #[test]
    /// 验证动作映射会将历史 HTTP 动词统一到冻结动作语义，避免匹配歧义。
    fn test_normalize_action_keyword_aliases() {
        assert_eq!(normalize_action_keyword("GET"), "read");
        assert_eq!(normalize_action_keyword("post"), "write");
        assert_eq!(normalize_action_keyword("PATCH"), "write");
        assert_eq!(normalize_action_keyword("LIST"), "list");
        assert_eq!(normalize_action_keyword("DELETE"), "delete");
    }

    #[test]
    /// 验证 scope 判定使用边界前缀规则，避免相似字符串产生误授权。
    fn test_matches_resource_scope_with_boundary() {
        assert!(matches_resource_scope("stream_team_a", "stream_team_a"));
        assert!(matches_resource_scope("stream_team_a", "stream_team_a_logs"));
        assert!(!matches_resource_scope("stream_team_a", "stream_team_ab"));
        assert!(matches_resource_scope("*", "stream_team_ab"));
    }

    #[tokio::test]
    /// 验证同一请求同时命中 allow 与 deny 时，最终决策必须是 deny。
    async fn test_simulator_deny_takes_precedence_over_allow() {
        reset_store();

        let _ = create_role(
            "org4".to_string(),
            UserRoleRequest {
                role: "custom_guard".to_string(),
                custom: None,
            },
        )
        .await;

        let _ = update_role(
            "org4".to_string(),
            "custom_guard".to_string(),
            OssRoleRequest {
                add: vec![
                    OssRolePermission {
                        object: "stream/team/a".to_string(),
                        permission: "allow_write".to_string(),
                    },
                    OssRolePermission {
                        object: "stream/team/a".to_string(),
                        permission: "deny_write".to_string(),
                    },
                ],
                remove: vec![],
                add_users: Some(HashSet::from(["dora@example.com".to_string()])),
                remove_users: None,
            },
        )
        .await;

        let resp = simulate_permissions(
            "org4".to_string(),
            PermissionSimulationRequest {
                subject: "dora@example.com".to_string(),
                resource: "stream/team/a".to_string(),
                action: "POST".to_string(),
            },
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        let payload: PermissionSimulationResponse = read_json(resp).await;
        assert!(!payload.allowed);
        assert_eq!(payload.decision, "deny");
        assert!(payload
            .decision_chain
            .iter()
            .any(|step| step.stage == "deny_priority" && step.decision == "hit"));
    }

    #[tokio::test]
    /// 验证 scope 判定支持层级资源，并在边界不命中时正确返回 deny。
    async fn test_simulator_scope_evaluation() {
        reset_store();

        let _ = create_role(
            "org5".to_string(),
            UserRoleRequest {
                role: "scope_reader".to_string(),
                custom: None,
            },
        )
        .await;

        let _ = update_role(
            "org5".to_string(),
            "scope_reader".to_string(),
            OssRoleRequest {
                add: vec![OssRolePermission {
                    object: "stream/team/a".to_string(),
                    permission: "allow_read".to_string(),
                }],
                remove: vec![],
                add_users: Some(HashSet::from(["erin@example.com".to_string()])),
                remove_users: None,
            },
        )
        .await;

        let scoped_hit = simulate_permissions(
            "org5".to_string(),
            PermissionSimulationRequest {
                subject: "erin@example.com".to_string(),
                resource: "stream/team/a/error".to_string(),
                action: "GET".to_string(),
            },
        )
        .await;
        let scoped_hit_payload: PermissionSimulationResponse = read_json(scoped_hit).await;
        assert!(scoped_hit_payload.allowed);

        let scoped_miss = simulate_permissions(
            "org5".to_string(),
            PermissionSimulationRequest {
                subject: "erin@example.com".to_string(),
                resource: "stream/team/ab".to_string(),
                action: "GET".to_string(),
            },
        )
        .await;
        let scoped_miss_payload: PermissionSimulationResponse = read_json(scoped_miss).await;
        assert!(!scoped_miss_payload.allowed);
    }
}
