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
pub async fn simulate_permissions(org_id: String, req: PermissionSimulationRequest) -> Response {
    let subject = normalize_subject(&req.subject);
    let resource = normalize_name(&req.resource);
    let action = normalize_name(&req.action);

    let mut decision_chain = Vec::new();

    let (direct_roles, inherited_roles, matched_permissions) = with_org_store(&org_id, |store| {
        if let Some(store) = store {
            let (direct_roles, inherited_roles) = collect_roles_for_user(store, &subject);
            let all_roles = direct_roles
                .iter()
                .cloned()
                .chain(inherited_roles.iter().cloned())
                .collect::<HashSet<_>>();

            let matched_permissions = all_roles
                .iter()
                .flat_map(|role| {
                    store
                        .roles
                        .get(role)
                        .map(|record| {
                            record
                                .permissions
                                .iter()
                                .filter_map(|permission| {
                                    let resource_match = permission.object == "*"
                                        || resource == "*"
                                        || permission.object == resource
                                        || resource.starts_with(&permission.object);
                                    let action_match = permission.permission == "*"
                                        || permission.permission.contains("allow")
                                        || permission.permission == action;

                                    if resource_match && action_match {
                                        Some(format!("{role}:{}:{}", permission.object, permission.permission))
                                    } else {
                                        None
                                    }
                                })
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default()
                })
                .collect::<Vec<_>>();

            (direct_roles, inherited_roles, matched_permissions)
        } else {
            (HashSet::new(), HashSet::new(), Vec::new())
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

    let mut matched_permissions_sorted = matched_permissions;
    matched_permissions_sorted.sort();

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
            decision: if matched_permissions_sorted.is_empty() {
                "miss".to_string()
            } else {
                "hit".to_string()
            },
            reason: "检查角色权限是否覆盖 resource + action".to_string(),
            matched: matched_permissions_sorted.clone(),
        });
    }

    let allowed = has_admin_role || !matched_permissions_sorted.is_empty();
    decision_chain.push(PermissionSimulationStep {
        stage: "final_decision".to_string(),
        decision: if allowed {
            "allow".to_string()
        } else {
            "deny".to_string()
        },
        reason: if allowed {
            "至少命中一条有效授权关系".to_string()
        } else {
            "未命中可用授权关系，默认拒绝".to_string()
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
}
