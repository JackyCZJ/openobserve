# RBAC M5（Issue #7）OSS 最小接口说明

本文档描述 OSS 下新增/开放的最小 RBAC 接口骨架，目标是让前后端先完成路由与数据结构对齐，再逐步替换为持久化与完整策略引擎。

## 已开放接口（与 enterprise 路由命名保持一致）

- `POST /api/{org_id}/roles`
- `GET /api/{org_id}/roles`
- `PUT /api/{org_id}/roles/{role_id}`
- `DELETE /api/{org_id}/roles/{role_id}`
- `DELETE /api/{org_id}/roles/bulk`
- `GET /api/{org_id}/roles/{role_id}/permissions/{resource}`
- `GET /api/{org_id}/roles/{role_id}/users`
- `GET /api/{org_id}/users/{user_id}/roles`

- `POST /api/{org_id}/groups`
- `GET /api/{org_id}/groups`
- `PUT /api/{org_id}/groups/{group_name}`
- `GET /api/{org_id}/groups/{group_name}`
- `DELETE /api/{org_id}/groups/{group_name}`
- `DELETE /api/{org_id}/groups/bulk`
- `GET /api/{org_id}/users/{user_id}/groups`

- `GET /api/{org_id}/resources`

## 新增权限模拟器接口

- `POST /api/{org_id}/authz/simulate`

请求体：

```json
{
  "subject": "user:alice@example.com",
  "resource": "stream",
  "action": "post"
}
```

响应体（示例）：

```json
{
  "allowed": true,
  "decision": "allow",
  "decision_chain": [
    {
      "stage": "direct_role_binding",
      "decision": "hit",
      "reason": "检查主体是否被直接绑定到角色",
      "matched": ["custom_writer"]
    },
    {
      "stage": "permission_match",
      "decision": "hit",
      "reason": "检查角色权限是否覆盖 resource + action",
      "matched": ["custom_writer:stream:post"]
    },
    {
      "stage": "final_decision",
      "decision": "allow",
      "reason": "至少命中一条有效授权关系"
    }
  ]
}
```

## 当前实现边界

- 该实现为 **内存态最小骨架**（进程重启后不会保留）。
- 目标是保证接口契约、字段命名与 UI 接口调用先稳定。
- 复杂策略（持久化、跨组织继承、冲突规则、deny 优先细粒度）在后续里程碑补齐。

## UI 接入点（本次未改 UI 代码）

可在前端权限调试页/Token 详情页接入：

1. 基础数据面板：
   - 读取 `/roles`、`/groups`、`/users/{id}/roles`、`/users/{id}/groups`。
2. 权限解释面板：
   - 调用 `POST /authz/simulate`。
   - 用 `decision_chain` 渲染“命中链路”和“拒绝原因”。
3. Token 权限可视化：
   - 将 token 解析出的主体（subject）映射为 `simulate` 请求中的 `subject`。
   - 对关键资源执行批量模拟并聚合展示读写标签。
