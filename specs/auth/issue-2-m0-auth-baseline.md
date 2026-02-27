# Issue #2（M0）鉴权基线文档（最小可合并增量）

## 1. 范围与目标

本次只做 **M0 最小可合并文档增量**，聚焦四件事：

1. 鉴权调用链梳理（含关键分支与落点）。
2. 复现矩阵模板（单独文档）。
3. 400/401/403 边界与 reason code 建议。
4. auth decision log 最小字段建议。

非目标：本次不改线上行为、不引入破坏性协议变更。

---

## 2. 鉴权调用链（当前实现）

### 2.1 HTTP `/api` 主链路

入口与中间件挂载：

- `/api` 业务路由：`src/handler/http/router/mod.rs:974`
- 鉴权中间件挂载：`src/handler/http/router/mod.rs:883`
- 鉴权中间件实现：`src/handler/http/router/mod.rs:102`

主链路（简化）：

```text
HTTP Request
  -> auth_middleware
    -> AuthExtractor::from_request_parts
      -> extract_auth_str_from_parts（cookie/header/session 归一化）
      -> 产出 {auth, method, o2_type, org_id, bypass_check, parent_id}
    -> oo_validator
      -> oo_validator_internal
        -> Basic 分支: validator -> validate_credentials(_ext) -> check_permissions
        -> Bearer 分支: token_validator -> verify_decode_token -> check_permissions
        -> auth_ext 分支: validator
    -> success: 注入 user_id 头给下游 handler
```

关键代码位置：

- `AuthExtractor`/拒绝响应：`src/common/utils/auth.rs:223`、`src/common/utils/auth.rs:237`
- 认证字符串抽取（cookie/header/session）：`src/common/utils/auth.rs:1228`
- `oo_validator_internal`（Basic/Bearer/auth_ext 分流）：`src/handler/http/auth/validator.rs:864`
- Basic 主校验入口：`src/handler/http/auth/validator.rs:139`
- Bearer 主校验入口：`src/handler/http/auth/token.rs:27`
- RBAC/OpenFGA 判定：`src/handler/http/auth/validator.rs:1075`

### 2.2 其他 HTTP 鉴权链路

- AWS Firehose：`src/handler/http/router/mod.rs:910` -> `src/handler/http/auth/validator.rs:714`
- GCP：`src/handler/http/router/mod.rs:922` -> `src/handler/http/auth/validator.rs:758`
- RUM：`src/handler/http/router/mod.rs:934` -> `src/handler/http/auth/validator.rs:804`
- Proxy：`src/handler/http/router/mod.rs:209` -> `src/handler/http/auth/validator.rs:1010`
- Action Server：`src/handler/http/auth/action_server.rs:51`

### 2.3 gRPC 鉴权链路（并行体系）

- 入口：`src/handler/grpc/auth/mod.rs:28`
- 先校验 internal/super-cluster token，再走 Basic credentials 与组织头。

---

## 3. 400/401/403 边界与 reason code 建议

> 原则：
> - **400**：请求语义/格式错误（客户端可改请求立即重试）。
> - **401**：身份未建立或凭证无效（需重新认证/换凭证）。
> - **403**：身份已建立但无权限（需授权变更，不是重登可解）。

### 3.1 当前实现观察（与建议边界的差异）

1. 多数“格式错误”场景目前也返回 401（如 Basic/base64 解析失败、AWS/GCP key 解码失败）。
   - 例：`src/handler/http/auth/validator.rs:882`、`src/handler/http/auth/validator.rs:725`、`src/handler/http/auth/validator.rs:775`
2. `AuthExtractor` 缺失鉴权信息时返回 401 JSON（合理）。
   - `src/common/utils/auth.rs:237`
3. RBAC 拒绝返回 403（合理）。
   - `src/handler/http/auth/validator.rs:201`
4. 存在一个历史不一致点：`HttpResponse::unauthorized` 使用了 HTTP 403，但 body code=401。
   - `src/common/meta/http.rs:154`

### 3.2 M0 reason code 命名建议

建议统一机器可读字段 `reason_code`，命名：`AUTH_<HTTP_STATUS>_<SCENE>`。

建议首批清单：

- 400
  - `AUTH_400_MALFORMED_AUTH_HEADER`
  - `AUTH_400_INVALID_BASE64`
  - `AUTH_400_MISSING_REQUIRED_AUTH_PARAM`
  - `AUTH_400_INVALID_AUTH_SCHEME`
- 401
  - `AUTH_401_MISSING_CREDENTIALS`
  - `AUTH_401_INVALID_CREDENTIALS`
  - `AUTH_401_TOKEN_EXPIRED`
  - `AUTH_401_TOKEN_VERIFICATION_FAILED`
  - `AUTH_401_SESSION_NOT_FOUND`
- 403
  - `AUTH_403_PERMISSION_DENIED`
  - `AUTH_403_STATIC_TOKEN_DISALLOWED`
  - `AUTH_403_TOKEN_SUBJECT_NOT_IN_ORG`

### 3.3 建议判定顺序（避免状态码漂移）

1. 先做协议与格式校验 -> 400。
2. 再做凭证真伪/时效校验 -> 401。
3. 最后做权限校验（RBAC/对象级授权）-> 403。

---

## 4. Auth Decision Log 最小字段（M0）

建议每次鉴权决策输出一条结构化日志（允许采样），最小字段如下：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `ts` | RFC3339 string | 是 | 决策时间 |
| `trace_id` | string | 是 | 关联请求链路 |
| `request_id` | string | 否 | 网关/应用请求 ID |
| `protocol` | enum(`http`,`grpc`) | 是 | 协议类型 |
| `method` | string | 是 | 请求方法 |
| `path_template` | string | 是 | 路由模板（避免泄露原始 ID） |
| `org_id` | string | 否 | 组织上下文 |
| `auth_type` | enum(`basic`,`bearer`,`session`,`auth_ext`,`token_only`,`none`) | 是 | 凭证类型 |
| `principal` | string | 否 | 用户标识（建议脱敏/哈希） |
| `decision` | enum(`allow`,`deny`) | 是 | 结果 |
| `http_status` | int | 是 | 结果状态码 |
| `reason_code` | string | 是 | 机器可读失败原因 |
| `latency_ms` | int | 是 | 鉴权耗时 |

示例：

```json
{
  "ts": "2026-02-26T15:00:00Z",
  "trace_id": "01H...",
  "protocol": "http",
  "method": "POST",
  "path_template": "/api/{org_id}/_search",
  "org_id": "default",
  "auth_type": "bearer",
  "principal": "hash:8f3a...",
  "decision": "deny",
  "http_status": 403,
  "reason_code": "AUTH_403_PERMISSION_DENIED",
  "latency_ms": 7
}
```

---

## 5. 复现矩阵模板

复现矩阵模板见：`specs/auth/repro-matrix-template.md`

---

## 6. M0 下一步（文档后的最小代码增量建议）

1. 先补一个 **`reason_code` 常量集合**（不改行为，只做定义与映射占位）。
2. 在 auth 中间件失败路径补充 **decision log 字段骨架**（先日志，不改响应体）。
3. 按复现矩阵逐步把“格式错误”从 401 收敛到 400（分批改，保持兼容开关）。
