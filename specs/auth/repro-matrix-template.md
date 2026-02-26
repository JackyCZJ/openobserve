# 鉴权复现矩阵模板（Issue #2 / M0）

> 用途：统一记录“预期 vs 实际”鉴权行为，支撑状态码边界与 reason code 收敛。

## 1. 填写规则

- `expected_*`：本轮目标行为。
- `actual_*`：当前实现实测。
- `reason_code`：优先使用 `AUTH_<HTTP_STATUS>_<SCENE>`。
- `trace_id`：必须可回查日志。

## 2. 复现矩阵

| case_id | endpoint | method | auth_input | precondition | expected_status | expected_reason_code | actual_status | actual_reason_code | trace_id | result | note |
|---|---|---|---|---|---:|---|---:|---|---|---|---|
| AUTH-M0-001 | `/api/{org}/_search` | POST | 无 Authorization/Cookie | 无 | 401 | AUTH_401_MISSING_CREDENTIALS | TBD | TBD | TBD | TBD | |
| AUTH-M0-002 | `/api/{org}/_search` | POST | `Authorization: Basic <非法base64>` | 无 | 400 | AUTH_400_INVALID_BASE64 | TBD | TBD | TBD | TBD | |
| AUTH-M0-003 | `/api/{org}/_search` | POST | `Authorization: Basic <base64(no colon)>` | 无 | 400 | AUTH_400_MALFORMED_AUTH_HEADER | TBD | TBD | TBD | TBD | |
| AUTH-M0-004 | `/api/{org}/_search` | POST | `Authorization: Bearer <过期token>` | token 过期 | 401 | AUTH_401_TOKEN_EXPIRED | TBD | TBD | TBD | TBD | |
| AUTH-M0-005 | `/api/{org}/_search` | POST | `Authorization: Bearer <签名错误token>` | token 篡改 | 401 | AUTH_401_TOKEN_VERIFICATION_FAILED | TBD | TBD | TBD | TBD | |
| AUTH-M0-006 | `/api/{org}/_search` | POST | 有效 Bearer | 用户无该对象权限 | 403 | AUTH_403_PERMISSION_DENIED | TBD | TBD | TBD | TBD | |
| AUTH-M0-007 | `/aws/{org}/{stream}/_kinesis_firehose` | POST | `X-Amz-Firehose-Access-Key=<非法base64>` | 无 | 400 | AUTH_400_INVALID_BASE64 | TBD | TBD | TBD | TBD | |
| AUTH-M0-008 | `/gcp/{org}/{stream}/_sub` | POST | 缺失 `API-Key` | 无 | 401 | AUTH_401_MISSING_CREDENTIALS | TBD | TBD | TBD | TBD | |
| AUTH-M0-009 | `/rum/v1/{org}/rum` | POST | 缺失 `oo-api-key/o2-api-key` | 无 | 401 | AUTH_401_MISSING_CREDENTIALS | TBD | TBD | TBD | TBD | |
| AUTH-M0-010 | `/api/{org}/service_accounts/...` | GET | service account static token | `allow_static_token=false` | 403 | AUTH_403_STATIC_TOKEN_DISALLOWED | TBD | TBD | TBD | TBD | |

## 3. 可选附加字段（按需）

- `principal`
- `org_id`
- `auth_type`
- `latency_ms`
- `path_template`
