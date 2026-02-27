# Issue #8 (M6) RBAC 测试矩阵（最小可合并增量）

## 1. 范围与目标

本矩阵聚焦 M6 的最小可运行闭环：

- 补齐可立即执行的单元测试（动作映射、deny 优先、scope 判定）。
- 给出集成/安全/灰度/回滚的最小验收面，作为后续迭代的基线。
- 保证每类测试都有明确入口、通过标准与失败处置。

## 2. 测试矩阵

| 类别 | 目标 | 最小用例（当前已落地） | 执行入口 | 通过标准 | 失败处理 |
|---|---|---|---|---|---|
| 单元测试 | 锁定核心判定语义 | `test_normalize_action_keyword_aliases`、`test_simulator_deny_takes_precedence_over_allow`、`test_simulator_scope_evaluation` | `cargo test --package openobserve oss_skeleton` | 全部通过；deny 覆盖 allow；scope 边界不误放行 | 先回看 `decision_chain`，再修正匹配函数与测试样例 |
| 集成测试 | 验证 API 入口行为一致 | `/api/{org_id}/authz/simulate` 在不同角色绑定下返回稳定决策 | `tests/api-testing`（后续补脚本） | 同请求在同配置下决策稳定且可复现 | 固定测试数据，记录请求/响应体并回放 |
| 安全测试 | 确认默认拒绝与越权防护 | 无绑定主体默认 `deny`；冲突规则 `deny` 优先 | Rust 单测 + API 回归 | 未命中授权关系时不出现误放行 | 立即阻断发布，回退到 `legacy` |
| 灰度测试 | 对比新旧鉴权 provider 行为 | `AUTHZ_PROVIDER=legacy` 与 `AUTHZ_PROVIDER=local_rbac` 的抽样请求对比 | 灰度环境压测 + 日志对比 | 关键 API 决策一致或偏差在白名单内 | 保持灰度比例不扩容，先修复偏差再继续 |
| 回滚测试 | 验证可快速回切 | `local_rbac -> legacy` 配置回切与服务恢复 | 变更手册演练 | 回切后 403/5xx 恢复到基线，鉴权延迟恢复 | 执行一键回滚并冻结变更窗口 |

## 3. M6 本次交付的可运行单测清单

- 文件：`src/handler/http/request/authz/oss_skeleton.rs`
- 新增/增强测试：
  - 动作映射：`GET/POST/PATCH` 统一语义映射。
  - deny 优先：同 scope 同 action 下 deny 覆盖 allow。
  - scope 判定：支持层级 scope，同时避免相似字符串误匹配。

## 4. 验收建议

- 合并前最少执行：
  1. 目标单测：`cargo test --package openobserve oss_skeleton`
  2. 全量静态检查：`cargo clippy --workspace --all-targets --all-features -- -D warnings`
- 发布前必须完成灰度与回滚演练，步骤见 `docs/rbac/m6-authz-provider-canary-rollback.md`。
