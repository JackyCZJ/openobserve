# Issue #8 (M6) 灰度与回滚手册（AUTHZ_PROVIDER=legacy|local_rbac）

## 1. 目的

本手册用于在 M6 阶段安全切换鉴权 provider，并保证出现异常时可在分钟级回滚。

- 目标 provider：`legacy`、`local_rbac`
- 目标场景：预发灰度、生产小流量试点、生产紧急回滚

> 说明：手册统一使用 `AUTHZ_PROVIDER` 作为操作名；若部署系统使用其他实际环境变量名（例如 `ZO_AUTHZ_PROVIDER`），请在发布平台做等价映射。

## 2. 发布前检查

1. 功能检查
   - `legacy` 与 `local_rbac` 均可启动。
   - `/authz/simulate` 接口可返回带 `decision_chain` 的结果。
2. 质量检查
   - 关键单测通过（动作映射 / deny 优先 / scope 判定）。
   - `cargo clippy --workspace --all-targets --all-features -- -D warnings` 通过。
3. 观测检查
   - 已接入 403 比例、鉴权耗时 p95、5xx 比例告警。

## 3. 灰度步骤

### Step 0：基线确认（全部 legacy）

- 配置：`AUTHZ_PROVIDER=legacy`
- 记录基线：
  - 鉴权失败率（403）
  - API 总错误率（5xx）
  - 鉴权相关接口 p95

### Step 1：1%~5% 节点切换 local_rbac

- 仅灰度节点配置为：`AUTHZ_PROVIDER=local_rbac`
- 其余节点保持：`AUTHZ_PROVIDER=legacy`
- 观察 15~30 分钟：
  - 403 是否出现异常抖动
  - 关键请求是否出现越权拒绝或误放行

### Step 2：按 5% -> 25% -> 50% -> 100% 扩容

每一档至少观察 30 分钟，满足以下条件再升档：

- 403、5xx、p95 均未超过基线阈值
- 关键组织/关键 API 抽样对比无系统性偏差
- 无高优先级告警未关闭

## 4. 回滚策略

### 4.1 标准回滚（推荐）

- 将异常节点配置改回：`AUTHZ_PROVIDER=legacy`
- 重启或滚动发布受影响实例
- 保持其余节点不变，先止损再排障

### 4.2 全量回滚（紧急）

- 所有节点统一切回：`AUTHZ_PROVIDER=legacy`
- 暂停继续扩容或发布
- 固化异常样本（请求参数、响应、日志 trace_id）

### 4.3 回滚后验证

- 403、5xx 与延迟恢复到基线范围
- 关键业务路径（查询、告警、仪表盘）可正常访问
- 抽样验证 20+ 关键请求无异常拒绝

## 5. 常见异常与处理

1. 403 突增
   - 先回滚到 `legacy`，再检查 deny 规则和 scope 匹配。
2. 局部组织越权失败
   - 对比同请求在 `legacy` 与 `local_rbac` 的 `decision_chain`。
3. 鉴权延迟升高
   - 降低灰度比例，定位慢请求路径后再恢复。

## 6. 退出条件（可进入下一阶段）

- `local_rbac` 在 100% 流量稳定运行至少 24 小时。
- 无 P0/P1 鉴权问题。
- 监控指标稳定，且回滚演练记录完整。
