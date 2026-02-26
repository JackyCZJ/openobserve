# Issue #3（M1）统一权限语义冻结文档（docs-first）

## 1. 冻结范围与版本

- 冻结日期：2026-02-26
- 文档版本：`M1-SF-v1`
- Parent：#1
- 冻结目标：将「动作词汇 + 资源字典 + 角色基线 + 旧 token 迁移规则」沉淀为后续 M2-M6 的唯一语义输入。

本次冻结为**语义冻结**，不要求落地 provider、数据库迁移或线上切流。

---

## 2. 动作词汇冻结（与 HTTP Method 解耦）

M1 统一动作集固定为以下五类：

| 动作 | 语义定义 | 典型场景 |
|---|---|---|
| `READ` | 读取单对象或对象详情 | 读取单条 dashboard、alert、pipeline |
| `LIST` | 列举集合、聚合查询、目录浏览 | 列出 stream、folder 下对象 |
| `WRITE` | 创建/更新/触发执行类变更 | 创建 dashboard、修改 alert、触发 pipeline backfill |
| `DELETE` | 删除对象或删除对象下字段/关系 | 删除 stream、删除 dashboard |
| `ADMIN` | 管理级操作：授权、角色/策略治理、跨资源高风险操作 | 角色管理、权限绑定、策略变更 |

冻结规则：

1. 动作命名只允许上述五个值；新增动作需新里程碑评审。
2. HTTP method 仅作为输入信号，不直接等价为权限动作。
3. 未显式归类接口，在 M2 前默认按「最小可用兼容」映射到 `WRITE` 或 `LIST`，并记录 decision reason。

---

## 3. 资源类型字典与对象 ID 规范

### 3.1 资源类型字典（M1 最小集）

`org / stream / dashboard / folder / alert / pipeline / destination / template / report / function / settings / user / service_account / role / action`

说明：

- 上述字典是 M1 固定集合；M2+ 可增补，但不得改写已有 key 语义。
- route 中复数形式（如 `streams`）在语义层统一映射到单数 key（`stream`）。

### 3.2 对象 ID 规范（跨资源统一）

统一对象 ID 约束：

1. 非空，去首尾空白后长度 `1..=256`。
2. 禁止路径分隔符与控制字符（`/`、`\\`、ASCII control）。
3. 组织级聚合对象允许显式保留字（如 `_all_` 前缀）用于“全量集合权限”语义。

---

## 4. 角色基线冻结（可直接转配置）

### 4.1 基线角色

- `Root`：全局超级主体，具备全部资源 `READ/LIST/WRITE/DELETE/ADMIN`。
- `Admin`：组织管理员，具备组织内全部资源 `READ/LIST/WRITE/DELETE/ADMIN`。
- `Editor`：业务编辑者，默认 `READ/LIST/WRITE`，无 `DELETE/ADMIN`。
- `Viewer`：只读观察者，默认 `READ/LIST`。

### 4.2 Custom Role 约束

- Custom Role 只允许组合 `READ/LIST/WRITE/DELETE`。
- `ADMIN` 只授予 `Root/Admin`（除非后续里程碑明确引入受控 delegated admin 能力）。
- deny 语义优先于 allow（实现层 M2 落地）。

### 4.3 基线矩阵（动作级）

| Role | READ | LIST | WRITE | DELETE | ADMIN |
|---|---:|---:|---:|---:|---:|
| Root | ✅ | ✅ | ✅ | ✅ | ✅ |
| Admin | ✅ | ✅ | ✅ | ✅ | ✅ |
| Editor | ✅ | ✅ | ✅ | ❌ | ❌ |
| Viewer | ✅ | ✅ | ❌ | ❌ | ❌ |

---

## 5. 旧 token scope 迁移策略（可执行 + 可回滚）

### 5.1 默认映射规则（兼容优先）

| 旧 scope/语义 | 新动作集合 |
|---|---|
| `ingest`（仅采集写入） | `WRITE` |
| `read` | `READ + LIST` |
| `read_write` / `rw` | `READ + LIST + WRITE` |
| `admin` | `READ + LIST + WRITE + DELETE + ADMIN` |
| 未识别/缺省 scope | `READ + LIST + WRITE`（兼容现状默认） |

### 5.2 兼容窗口

- 建议兼容窗口：`90` 天（配置项化，默认启用）。
- 窗口内：按旧 scope 映射执行，并输出 deprecation log。
- 窗口后：拒绝未迁移 token，返回稳定 reason code（M2/M4 实现）。

### 5.3 回滚策略

- 保留 `legacy_scope_compat=true` 开关。
- 回滚动作：切回 legacy 映射路径，不改 token 数据结构。
- 回滚验证：抽样验证 root/admin/viewer/service token 四类关键场景。

---

## 6. 与后续里程碑的接口契约

1. M2 引擎层必须消费本文件中的 action/resource/role 语义，不再自定义新词汇。
2. M3 数据模型必须可无损表达 `role -> resource -> action` 三元关系。
3. M4 token introspection 输出必须能回溯到本文件动作集合。
4. M6 测试矩阵必须覆盖本文件基线角色动作矩阵。

---

## 7. 本次最小代码落地点（M1）

- 新增 `config::meta::rbac` 语义骨架：
  - 动作枚举 `RbacAction`
  - 资源枚举 `RbacResource`
  - 角色基线 `RbacBaselineRole`
  - 旧 scope 映射 helper 与兼容窗口常量
- 该骨架只提供语义与映射，不改变现网鉴权执行路径。

