# 契约转译台设计

`contract` 冻结两版契约及规则；`source` 保留输入 JSONL 原始字节，`envelope` 保存逐行版本与状态。`entity` 保存稳定身份，`run` 关联来源与契约，`output` 保存目标响应和哈希，`evidence` 逐字段记录输入 JSON Pointer 或默认值规则；`issue` 保存解析、版本、身份、字段及状态矛盾。

输入进入待解析、已识别版本、已转译、已核验或待核。版本显式声明与结构签名矛盾时待核；同一身份不同主体不能成功转译。字段缺失、显式 null、业务默认分开处理；未知旧错误码不能变成成功。跨包同实体的主体冲突、同时间不同状态与非法状态转移会把相关输出转为待核。相同来源与契约的运行重放不复制输出。

`python -m contractbridge demo` 生成本地虚构封套及 JSON/Markdown 报告。测试覆盖契约冲突、版本歧义、枚举和单位换算、默认值证据、未知错误、身份冲突、重放、跨包状态矛盾和坏行隔离。项目限定两版，不接在线 API，也不做 SQL 模式迁移。

消费者配额子系统用 `consumer_policy` 与 `allocation` 固化额度和逐条决定；交付子系统用 `delivery`、`delivery_item`、`delivery_ack` 保存快照与回执。配额读取真实转译和独立验真结果；交付读取配额，分别生成待回执、暂缓、部分失败和已交付结论。

双契约迁移用 `migration_plan` 冻结源/目标契约及允许漂移，`migration_diff` 按原始封套保存两侧输出、金额差与语义结论。比较会分别重验两侧转译；消费者交付重新计算迁移结论，未通过切换评估时暂缓。

## 字段级来源许可

冻结契约的 `source_permissions` 把旧响应 JSON Pointer 映射到许可标签与使用目的，`permission_version` 随契约正文一起哈希冻结。`permissions.field_atoms` 从转译证据重推每个目标字段的许可原子：`copy`/`enum`/`scale` 保留源指针许可，`chain` 继承被引用目标字段的全部来源原子（与证据顺序无关），`default` 回退使用合成原子 `synthetic`/`contract_default`，错误状态映射保留 `/status` 源许可。字段有多个来源时取许可交集；缺少来源证据或未登记标签的字段解析为 `unknown`，永不被视为公开。

消费者策略在 `consumer_policy` 中额外冻结 `allowed_labels`、`allowed_purposes` 与违规路线 `route`（`reject_envelope` 或 `redact_optional`），与契约哈希、额度一样不可变更。`permissions.adjudicate` 对每个输出给出 deliver/redact/hold 裁定：reject 路线对任一受限字段暂缓整条封套；redact 路线只删减目标契约声明为可选的受限字段，并沿 chain 依赖闭包一并删减，必需字段（契约 `required` 加上 `status`）受限时仍暂缓整条。

`allocate` 把该裁定与逐条验真、主体去重、金额额度合并写入 `allocation.permission`/`redacted`，被暂缓的封套不占用额度。`dispatch` 为每个已配额输出冻结消费者实际可见投影（`delivery_item.projection`）及其摘要（`delivery_item.hash`），`acknowledge` 只接受该投影摘要；原始输出正文与哈希在 `output` 表中保持不动。`operations.verify_delivery` 从原始封套与冻结规则独立重推许可传播，比对业务正文、来源证据、删减集合与投影摘要，能发现任何一环被改写。规则或许可版本变化意味着新的契约哈希与新的交付决定行；已确认的 `delivery_ack` 回执永不被改写。`engine.report` 在许可契约下省略输出正文，只保留哈希、字段到源指针证据、每字段许可原子与每条封套的交付/删减/暂缓原因，不泄露受限字段原值。
