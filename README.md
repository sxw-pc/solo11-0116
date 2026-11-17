# 契约转译台

旧版 JSON 接口封套转新业务消费者契约。保留版本、字段级来源、身份冲突、缺失语义、错误映射和跨包状态证据。

运行：`python -m pip install . --no-deps --no-build-isolation`，`python -m contractbridge demo`，`python -m contractbridge --help`，`python -m pytest -q`。运行与测试使用本地合成数据，不访问网络。

## 转译依赖与独立验真

`chain` 映射可用 `$目标字段名` 引用另一已转译字段；规则按依赖排序，未知引用和循环在契约冻结时拒绝。跨包状态按 UTC 瞬时排序，避免时区偏移改变业务次序。`verify` 从原始封套重放转译并重算字段级来源，能发现输出值及其哈希被一起改写、或证据指针被伪造。

同一契约版本号对应的规则正文不可更改；语义变更必须分配新版本，旧版本保持可复核。

`freshness-policy` 冻结输出时效阈值，`freshness-record` 以独立 ID 记录 source、received、published 时间点，`freshness-report` 给出当前简单的逐输出历时判断；事件可带 supersedes 引用，但当前报表未解释修订或迟到事件。

## 消费者配额与交付回执

`consumer-policy` 冻结消费者额度，`allocate` 根据逐条验真、主体去重及累计金额形成配额决定。`dispatch` 只对整批已配额输出生成交付快照；`acknowledge` 逐条记录接收或失败，重复回执幂等，冲突回执拒绝。转译已核验但额度超限时暂缓交付；部分接收失败形成可查询的部分失败状态。

`migration-plan` 定义旧新契约的金额漂移预算，`migration-compare` 对同一原始封套的双份转译逐项复验身份、业务状态和金额，保存差异记录。目标契约的交付会重算迁移结论；单条语义漂移、缺失或篡改分别阻断或暂缓切换，即使目标转译单独验真通过也不直接交付。
