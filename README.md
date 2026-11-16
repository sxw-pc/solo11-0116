# 契约转译台

旧版 JSON 接口封套转新业务消费者契约。保留版本、字段级来源、身份冲突、缺失语义、错误映射和跨包状态证据。

运行：`python -m pip install . --no-deps --no-build-isolation`，`python -m contractbridge demo`，`python -m contractbridge --help`，`python -m pytest -q`。运行与测试使用本地合成数据，不访问网络。

## 转译依赖与独立验真

`chain` 映射可用 `$目标字段名` 引用另一已转译字段；规则按依赖排序，未知引用和循环在契约冻结时拒绝。跨包状态按 UTC 瞬时排序，避免时区偏移改变业务次序。`verify` 从原始封套重放转译并重算字段级来源，能发现输出值及其哈希被一起改写、或证据指针被伪造。

同一契约版本号对应的规则正文不可更改；语义变更必须分配新版本，旧版本保持可复核。
