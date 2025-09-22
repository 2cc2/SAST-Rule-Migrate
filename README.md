# B2RScan: Back-to-Rule Scan

**B2RScan** 是一个统一的漏洞检测规则框架。

它的目标是把不同 SAST 工具（Semgrep、CodeQL、Gosec、PMD …）里的规则抽取出来，转化为统一的 **xCPG-IR** 表示，并且还能再导出回各种 SAST —— 支持 **规则迁移、执行验证、回归测试**。

------

## 特性

- **规则提取（Rule Extraction）**
  - 调用现成的智能体（如 `trae-agent`），自动解析不同工具的规则文件。
  - 输出统一 IR，包含 `sources / sinks / sanitizers / validators / path` 等关键字段。
- **统一 IR（xCPG-IR）**
  - SAST 无关的中间表示（IR），是整个项目的“唯一事实源”。
  - 支持 Schema 校验、Lint 检查和知识库补全（API 别名、净化函数、传播摘要）。
- **跨语言 / 跨工具**
  - 不同语言（Java / Python / Go / JS / PHP …）的规则都能抽取到 IR。
  - IR 可以再导出成 Semgrep YAML、CodeQL QL 等规则文件，形成**规则迁移**能力。
- **执行验证（xCPG 引擎）**
  - IR 可以编译成执行计划，运行在 xCPG 图上，做跨语言数据流 / 结构匹配分析。
  - 支持最小正/反例（MRE）绑定，保证规则的正确性和可回归。