下面按 **功能领域** 把你给出的 60 余个 CodeQL 共享库（`.qll`）文件重新分组，并给出每组的核心作用与典型文件，方便后续按需索引。

---

### 1. 污点跟踪 / 数据流分析（核心安全）
| 文件 | 作用 |
|---|---|
| `DataFlow.qll` | 全局（跨过程）数据流框架 |
| `TaintTracking.qll` | 本地 + 全局污点传播 |
| `ContentDataFlowImpl.qll` | 带「内容/字段」敏感的数据流 |
| `DataFlowImpl*.qll` | 数据流多阶段实现与一致性检查 |
| `VariableCapture.qll` | 闭包变量捕获的数据流补全 |
| `FlowSummaryImpl.qll` | 模型即数据（MaD）摘要定义 |
| `ModelGeneratorImpl.qll` | 自动生成源/汇/摘要模型 |
| `ModelValidation.qll` | MaD 模型语法校验 |

---

### 2. 控制流 / SSA / 可达性
| 文件 | 作用 |
|---|---|
| `Cfg.qll` / `BasicBlock.qll` | AST → CFG 构建 |
| `ControlFlowReachability.qll` | 局部可达性 + SSA 值传播 |
| `Guards.qll` | 条件守卫（guard）控制关系 |
| `SuccessorType.qll` | CFG 边类型枚举 |
| `ConstantCondition.qll` | 恒真/恒假分支检测 |
| `Ssa.qll` | 语言无关 SSA 形式定义 |

---

### 3. 类型系统 / 类型推断 / 类型流
| 文件 | 作用 |
|---|---|
| `TypeFlow.qll` | 运行时类型上下界推断 |
| `TypeFlowImpl.qll` | 类型流实现（精确/联合界限） |
| `UniversalFlow.qll` | 全路径通用属性证明（如非空） |
| `TypeInference.qll` | 跨语言类型推断基础设施 |
| `TypeTracking.qll` / `SummaryTypeTracker.qll` | 类型沿调用链传播 |

---

### 4. 密码学 / 量子算法建模
| 文件 | 作用 |
|---|---|
| `ConceptsShared.qll` | 跨语言加密算法抽象（源、汇、传播） |
| `Model.qll` (quantum) | 加密操作实例（对称、非对称、签名、MAC 等） |
| `Standardization.qll` | 算法类型 → 字符串/参数标准化 |

---

### 5. 正则表达式 / ReDoS / 过滤缺陷
| 文件 | 作用 |
|---|---|
| `RegexTreeView.qll` | 正则表达式 AST 统一视图 |
| `NfaUtils.qll` | 正则 → NFA 构造与通用算法 |
| `ExponentialBackTracking.qll` | 指数回溯检测 |
| `SuperlinearBackTracking.qll` | 多项式回溯检测 |
| `RegexpMatching.qll` | 测试字符串匹配与捕获组填充 |
| `BadTagFilterQuery.qll` | HTML 标签过滤正则缺陷 |
| `MissingRegExpAnchor.qll` | 缺失/误导锚点检测 |
| `OverlyLargeRangeQuery.qll` | 过宽字符范围检测 |
| `HostnameRegexp.qll` | URL/域名正则安全性检查 |

---

### 6. 范围 / 模数 / 数值分析
| 文件 | 作用 |
|---|---|
| `RangeAnalysis.qll` | 表达式/SSA 变量上下界跟踪 |
| `ModulusAnalysis.qll` | 模数一致性推理（取模、余数） |
| `RangeUtils.qll` | SSA 相关工具谓词 |

---

### 7. 敏感数据识别 / 启发式
| 文件 | 作用 |
|---|---|
| `SensitiveDataHeuristics.qll` | 凭据、密钥、私钥等正则启发式 |

---

### 8. XML / YAML / Serverless 配置
| 文件 | 作用 |
|---|---|
| `Xml.qll` | XML AST 与导航 |
| `Yaml.qll` | YAML AST 与取值 |
| `ServerLess.qll` | 解析 Lambda/Serverless 处理器并标记远程入口 |

---

### 9. 威胁模型 / 抑制 / 统计
| 文件 | 作用 |
|---|---|
| `ThreatModels.qll` | 启用/禁用查询级威胁模型 |
| `AlertSuppression.qll` | `lgtm/codeql` 注释抑制 |
| `AlertFiltering.qll` | 差异范围（PR）内警报过滤 |
| `ReportStats.qll` | 数据库质量统计 |

---

### 10. 工具 / 辅助 / 基础类型
| 文件 | 作用 |
|---|---|
| `Location.qll` | 文件位置签名 |
| `FileSystem.qll` / `FilePath.qll` | 文件/文件夹/路径归一化 |
| `Strings.qll` | Unicode 转义与可见字符处理 |
| `Numbers.qll` | 二/八/十六进制解析与转换 |
| `Option.qll` | Maybe/Option 类型 |
| `Either.qll` | 联合类型 Either |
| `Boolean.qll` / `Unit.qll` / `Void.qll` | 基础单值类型 |
| `DenseRank.qll` | 密集排名算法 |
| `TypoDatabase.qll` | 常见拼写错误映射 |

---

### 11. 教程 / 示例
| 文件 | 作用 |
|---|---|
| `tutorial.qll` | 家谱/人口统计示例，用于 CodeQL 教学 |

---

### 使用建议
- **做污点规则** → 优先看组 1、2、5  
- **加新加密算法源/汇** → 组 4  
- **写 ReDoS 查询** → 组 5  
- **需要类型推断/范围分析** → 组 3、6  
- **处理 XML/YAML/Serverless** → 组 8  
- **统一抑制或威胁模型** → 组 9  
- **工具链或基础类型缺失** → 组 10  

这样即可按场景快速定位所需 `.qll` 文件，避免「大海捞针」。