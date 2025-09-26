# B2RScan: Back-to-Rule Scan

**B2RScan** 是一个统一的漏洞检测规则框架。

它的目标是把不同 SAST 工具（Semgrep、CodeQL、Gosec、PMD …）里的规则抽取出来，转化为统一的 **xCPG-IR** 表示，并且还能再导出回各种 SAST —— 支持 **规则迁移、执行验证、回归测试**。

## 特性

- **规则提取（Rule Extraction）**
  - 调用现成的智能体（如 `trae-agent`），自动解析不同工具的规则文件。
  - 输出统一 IR，包含 `sources / sinks / sanitizers / validators / path` 等关键字段。
- **统一 IR（xCPG-IR）**
  - SAST 无关的中间表示（IR），是整个项目的"唯一事实源"。
  - 支持 Schema 校验、Lint 检查和知识库补全（API 别名、净化函数、传播摘要）。
- **跨语言 / 跨工具**
  - 不同语言（Java / Python / Go / JS / PHP …）的规则都能抽取到 IR。
  - IR 可以再导出成 Semgrep YAML、CodeQL QL 等规则文件，形成**规则迁移**能力。
- **执行验证（xCPG 引擎）**
  - IR 可以编译成执行计划，运行在 xCPG 图上，做跨语言数据流 / 结构匹配分析。
  - 支持最小正/反例（MRE）绑定，保证规则的正确性和可回归。

## 文档

- [架构设计](docs/architecture.md) - 系统架构和设计模式
- [使用指南](docs/user_guide.md) - 详细的使用说明和示例
- [开发指南](docs/development.md) - 开发环境搭建和贡献指南
- [规则提取](docs/规则提取.md) - 规则提取模块详细说明
- [SAST工具理解](docs/understanding.md) - SAST工具理解模块详细说明

## 安装

### 环境要求

- Python 3.8+
- uv (Python包管理工具)

### 安装步骤

```bash
# 克隆项目
git clone <repository-url>
cd B2RScan

# 安装依赖
make install
```

或者手动安装：

```bash
uv pip install -e .
find . -name "*.egg-info" -exec rm -rf {} +
```

## 项目结构

```
B2RScan/
├── src/b2rscan/           # 核心源代码
│   ├── agent_wrapper/     # 智能体包装器
│   ├── config/            # 配置加载器
│   ├── ir/                # 中间表示(IR)定义
│   ├── llm_wrapper/       # 大语言模型封装
│   ├── min_agent/         # 最小智能体实现
│   ├── monitor/           # 监控和日志
│   ├── task/              # 核心任务模块
│   │   ├── rule_extraction/  # 规则提取
│   │   └── understanding/    # SAST工具理解
│   └── toolbox/           # 工具箱
├── agent_output/          # 智能体输出结果
├── docs/                  # 文档
├── logs/                  # 日志文件
├── Makefile               # 构建脚本
├── config.yaml            # 配置文件
└── pyproject.toml         # 项目配置
```

## 核心组件

### 1. 规则提取 (Rule Extraction)

规则提取模块负责从各种SAST工具中提取规则并转换为统一的xCPG-IR格式。

主要类:
- [RuleExtractor](src/b2rscan/task/rule_extraction/extractor.py): 主要的规则提取器
- [IRConverter](src/b2rscan/task/rule_extraction/ir_converter.py): IR转换器

### 2. 统一IR (xCPG-IR)

xCPG-IR是项目的核心中间表示，具有以下字段：

- `id`: 规则唯一标识符
- `name`: 规则名称
- `description`: 规则描述
- `severity`: 严重性等级 (low, medium, high, critical)
- `sources`: 数据源点
- `sinks`: 数据汇点
- `sanitizers`: 净化函数
- `validators`: 验证函数
- `meta`: 元数据

### 3. SAST工具理解

理解模块通过智能体分析SAST工具的内部工作机制，并构建知识图谱。

### 4. 大语言模型封装

项目支持多种大语言模型：

- OpenAI API
- 阿里云DashScope (Qwen)

## 使用方法

### 规则提取

```python
from b2rscan.task.rule_extraction import RuleExtractor

# 初始化提取器
extractor = RuleExtractor()

# 从CodeQL提取规则
rules = extractor.extract_rules("codeql", "/path/to/codeql/rules")

# 从Semgrep提取规则
rules = extractor.extract_rules("semgrep", "/path/to/semgrep/rules")
```

### SAST工具理解

```python
from b2rscan.task.understanding.agent import SASTUnderstandAgent

# 理解CodeQL工具
agent = SASTUnderstandAgent("/path/to/codeql", "codeql")
agent.run()
```

## 配置

项目配置文件为 [config.yaml](config.yaml)：

```yaml
sast_understanding:
    knowledge_graph_dir: "sast_knowledge_graph"
    max_steps: 20
```

## 开发

### 代码规范

项目使用以下代码质量工具：

- ruff: 代码风格检查和格式化
- mypy: 静态类型检查
- codespell: 拼写检查
- pre-commit: 提交前检查

### 添加新功能

1. 在对应的task目录下创建新模块
2. 遵循现有的模块结构和接口
3. 添加适当的单元测试
4. 更新文档

## 许可证

[待添加]

## 联系方式

[待添加]