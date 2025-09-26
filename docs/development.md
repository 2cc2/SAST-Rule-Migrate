# B2RScan 开发指南

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

## 开发环境搭建

### 克隆项目

```bash
git clone <repository-url>
cd B2RScan
```

### 安装依赖

```bash
make install
```

或者手动安装：

```bash
uv pip install -e .
find . -name "*.egg-info" -exec rm -rf {} +
```

### 代码质量检查

项目使用以下工具进行代码质量检查：

```bash
# 运行所有检查
pre-commit run --all-files

# 或者分别运行
ruff check .
ruff format --check .
mypy src/
codespell .
```

## 添加新功能

### 添加新的 SAST 工具支持

1. 在 [src/b2rscan/task/rule_extraction/parser/](../src/b2rscan/task/rule_extraction/parser/) 目录下创建新的解析器：

```python
from .base import BaseParser

class NewSASTParser(BaseParser):
    def parse(self, file_path: str) -> List[Dict[str, Any]]:
        # 实现解析逻辑
        pass
```

2. 在 [src/b2rscan/task/rule_extraction/parser/__init__.py](../src/b2rscan/task/rule_extraction/parser/__init__.py) 中注册解析器：

```python
from .new_sast_parser import NewSASTParser

PARSERS = {
    'new_sast': NewSASTParser,
    # 其他解析器
}
```

3. 更新 [RuleExtractor](../src/b2rscan/task/rule_extraction/extractor.py) 以支持新的工具类型。

### 添加新的工具函数

1. 在 [src/b2rscan/toolbox/](../src/b2rscan/toolbox/) 目录下创建新的工具：

```python
from b2rscan.toolbox.base.base import Tool, ToolResult

class NewTool(Tool):
    name = "new_tool"
    description = "工具描述"
    
    def run(self, **kwargs) -> ToolResult:
        # 实现工具逻辑
        pass
```

2. 在适当的位置注册工具，例如在 [SASTUnderstandAgent](../src/b2rscan/task/understanding/agent.py) 中：

```python
from b2rscan.toolbox.new_tool import NewTool

class SASTUnderstandAgent:
    def __init__(self, sast_code_path, sast_name: Optional[str]=None):
        # 其他初始化代码
        self.tools.register(NewTool())
```

## 代码规范

### Python 编码规范

1. Python 模块名称不能包含连字符（-），应使用下划线（_）
2. 对于主要用途为存储数据的类，应优先考虑使用 `@dataclass` 装饰器
3. 当函数参数具有 None 默认值时，应使用 `Optional[str]` 或 `Union[str, None]` 进行类型注解

### LLM 调用规范

在调用 LLMWrapper 类提供的 LLM 功能时，应使用 `infer` 方法进行推理生成，禁止使用不存在的 `generate` 方法。

### 日志规范

项目日志系统支持双格式输出：
- 控制台：人性可读格式 `[LEVEL] message`
- 文件：JSONL 格式，便于机器解析

必须记录基础元数据：时间戳、日志级别、日志名称，并支持添加额外结构化数据。

### 工具注册规范

1. 所有工具必须继承 `Tool` 基类，并实现 `get_name`、`get_description`、`get_parameters` 和 `execute` 方法
2. 工具通过 `tools_registry` 注册表进行统一管理
3. 工具执行结果需以 `ToolResult` 格式返回

## 测试

### 单元测试

在 [test/](../test/) 目录下添加单元测试：

```python
import unittest
from b2rscan.task.rule_extraction.parser.new_sast_parser import NewSASTParser

class TestNewSASTParser(unittest.TestCase):
    def test_parse(self):
        parser = NewSASTParser()
        result = parser.parse("test_file.rule")
        self.assertIsInstance(result, list)
```

### 运行测试

```bash
python -m unittest discover test/
```

## 贡献指南

1. Fork 项目
2. 创建功能分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启 Pull Request

### 代码审查标准

1. 代码必须通过所有质量检查
2. 必须包含适当的单元测试
3. 必须更新相关文档
4. 遵循项目编码规范

## 发布流程

1. 更新版本号在 [pyproject.toml](../pyproject.toml)
2. 更新 [CHANGELOG.md](../CHANGELOG.md)
3. 创建并推送标签
4. 构建并发布到 PyPI

## 常用开发命令

```bash
# 安装开发依赖
make install

# 运行代码质量检查
make lint

# 运行测试
make test

# 格式化代码
make format
```