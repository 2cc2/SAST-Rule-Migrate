# B2RScan 使用指南

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

## 配置

项目配置文件为 [config.yaml](../config.yaml)：

```yaml
sast_understanding:
    knowledge_graph_dir: "sast_knowledge_graph"
    max_steps: 20
```

### LLM 配置

在使用 LLM 功能之前，需要配置相应的 API 密钥：

1. OpenAI:
   - 设置环境变量 `OPENAI_API_KEY`

2. DashScope (Qwen):
   - 设置环境变量 `DASHSCOPE_API_KEY`

## 基本用法

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

## 高级用法

### 自定义规则提取

可以通过传递选项来自定义规则提取过程：

```python
options = {
    "include_patterns": ["**/*.ql"],
    "exclude_patterns": ["test/**/*.ql"],
    "max_depth": 3
}

rules = extractor.extract_rules("codeql", "/path/to/codeql/rules", options)
```

### 批量处理

```python
sast_tools = [
    ("codeql", "/path/to/codeql/rules"),
    ("semgrep", "/path/to/semgrep/rules")
]

all_rules = []
for sast_tool, path in sast_tools:
    rules = extractor.extract_rules(sast_tool, path)
    all_rules.extend(rules)
```

## xCPG-IR 格式

xCPG-IR 是统一的中间表示格式，包含以下字段：

```json
{
  "id": "唯一标识符",
  "name": "规则名称",
  "description": "规则描述",
  "severity": "严重性等级",
  "sources": ["数据源点列表"],
  "sinks": ["数据汇点列表"],
  "sanitizers": ["净化函数列表"],
  "validators": ["验证函数列表"],
  "meta": {
    "额外元数据"
  }
}
```

## 故障排除

### 常见问题

1. **LLM 调用失败**
   - 检查 API 密钥是否正确配置
   - 检查网络连接
   - 查看日志文件获取详细错误信息

2. **规则提取结果为空**
   - 检查路径是否正确
   - 确认 SAST 工具类型是否支持
   - 查看日志文件获取详细信息

3. **依赖安装失败**
   - 确保使用的是支持的 Python 版本
   - 检查 uv 是否正确安装
   - 尝试清除缓存后重新安装

### 日志查看

日志文件位于 [logs/](../logs/) 目录下：

```bash
# 查看最新日志
tail -f logs/b2rscan.log

# 搜索特定错误
grep "ERROR" logs/b2rscan.log
```

## API 参考

### RuleExtractor

```python
class RuleExtractor:
    def __init__(self, config_path: Optional[str] = None):
        pass
    
    def extract_rules(self, sast_tool: str, source_path: str, options: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        pass
```

### SASTUnderstandAgent

```python
class SASTUnderstandAgent:
    def __init__(self, sast_code_path, sast_name: Optional[str]=None):
        pass
    
    def run(self, user_task: Optional[str] = None):
        pass
```