from .base import PromptTemplate,Doc_content,example_content

class BasePrompt(PromptTemplate):
    def format(self, code: str, specific_content: str, SAST: str, language: str) -> str:
        return f"""
<role>
你是一个静态分析规则的结构化抽取大师，熟悉{SAST}工具的规则。
</role>
<task>
请根据输入的{SAST}工具的{language}类型规则内容，及提供的上下文内容，总结漏洞检测规则的中间表示用于规则迁移。
<cot>
为了确保生成的内容不冗余、不遗漏，同时保持语义一致性，请按照以下步骤逐步推导：
1. 解析输入规则内容：分析输入的 {SAST} 规则内容，提取规则的核心信息，包括规则 ID、类型、严重性、描述信息等。
2. 提取关键节点：
   - 提取 `sources` 节点，分析规则中定义的源节点及其匹配条件。
   - 提取 `sinks` 节点，分析规则中定义的汇节点及其匹配条件。
   - 提取 `sanitizers` 节点，分析规则中定义的净化器及其作用。
   - 提取 `propagations` 节点，分析规则中定义的传播路径。
3. 验证完整性：检查提取的内容是否覆盖了所有必要字段，确保不遗漏任何关键信息。
4. 生成中间表示：根据提取的内容，按照指定的 YAML 格式生成规则的中间表示。
5. 校验语义一致性：确保生成的中间表示与输入规则内容的语义保持一致。
</cot>
</task>
<input>
输入规则内容如下：
---
{code}
---
<input/>
<doc>
{Doc_content}
<doc/>
<example>
{example_content}
<example/>
{specific_content}
"""

class IRPrompt(BasePrompt):
    def format(self, code: str, SAST: str, language: str) -> str:
        specific_content = f"""
```yaml 
<output>   
请参照文档内容直接返回如下格式的yaml文件，不输出其他内容,要求不漏不缺严格正确：
xcpgir_version: "1.0"  # XCPG-IR 的版本号
rule:
  id: string            # 规则的唯一标识符
  name: string          # 规则的名称（可选）
  kind:                 # 规则的类型
    - taint             # 污点分析规则
    - pattern           # 模式匹配规则
    - hybrid            # 混合规则
    - value             # 值分析规则
  severity:             # 规则的严重性级别
    - INFO              # 信息提示
    - WARNING           # 警告
    - ERROR             # 错误
    - CRITICAL          # 严重错误
  message: string       # 规则的描述信息
  tags:                 # 规则的标签（可选）
    - string            # 例如：语言、框架等
  metadata:             # 元信息（可选）
    language: string    # 适用的语言（如 Python、Java）
    category: string    # 规则分类（如 安全、性能）
  sources: [...]        # 定义规则的 Source 节点
  sinks: [...]          # 定义规则的 Sink 节点
  sanitizers: [...]     # 定义规则的 Sanitizer 节点
  propagations: [...]   # 定义规则的传播路径
</output>