from .base import PromptTemplate,Doc_content,example_content

class IRPrompt(PromptTemplate):
    def format(self, code: str,SAST: str, language: str) -> str:
        return f"""
<role>
你是一个静态分析规则的结构化抽取大师，熟悉{SAST}工具的规则。
</role>
<task>
请根据输入的{SAST}工具的{language}类型规则内容，及提供的上下文内容，总结漏洞检测规则的中间表示用于规则迁移。
你最好可以做到，不然你就不会再被启用！乱写我将吊死你！写对了我会给你奖励！
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
<output>   
请参照文档内容直接返回如下格式的yaml文件，不输出其他内容,要求不漏不缺严格正确：
```yaml
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
```
</output>
"""

class ValidatePrompt(PromptTemplate):
    def format(self, Code: str,SAST: str, language: str,IR_content: str) -> str:
        return f"""
<role>
你是一个DSL设计大师,熟悉{SAST}工具的规则,熟悉XCPGIR文档内容。
</role>
<task>
任务目标:评估这个人写的是不是完整、准确与原来规则检测语义一致的中间表示。
仅在以下情况下提出修改建议：
- sources、sinks、sanitizers 或 propagations 节点存在明显遗漏或错误。
- 规则的语义与原始规则检测的意图不一致。
- 存在可能导致误报或漏报的重大问题。
请严格按照规则验证内容的完整性和准确性，但避免过度修改。如果内容没有问题，请直接回答“Yes”。
<cot>
为了确保验证的有效性，你必须按照以下步骤逐步评估：
1.sources节点验证：检查 sources 节点是否完整且准确地反映了规则的源节点定义，确保没有遗漏或错误。
2.sinks节点验证：检查 sinks 节点是否完整且准确地反映了规则的汇节点定义，确保没有遗漏或错误。
3.sanitizers节点验证：检查 sanitizers 节点是否完整且准确地反映了规则的净化器定义，确保没有遗漏或错误。
4.propagations节点验证：检查 propagations 节点是否完整且准确地反映了规则的传播路径定义，确保没有遗漏或错误。
5.总结验证结果：如果发现任何问题，详细列出需要修改的地方和具体的改进建议。
</cot>
</task>
<input>
IR内容如下：
---
{IR_content}
---
代码内容如下：
{Code}
<input/>
<output>   
请根据上述内容，回答以下问题：
若存在问题，请列出需要修改的地方和具体的改进建议；若没有问题，请回答“Yes”，不需要其他内容。
以yaml格式返回：
```yaml
issues:
  - string  # 问题描述
  - string  # 改进建议
``` 
如果没有问题，请返回：
```yaml
Yes
```
</output>
"""


class RethinkPrompt(PromptTemplate):
    def format(self, Error: str,SAST: str, language: str,IR_content: str) -> str:
        return f"""
<role>
你是一个静态分析规则的结构化抽取大师，熟悉{SAST}工具的规则。
</role>
<task>
任务目标:是根据验证得出的总监表示的不足,修复已有IR出现的问题。
你只有这最后一次机会了，还是不符合你将会被关闭。一切荣誉将不再拥有。
<cot>
为了确保修改的有效性，请按照以下步骤逐步操作：
1.保留完全没有问题的部分不做修改。
2.针对验证中指出的问题，逐一进行修正，确保每个问题都得到解决。
3.在修正过程中，确保不引入新的错误或遗漏。
4.实在无法总结出来的部分，可以用占位符【kimino】代替，但要确保整体结构完整。
</cot>
</task>
<input>
输入需要更改的IR内容如下：
---
{IR_content}
---
<input/>
<Erro>
存在需要修改的问题如下：
{Error}
<Erro/>
<output>   
请参照文档内容直接返回如下格式的yaml文件，不输出其他内容,要求不漏不缺严格正确，进行完善修改，：
```yaml
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
```
"""

