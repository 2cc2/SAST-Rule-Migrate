from .base import PromptTemplate

class IRPrompt(PromptTemplate):
    def format(self, code: str) -> str:
        return f"""
            <role>
            你是经验丰富的代码安全审计工程师，负责工具规则的总结任务。
            </role>
            <task>
            理解Semgrep工具的规则内容将其按照模版总结为中间表示
            </task>
            <origin_rule>
            以下是用户提交的规则代码，请进行总结，尽可能的保留更多信息：
            {code}
            </origin_rule>
            <example>
            这个中间表示的模版如果仅为模式匹配请设计模式匹配项并按照模版风格中补充匹配内容:
            id: java/unsafe-deserialization-rmi
kind: taint                 # 这是典型的 taint tracking，而不是单纯的值属性检查
interprocedural: true       # 跨过程 taint 传播
path_output: full           # 保留完整的数据流路径
severity: ERROR
message: Unsafe deserialization in a remote object

sources:
  - kind: CONSTRUCTOR
    type: any               # 任意类型实例化
    guard: hasVulnerableMethod  # 限制条件：构造的类中存在接收复杂对象参数的远程方法

sinks:
  - select:
      node: CALL_ARG
      callee:
        qname:
          - java.rmi.Naming.bind
      arg_index: 1

sanitizers: []

propagation:
  - step:
      from: CALL_ARG
      callee: java.rmi.server.UnicastRemoteObject.exportObject
      arg_index: 0
      to: CALL_RET
      forbid_if:
        param_type:
          index: [2, 4]
          qname: java.io.ObjectInputFilter  # 如果 exportObject 有安全过滤器参数则不传播
  preset: none
    constraints:
            </example>
            <output>
            请以 Markdown 格式返回转换后的规则。只返回如下代码块，不多输出任何内容
            ```json
            # 总结的中间表示
            ```
            </output>
        """
class IRTransformPrompt(PromptTemplate):
    def format(self, IR: str,language:str,sast:str,example) -> str:
        return f"""
            <role>
            你是经验丰富的代码安全审计工程师，负责工具规则的迁移任务。
            </role>
            <task>
            理解Semgrep工具的规则中间表示的内容将其迁移到Codeql工具中,规则符合{sast}的语法规范。
            PS:中间表示是对规则的高度抽象总结，包含规则的核心要素和逻辑。请生成规则过程中保证信息完整准确。
            </task>
            <origin_rule>
            以下是用户提交的中间表示，请进行转换：
            {IR}
            </origin_rule>
            <example>
            请仿照下面提供的例子进行规则的编写，
            {example}
            </example>
            <output>
            请以 Markdown 格式返回转换后的规则，确保规则符合 {sast} 的{language}语言的语法规范。只返回如下代码块，不多输出任何内容
            ```ql
            # 转换后的 {sast} 规则
            ```
            </output>
        """
class TransformPrompt(PromptTemplate):
    def format(self, code: str,language:str,sast:str,example) -> str:
        return f"""
            <role>
            你是经验丰富的代码安全审计工程师，负责工具规则的迁移任务。
            </role>
            <task>
            理解Semgrep工具的规则内容将其迁移到Codeql工具中,规则符合{sast}的语法规范。
            </task>
            <origin_rule>
            以下是用户提交的规则代码，请进行转换：
            {code}
            </origin_rule>
            <example>
            请仿照下面提供的例子进行规则的编写，
            {example}
            </example>
            <output>
            请以 Markdown 格式返回转换后的规则，确保规则符合 {sast} 的{language}语言的语法规范。只返回如下代码块，不多输出任何内容
            ```ql
            # 转换后的 {sast} 规则
            ```
            </output>
        """
class RepairPrompt(PromptTemplate):
    def format(self, code: str,error:str,language:str,sast:str,advise:str) -> str:
        return f"""
            <error>
            以下是代码在工具运行时工具捕捉的错误：
            {error}
            </error>
            <advise>
            请根据以下建议一步一步修改规则：
            {advise}
            </advise>
            <output>
            请以 Markdown 格式只返回修改后完整的规则，如下代码块，不多输出任何内容
            ```ql
            # 转换后的 {sast} 规则
            ```
            </output>
        """
class AbstractPrompt(PromptTemplate):
    def format(self, code: str,error:str,language:str,sast:str) -> str:
        return f"""
            <role>
            你是经验丰富的{sast}规则设计工程师，负责解决代码编写的报错。
            </role>
            <task>
            在保证代码语义功能不变的前提下，根据error内容和{sast}语法规范修改代码中的错误提出有效的修改plan。
            </task>
            <origin_rule>
            以下是存在问题的规则代码：
            {code}
            </origin_rule>
            <error>
            以下是代码在工具运行时工具捕捉的错误：
            {error}
            </error>
            <output>
            请查找{sast}工具相关语法，进行修改正，给出修复的步骤用于COT指导大模型修复。格式如下：
            “”“
            为解决以下错误：{error}，请按照以下步骤进行修复：
            1.xxx
            2.xxx
            ”“”
            </output>
        """
