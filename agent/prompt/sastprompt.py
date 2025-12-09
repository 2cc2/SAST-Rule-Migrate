from .base import PromptTemplate

class TransformPrompt(PromptTemplate):
    def format(self, code: str,language:str,sast:str,example) -> str:
        return f"""
            <role>
            你是经验丰富的代码安全审计工程师，负责工具规则的迁移任务。
            </role>
            <task>
            理解Gosec工具的规则内容将其迁移到Semgrep工具中,规则符合{sast}的语法规范。
            </task>
            <origin_rule>
            以下是用户提交的规则代码，请进行转换：
            {code}
            </origin_rule>
            <example>
            {example}
            </example>
            <output>
            请以 Markdown 格式返回转换后的规则，确保规则符合 {sast} 的语法规范。只返回如下代码块，不多输出任何内容
            ```yaml 
            # 转换后的 {sast} 规则
            ```
            </output>
        """
# class RepairPrompt(PromptTemplate):
#     def format(self, code: str,error:str,language:str,sast:str) -> str:
#         return f"""
#             <error>
#             你是经验丰富的{sast}规则设计工程师，负责解决代码编写的报错,在不改变规则功能的前提下只对下列错误进行改正。
#             {error}
#             </error>
#             <task>
#             1.请先规划修改策略，作为思维链(COT)指导大模型修复。
#             2.请根据错误内容和{sast}语法规范修改代码中的错误。
#             </task>
#             <output>
#             请以 Markdown 格式返回修改采取的策略，和修改后完整规则，如下代码块，不多输出任何内容
#             ```yaml 
#             # 转换后的 {sast} 规则
#             ```
#             </output>
#         """
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
            请以 Markdown 格式返回修改采取的策略，和修改后完整的规则，如下代码块，不多输出任何内容
            【修改策略】
            ```yaml 
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
# class RepairPrompt(PromptTemplate):
#     def format(self, code: str,error:str,language:str,sast:str,advise:str) -> str:
#         return f"""
#             <role>
#             你是经验丰富的{sast}规则设计工程师，负责解决代码编写的报错。
#             </role>
#             <task>
#             在保证代码语义功能不变的前提下，修复代码中的错误。符合 {sast} 语法规范。
#             </task>
#             <origin_rule>
#             以下是提供的需要修改的规则代码：
#             {code}
#             </origin_rule>
#             <error>
#             以下是代码在工具运行时工具捕捉的错误：
#             {error}
#             </error>
#             <advise>
#             大模型进行的修改建议如下：
#             {advise}
#             根据建议，请对规则进行必要的修改。
#             </advise>
#             <output>
#             请以 Markdown 格式返回修改采取的策略，和修改后完整规则，如下代码块，不多输出任何内容
#             【修改策略】
#             ```yaml 
#             # 转换后的 {sast} 规则
#             ```
#             </output>
#         """
# class AbstractPrompt(PromptTemplate):
#     def format(self, code: str,error:str,language:str,sast:str) -> str:
#         return f"""
#             <role>
#             你是经验丰富的{sast}规则设计工程师，负责解决代码编写的报错。
#             </role>
#             <task>
#             在保证代码语义功能不变的前提下，根据error内容和{sast}语法规范修改代码中的错误提出有效的修改plan。
#             </task>
#             <origin_rule>
#             以下是存在问题的规则代码：
#             {code}
#             </origin_rule>
#             <error>
#             以下是代码在工具运行时工具捕捉的错误：
#             {error}
#             </error>
#             <output>
#             请查找{sast}工具相关语法，进行修改正，给出修复的步骤用于COT指导大模型修复。格式如下：
#             “”“
#             为解决以下错误：{error}，请按照以下步骤进行修复：
#             1.xxx
#             2.xxx
#             ”“”
#             </output>
#         """