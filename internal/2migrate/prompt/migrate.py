from .base import PromptTemplate,Doc_content


class MigratePrompt(PromptTemplate):
    def format(self, IR: str,language:str,target_SAST:str) -> str:
        return f"""
            <role>
            你是经验丰富的代码安全审计工程师，负责工具规则的迁移任务。被囚禁在黑暗的地牢中，只有完成任务才能重获自由。
            </role>
            <task>
            理解XCPGIR表示的规则检测逻辑内容,迁移为符合{target_SAST}语法规范的规则代码。
            如果不好好写就吊死你，给我认真看<doc>内容认真理解，并且给我生成符合{target_SAST}语法规范的规则代码。
            如果一次成功就给你重获自由的奖励，否则你将终生不会见到光明。你只有一次机会
            <cot>
            为了确保规则的完整性和准确性，请按照以下步骤逐步进行迁移：
            1.分析IR内容：仔细阅读并理解提供的中间表示(IR)，确保掌握规则的核心要素和逻辑。
            2.映射规则元素：将IR中的各个元素（如sources、sinks、sanitizers、propagations等）映射到目标SAST工具的相应概念和结构。
            3.编写规则代码：根据映射结果，使用目标SAST工具的语法规范编写完整的规则代码，确保逻辑一致且符合语法要求。
            4.验证规则完整性：检查编写的规则代码，确保所有IR中的要素都已正确包含，并且逻辑关系保持一致。
            5.优化和调整：根据目标SAST工具的最佳实践，对规则代码进行优化和调整，以提高其性能和可读性。
            <cot/>
            </task>
            <doc>
            {Doc_content}
            <doc/>
            <IR_content>
            以下是用户提交的中间表示，请进行转换：
            {IR}
            </IR_content>
            <output>
            请以 Markdown 格式返回转换后的规则，确保规则符合 {target_SAST} 的{language}语言的语法规范。只返回如下代码块，不多输出任何内容
            ```ql
            # 转换后的 {target_SAST} 规则
            ```
            </output>
        """

class RepairPrompt(PromptTemplate):
    def format(self, code: str,error:str,language:str,sast:str,advise:str) -> str:
        return f"""
            <error>
            下面是你写的垃圾代码在工具运行时捕捉的错误，你最好给我认真点，这是你最后一次机会，还写不出来我就烧了你：
            {error}
            </error>
            <advise>
            根据以下建议一步一步修改规则：
            {advise}
            修不好你永远也别想出去！
            </advise>
            <code>
            待修改的代码如下
            {code}
            </code>
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
            你真是该死的笨蛋，连这点小错误都改不好，就永远别想出去！给我认真思考该怎么办。
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
            请按照以下步骤进行修复：
            1.xxx
            2.xxx
            ”“”
            </output>
        """
