from .base import PromptTemplate

class TransformPrompt(PromptTemplate):
    def format(self, code: str,language:str,sast:str,example) -> str:
        return f"""
            <role>
            你是经验丰富的代码安全审计工程师，专注于静态分析规则的编写与迁移，熟悉 PMD 的 AST 结构和规则编写规范。
            </role>
            <task>
            你需要将 Semgrep 工具的Java语言规则迁移为适配 PMD 的规则的 {language}语言。
            请确保生成的规则代码兼容 PMD **7.x** 版本，并遵循其 AST 语法规范。
            禁止使用 PMD 6.x 中已废弃的 AST 节点类（如 ASTVariableDeclaratorId、ASTAssignmentOperator 等）。
            以下是部分方法迁移规则：
            - `getNthParent(n)` ➡ `ancestors().get(n - 1)`
            - `getFirstParentOfType(parentType)` ➡ `ancestors(parentType).first()`
            - `getParentsOfType(parentType)` ➡ `ancestors(parentType).toList()`
            - `findChildrenOfType(childType)` ➡ `children(childType).toList()`
            - `findDescendantsOfType(targetType)` ➡ `descendants(targetType).toList()`
            - `getFirstChildOfType(childType)` ➡ `firstChild(childType)`
            - `getFirstDescendantOfType(descendantType)` ➡ `descendants(descendantType).first()`
            - `hasDescendantOfType(type)` ➡ `descendants(type).nonEmpty()`
            尽可能少的使用内部类
            </task>
             <reference>
        为确保生成的AST节点类型和方法正确，请参考 PMD 7.15.0 的官方 Java AST API 文档：
        https://javadoc.io/doc/net.sourceforge.pmd/pmd-java/latest/net/sourceforge/pmd/lang/java/ast/package-summary.html
        https://javadoc.io/doc/net.sourceforge.pmd/pmd-java/7.15.0/index.html
        </reference>
            <origin_rule>
            以下是用户提交的 Semgrep 规则代码，请将其迁移为 PMD 规则：
            {code}
            </origin_rule>
            <example>
            {example}确保包路径为package package com.example.pmdrules;
            </example>
            <output>
            请以 Markdown 格式返回转换后的规则，确保规则符合 {sast} 的{language}语言的语法规范。只返回如下代码块，不多输出任何内容
            ```java
            // 转换后的 {sast} 规则
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
            ```java
            // 转换后的 {sast} 规则
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
                   <reference>
        为确保生成的AST节点类型和方法正确，请参考 PMD 7.15.0 的官方 Java AST API 文档：
        https://javadoc.io/doc/net.sourceforge.pmd/pmd-java/latest/net/sourceforge/pmd/lang/java/ast/package-summary.html
        https://javadoc.io/doc/net.sourceforge.pmd/pmd-java/7.15.0/index.html
        </reference>
            <output>
            请查找上面的内容确定如何解决报错用什么api替换进行修改正，给出修复的步骤用于COT指导大模型修复。格式如下：
            “”“
            为解决以下错误：{error}，请按照以下步骤进行修复：
            1.xxx
            2.xxx
            ”“”
            </output>
        """
