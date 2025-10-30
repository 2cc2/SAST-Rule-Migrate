from .base import PromptTemplate

class SummaryPrompt(PromptTemplate):
    def format(self, code: str) -> str:
        return f"请你总结以下代码的功能，并用简洁自然语言说明其主要作用：\n\n{code}\n\n总结:"