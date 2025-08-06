from typing import List, Optional
import json
import time
import os
import requests
from enum import Enum
import tiktoken
# from agent.prompt.semgrep import SemgrepPrompt

class Model(Enum):
    GPT_4 = "gpt-4"
    DEEPSEEK_V3 = "deepseek-v3"
    DEEPSEEK_CHAT = "deepseek-chat"
    CLD = "gpt-clde-3-5-sont-240620"

class LLMBot:
    def __init__(self, system_prompt="你是静态分析工具漏洞检测规则编写大师", model=Model.GPT_4.value):
        self.messages = [{"role": "system", "content": system_prompt}]
        self.api_key = os.getenv("LLM_API_KEY")
        self.url = "https://4.0.wokaai.com/v1/chat/completions"
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        self.model = model
    def clear_context(self):
        """清除上下文，仅保留系统提示"""
        self.messages = [{"role": "system", "content":"你是静态分析工具漏洞检测规则编写大师"}]

    def inference(self, message, max_tokens=3000):
        self.messages.append({"role": "user", "content": message})
        data = {
            "model": self.model,
            "messages": self.messages,
            "max_tokens": max_tokens,
            "temperature": 0,
        }
        response = requests.post(self.url, headers=self.headers, json=data)
        response_json = response.json()
        print(response_json)
        if "choices" not in response_json or not response_json["choices"]:
            raise RuntimeError("Invalid response: 'choices' field is missing or empty.")
        if "message" not in response_json["choices"][0] or "content" not in response_json["choices"][0]["message"]:
            raise RuntimeError("Invalid response: 'message' or 'content' field is missing in choices.")

        content = response_json['choices'][0]['message']['content']
        # self.messages = self.messages[:1]  # Reset messages to only include the system prompt
        # 保留系统提示和最近两条消息
        if len(self.messages) > 5:
            self.messages = [self.messages[0]] + self.messages[-5:]
        return content

class LLM:

    def __init__(self, system_prompt: Optional[str] = "You are a skilled vulnerability detection rule designer.", model=Model.DEEPSEEK_V3.value, verbose: bool = False):
        self.bot = LLMBot(system_prompt=system_prompt, model=model)
        self.encoding = tiktoken.encoding_for_model("gpt-4")
        self.verbose = verbose

    def count_tokens(slef,text):
        encoding = tiktoken.encoding_for_model("gpt-3.5-turbo")
        tokenized = encoding.encode(text)
        return len(tokenized)
    
    def Transform_rules(self, prompt: str, code: str,max_tokens: int = 3000) -> str:
        """
        Transform the input prompt using the LLM.
        """
        if self.verbose:
            print(f"Input prompt: {prompt}")
            print(f"Max tokens: {max_tokens}")

        response = self.bot.inference(prompt, max_tokens=max_tokens)
        if self.verbose:
            print(f"LLM response: {response}")
        return self.batch_prompt(prompt, var_key="code", var_value=code)
    def clear_context(self):
        """清除上下文，仅保留系统提示"""
        self.bot.clear_context()
        print(self.bot.messages)   
    def Transform(self, prompt: str, max_tokens: int = 3000) -> str:
    
        response = self.bot.inference(prompt, max_tokens=max_tokens)
        if self.verbose:
            print(f"LLM response: {response}")
        return response.strip()
  
if __name__ == "__main__":
    bot = LLMBot(system_prompt="You are a helpful assistant.", model=Model.GPT_4.value)
    response = bot.inference('你知道的代码扫描工具PMD的最新版本是多少')
    print(response)
