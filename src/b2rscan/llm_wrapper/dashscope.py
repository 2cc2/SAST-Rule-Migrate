"""DashScope LLM client implementation."""

import os
from typing import List, Dict, Any, cast, Optional

import openai
import tiktoken

from .types import LLMClient, LLMMessage, LLMResponse, ModelParameters


class DashScopeClient(LLMClient):
    """DashScope LLM client."""

    def __init__(self, params: ModelParameters) -> None:
        """
        Initialize DashScope client.
        
        Args:
            params: Model parameters
            
        Raises:
            ValueError: If API key is not provided
        """
        super().__init__(params)
        
        # 获取API密钥，优先使用params中的，其次使用环境变量
        api_key = params.api_key or os.getenv("DASHSCOPE_API_KEY")
        if not api_key:
            raise ValueError("DashScope API key not provided. Set DASHSCOPE_API_KEY environment variable.")
            
        self.client = openai.OpenAI(
            api_key=api_key,
            base_url=params.base_url or "https://dashscope.aliyuncs.com/compatible-mode/v1"
        )
        try:
            self.tokenizer = tiktoken.encoding_for_model(params.model)
        except KeyError:
            self.tokenizer = tiktoken.get_encoding("cl100k_base")

    def complete(self, messages: List[LLMMessage], functions: Optional[List[Dict[str, Any]]] = None) -> LLMResponse:
        """
        Generate completion using DashScope API.
        
        Args:
            messages: List of messages
            functions: Optional list of function definitions for function calling
            
        Returns:
            LLM response
        """
        # Convert messages to DashScope format
        dashscope_messages: List[Dict[str, Any]] = []
        for msg in messages:
            dashscope_messages.append({
                "role": msg.role,
                "content": msg.content
            })
            
        # Prepare API call parameters
        api_params = {
            "model": self.params.model,
            "messages": cast(Any, dashscope_messages),
            "temperature": self.params.temperature,
        }
        
        if self.params.max_tokens:
            api_params["max_tokens"] = self.params.max_tokens
            
        # Add function definitions if provided
        if functions:
            api_params["functions"] = functions
            api_params["function_call"] = "auto"
            
        response = self.client.chat.completions.create(**api_params)
        
        return LLMResponse(
            content=response.choices[0].message.content or "",
            usage={
                "prompt_tokens": response.usage.prompt_tokens if response.usage else 0,
                "completion_tokens": response.usage.completion_tokens if response.usage else 0,
                "total_tokens": response.usage.total_tokens if response.usage else 0
            } if response.usage else None,
            model=response.model,
            finish_reason=response.choices[0].finish_reason
        )

    def get_token_count(self, text: str) -> int:
        """
        Calculate token count for text.
        
        Args:
            text: Input text
            
        Returns:
            Token count
        """
        return len(self.tokenizer.encode(text))