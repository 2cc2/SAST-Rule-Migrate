"""OpenAI LLM client implementation."""

import os
from typing import List, Dict, Any, cast

import openai
import tiktoken

from .types import LLMClient, LLMMessage, LLMResponse, ModelParameters


class OpenAIClient(LLMClient):
    """OpenAI LLM client."""

    def __init__(self, params: ModelParameters) -> None:
        """
        Initialize OpenAI client.
        
        Args:
            params: Model parameters
            
        Raises:
            ValueError: If API key is not provided
        """
        super().__init__(params)
        
        # 获取API密钥，优先使用params中的，其次使用环境变量
        api_key = params.api_key or os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OpenAI API key not provided. Set OPENAI_API_KEY environment variable.")
            
        self.client = openai.OpenAI(
            api_key=api_key,
            base_url=params.base_url
        )
        try:
            self.tokenizer = tiktoken.encoding_for_model(params.model)
        except KeyError:
            self.tokenizer = tiktoken.get_encoding("cl100k_base")

    def complete(self, messages: List[LLMMessage]) -> LLMResponse:
        """
        Generate completion using OpenAI API.
        
        Args:
            messages: List of messages
            
        Returns:
            LLM response
        """
        # Convert messages to OpenAI format
        openai_messages: List[Dict[str, Any]] = []
        for msg in messages:
            openai_messages.append({
                "role": msg.role,
                "content": msg.content
            })
            
        response = self.client.chat.completions.create(
            model=self.params.model,
            messages=cast(Any, openai_messages),
            temperature=self.params.temperature,
            max_tokens=self.params.max_tokens
        )
        
        return LLMResponse(
            content=response.choices[0].message.content or "",
            usage={
                "prompt_tokens": response.usage.prompt_tokens,
                "completion_tokens": response.usage.completion_tokens,
                "total_tokens": response.usage.total_tokens
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