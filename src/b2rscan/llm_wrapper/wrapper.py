"""High-level LLM wrapper with context management."""

import logging
import os
from typing import List, Optional, Dict, Any
from .types import LLMMessage, ModelParameters, LLMClient
from .factory import LLMFactory


class LLMWrapper:
    """High-level LLM wrapper with context management capabilities."""

    def __init__(self, provider: str, system_prompt: str = "You are a helpful assistant.",
                 max_context_tokens: int = 128000) -> None:
        """
        Initialize LLM wrapper.
        
        Args:
            provider: LLM provider name
            system_prompt: System prompt for the LLM
            max_context_tokens: Maximum context tokens to maintain
        """
        self.provider = provider
        self.system_prompt = system_prompt
        self.max_context_tokens = max_context_tokens
        self.messages: List[LLMMessage] = [LLMMessage(role="system", content=system_prompt)]
        self.client: Optional[LLMClient] = None
        self.logger = logging.getLogger(__name__)
        modelparameters = ModelParameters(
            model="qwen3-235b-a22b-instruct-2507",
            api_key=os.getenv("dashscope"),  # Will be loaded from environment
        )
        self.configure(modelparameters)

    def configure(self, params: Optional[ModelParameters] = None) -> 'LLMWrapper':
        """
        Configure the LLM client.
        
        Args:
            params: Model parameters
            
        Returns:
            Self for chaining
        """
        if params is None:
            params = ModelParameters()
            
        # 如果没有显式提供API密钥，则从环境变量中获取
        if not params.api_key:
            if self.provider == "dashscope":
                params.api_key = os.getenv("DASHSCOPE_API_KEY")
            elif self.provider == "openai":
                params.api_key = os.getenv("OPENAI_API_KEY")
                
        self.client = LLMFactory.create(self.provider, params)
        return self

    def add_message(self, role: str, content: str) -> None:
        """
        Add a message to the conversation history.
        
        Args:
            role: Message role (system, user, assistant)
            content: Message content
        """
        self.messages.append(LLMMessage(role=role, content=content))

    def infer(self, prompt: str, functions: Optional[List[Dict[str, Any]]] = None) -> str:
        """
        Perform inference with context management.
        
        Args:
            prompt: User prompt
            functions: Optional list of function definitions for function calling
            
        Returns:
            LLM response content
        """
        if not self.client:
            raise RuntimeError("LLM client not configured. Call configure() first.")
            
        self.add_message("user", prompt)
        self._manage_context()

        response = self.client.complete(self.messages, functions)
        self.add_message("assistant", response.content)

        self.logger.info(f"LLM Response: {response.content[:100]}...")
        return response.content

    def _manage_context(self) -> None:
        """Manage conversation context to stay within token limits."""
        if not self.client:
            return
            
        total_tokens = sum(self.client.get_token_count(msg.content) for msg in self.messages)

        while total_tokens > self.max_context_tokens and len(self.messages) > 3:
            # Remove the oldest non-system message
            removed = self.messages.pop(1)  # Keep system message at index 0
            removed_tokens = self.client.get_token_count(removed.content)
            total_tokens -= removed_tokens
            self.logger.info(f"Removed message, freed {removed_tokens} tokens")