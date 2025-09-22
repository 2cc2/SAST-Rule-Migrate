"""LLM client factory."""

from typing import Dict, Type

from .types import LLMClient, ModelParameters
from .openai import OpenAIClient
from .dashscope import DashScopeClient


class LLMFactory:
    """Factory for creating LLM clients."""
    
    # Registry of available clients
    _clients: Dict[str, Type[LLMClient]] = {
        "openai": OpenAIClient,
        "dashscope": DashScopeClient
    }
    
    @classmethod
    def register(cls, name: str, client_class: Type[LLMClient]) -> None:
        """
        Register a new client type.
        
        Args:
            name: Provider name
            client_class: Client class
        """
        cls._clients[name] = client_class
    
    @classmethod
    def create(cls, provider: str, params: ModelParameters) -> LLMClient:
        """
        Create LLM client instance.
        
        Args:
            provider: Provider name
            params: Model parameters
            
        Returns:
            LLM client instance
            
        Raises:
            ValueError: If provider is not supported
        """
        if provider not in cls._clients:
            raise ValueError(f"Unsupported provider: {provider}")
        return cls._clients[provider](params)
    
    @classmethod
    def list_providers(cls) -> list:
        """
        List all supported providers.
        
        Returns:
            List of provider names
        """
        return list(cls._clients.keys())