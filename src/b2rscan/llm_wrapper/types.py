"""LLM types and interfaces."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from typing import List, Optional, Dict, Any


@dataclass
class LLMMessage:
    """Standard LLM message format."""
    role: str
    content: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return asdict(self)


@dataclass
class LLMResponse:
    """Standard LLM response format."""
    content: str
    usage: Optional[Dict[str, int]] = None
    model: Optional[str] = None
    finish_reason: Optional[str] = None


@dataclass
class ModelParameters:
    """Model configuration parameters."""
    model: str = "qwen-plus"
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    temperature: float = 0.7
    max_tokens: Optional[int] = None


class LLMClient(ABC):
    """Abstract base class for LLM clients."""

    def __init__(self, params: ModelParameters) -> None:
        """
        Initialize LLM client.
        
        Args:
            params: Model parameters
        """
        self.params = params

    @abstractmethod
    def complete(self, messages: List[LLMMessage]) -> LLMResponse:
        """
        Generate completion for given messages.
        
        Args:
            messages: List of messages
            
        Returns:
            LLM response
        """
        pass

    @abstractmethod
    def get_token_count(self, text: str) -> int:
        """
        Calculate token count for text.
        
        Args:
            text: Input text
            
        Returns:
            Token count
        """
        pass