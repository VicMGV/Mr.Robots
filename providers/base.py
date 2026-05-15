from abc import ABC, abstractmethod
from gateway.models import NormalizedRequest, AIResponse


class BaseProvider(ABC):
    """
    Abstract base class for all AI provider adapters.
    Every provider (Gemini, Claude, OpenAI, etc.) must implement this interface.
    """

    @abstractmethod
    async def complete(self, request: NormalizedRequest) -> AIResponse:
        """
        Send the request to the AI provider and return the raw response.
        Must be implemented by every provider adapter.
        """
        ...

    @abstractmethod
    def is_available(self) -> bool:
        """
        Check if the provider is reachable and the API key is configured.
        Returns True if ready to handle requests.
        """
        ...
