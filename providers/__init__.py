# Providers package
from providers.gemini_adapter import GeminiAdapter
from providers.claude_adapter import ClaudeAdapter
from providers.groq_adapter import GroqAdapter
from gateway.models import ModelProvider


def get_provider(model: ModelProvider):
    """Factory: returns the right adapter for the given model."""
    if model == ModelProvider.GEMINI:
        return GeminiAdapter()
    if model == ModelProvider.CLAUDE:
        return ClaudeAdapter()
    if model == ModelProvider.GROQ:
        return GroqAdapter()
    raise NotImplementedError(f"No adapter available for model: {model.value}")