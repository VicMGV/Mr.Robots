import logging
import httpx

from providers.base import BaseProvider
from gateway.models import NormalizedRequest, AIResponse, ModelProvider
from config import settings

logger = logging.getLogger(__name__)

CLAUDE_API_URL = "https://api.anthropic.com/v1/messages"
CLAUDE_MODEL   = "claude-3-5-haiku-20241022"


class ClaudeAdapter(BaseProvider):
    """Adapter for Anthropic Claude API."""

    def __init__(self):
        self.api_key = settings.CLAUDE_API_KEY

    def is_available(self) -> bool:
        return bool(self.api_key)

    async def complete(self, request: NormalizedRequest) -> AIResponse:
        if not self.is_available():
            raise RuntimeError("Claude API key is not configured.")

        headers = {"x-api-key": self.api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"}
        payload = {"model": CLAUDE_MODEL, "max_tokens": 1024, "messages": [{"role": "user", "content": request.prompt}]}

        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(CLAUDE_API_URL, headers=headers, json=payload)
            response.raise_for_status()
            data = response.json()
            content = data["content"][0]["text"]
            return AIResponse(request_id=request.request_id, model_used=ModelProvider.CLAUDE, raw_content=content)