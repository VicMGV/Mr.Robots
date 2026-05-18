import logging
import httpx

from providers.base import BaseProvider
from gateway.models import NormalizedRequest, AIResponse, ModelProvider
from config import settings

logger = logging.getLogger(__name__)

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL   = "llama-3.3-70b-versatile"  # fast + free tier


class GroqAdapter(BaseProvider):
    """Adapter for Groq API — OpenAI-compatible, high rate limits on free tier."""

    def __init__(self):
        self.api_key = settings.GROQ_API_KEY

    def is_available(self) -> bool:
        """Returns True if the Groq API key is configured."""
        return bool(self.api_key)

    async def complete(self, request: NormalizedRequest) -> AIResponse:
        """Send prompt to Groq and return normalized AIResponse."""
        if not self.is_available():
            raise RuntimeError("Groq API key is not configured.")

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "model": GROQ_MODEL,
            "messages": [
                {"role": "user", "content": request.prompt}
            ],
            "max_tokens": 1024,
            "temperature": 0.7,
        }

        async with httpx.AsyncClient(timeout=30) as client:
            try:
                response = await client.post(GROQ_API_URL, headers=headers, json=payload)
                response.raise_for_status()
                data = response.json()

                # OpenAI-compatible response format
                content = data["choices"][0]["message"]["content"]

                return AIResponse(
                    request_id=request.request_id,
                    model_used=ModelProvider.GROQ,
                    raw_content=content,
                )

            except httpx.HTTPStatusError as e:
                logger.error(f"Groq HTTP error: {e.response.status_code} - {e.response.text}")
                raise
            except Exception as e:
                logger.error(f"Groq unexpected error: {e}")
                raise
