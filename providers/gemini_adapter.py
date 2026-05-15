import logging
import httpx

from providers.base import BaseProvider
from gateway.models import NormalizedRequest, AIResponse, ModelProvider
from config import settings

logger = logging.getLogger(__name__)

GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent"


class GeminiAdapter(BaseProvider):
    """Adapter for Google Gemini API."""

    def __init__(self):
        self.api_key = settings.GEMINI_API_KEY

    def is_available(self) -> bool:
        return bool(self.api_key)

    async def complete(self, request: NormalizedRequest) -> AIResponse:
        if not self.is_available():
            raise RuntimeError("Gemini API key is not configured.")

        payload = {"contents": [{"parts": [{"text": request.prompt}]}]}
        url = f"{GEMINI_API_URL}?key={self.api_key}"

        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
            data = response.json()
            content = data["candidates"][0]["content"]["parts"][0]["text"]
            return AIResponse(request_id=request.request_id, model_used=ModelProvider.GEMINI, raw_content=content)