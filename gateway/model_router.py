import logging
from typing import Optional

from models import ModelProvider, NormalizedRequest, PolicyResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Fallback chain: if a model fails, try the next one in the list
# ---------------------------------------------------------------------------
FALLBACK_CHAIN: list[ModelProvider] = [
    ModelProvider.GEMINI,
    ModelProvider.CLAUDE,
    ModelProvider.OPENAI,
    ModelProvider.INTERNAL,
]


class ModelRouter:
    def __init__(self, disabled_providers: Optional[list[ModelProvider]] = None):
        """
        disabled_providers: list of models temporarily turned off.
        Used to simulate provider failures or maintenance windows.
        """
        self.disabled_providers: set[ModelProvider] = set(disabled_providers or [])

    # ---------------------------------------------------------------------------
    # Main routing logic
    # ---------------------------------------------------------------------------

    def route(
        self,
        request: NormalizedRequest,
        policy_result: PolicyResult,
    ) -> ModelProvider:
        """
        Decides which model will process the request.

        Priority:
        1. Model assigned by PolicyEngine (already validated against department policy)
        2. Fallback chain if assigned model is disabled
        3. First available model in fallback chain
        """
        assigned = policy_result.assigned_model

        # If the policy assigned a model and it's available, use it
        if assigned and assigned not in self.disabled_providers:
            logger.info(f"[{request.request_id}] Routing to assigned model: {assigned.value}")
            return assigned

        # If assigned model is disabled, try fallback
        if assigned and assigned in self.disabled_providers:
            logger.warning(
                f"[{request.request_id}] Assigned model '{assigned.value}' is disabled. "
                f"Attempting fallback..."
            )
            return self._fallback(request.request_id)

        # No model assigned (shouldn't happen if policy passed), use fallback
        logger.warning(f"[{request.request_id}] No model assigned. Using fallback chain.")
        return self._fallback(request.request_id)

    # ---------------------------------------------------------------------------
    # Fallback logic
    # ---------------------------------------------------------------------------

    def _fallback(self, request_id: str) -> ModelProvider:
        """
        Iterates the fallback chain and returns the first available model.
        Raises RuntimeError if all models are disabled.
        """
        for model in FALLBACK_CHAIN:
            if model not in self.disabled_providers:
                logger.info(f"[{request_id}] Fallback selected: {model.value}")
                return model

        raise RuntimeError("All AI providers are disabled. Cannot route request.")

    # ---------------------------------------------------------------------------
    # Provider management
    # ---------------------------------------------------------------------------

    def disable_provider(self, provider: ModelProvider) -> None:
        """Temporarily disable a provider (e.g. during outage)."""
        self.disabled_providers.add(provider)
        logger.warning(f"Provider disabled: {provider.value}")

    def enable_provider(self, provider: ModelProvider) -> None:
        """Re-enable a previously disabled provider."""
        self.disabled_providers.discard(provider)
        logger.info(f"Provider enabled: {provider.value}")

    def available_providers(self) -> list[ModelProvider]:
        """Returns the list of currently active providers."""
        return [m for m in ModelProvider if m not in self.disabled_providers]