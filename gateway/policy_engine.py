import json
import logging
from pathlib import Path
from typing import Optional

from models import NormalizedRequest, PolicyResult, ModelProvider

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Política por defecto si el departamento no tiene un JSON definido
# ---------------------------------------------------------------------------
DEFAULT_POLICY = {
    "allowed_models": ["gemini"],
    "blocked_actions": [],
    "blocked_keywords": [],
    "max_prompt_length": 4000,
    "allow_external_providers": False,
}


class PolicyEngine:
    def __init__(self, policies_dir: str = "policies"):
        self.policies_dir = Path(policies_dir)
        self._cache: dict[str, dict] = {}
        self._load_all_policies()

    # ---------------------------------------------------------------------------
    # Carga de políticas desde archivos JSON
    # ---------------------------------------------------------------------------

    def _load_all_policies(self) -> None:
        """Carga todos los JSON de la carpeta policies/ al iniciar."""
        if not self.policies_dir.exists():
            logger.warning(f"Policies directory not found: {self.policies_dir}")
            return

        for policy_file in self.policies_dir.glob("*.json"):
            department = policy_file.stem  # "finance.json" → "finance"
            try:
                with open(policy_file, "r", encoding="utf-8") as f:
                    self._cache[department] = json.load(f)
                logger.info(f"Policy loaded: {department}")
            except Exception as e:
                logger.error(f"Failed to load policy {policy_file}: {e}")

    def _get_policy(self, department: Optional[str]) -> dict:
        """Retorna la política del departamento o la política por defecto."""
        if department and department.lower() in self._cache:
            return self._cache[department.lower()]
        logger.warning(f"No policy found for department '{department}', using default.")
        return DEFAULT_POLICY

    # ---------------------------------------------------------------------------
    # Evaluación principal
    # ---------------------------------------------------------------------------

    def evaluate(self, request: NormalizedRequest) -> PolicyResult:
        """
        Evalúa la solicitud contra la política del departamento.
        Retorna un PolicyResult con allowed=True/False y el modelo asignado.
        """
        policy = self._get_policy(request.department)

        # 1. Verificar longitud del prompt
        max_length = policy.get("max_prompt_length", 4000)
        if len(request.prompt) > max_length:
            return PolicyResult(
                request_id=request.request_id,
                department=request.department,
                allowed=False,
                assigned_model=None,
                reason=f"Prompt exceeds max length of {max_length} characters.",
            )

        # 2. Verificar keywords bloqueadas
        blocked_keywords = policy.get("blocked_keywords", [])
        prompt_lower = request.prompt.lower()
        for keyword in blocked_keywords:
            if keyword.lower() in prompt_lower:
                return PolicyResult(
                    request_id=request.request_id,
                    department=request.department,
                    allowed=False,
                    assigned_model=None,
                    reason=f"Prompt contains blocked keyword: '{keyword}'.",
                )

        # 3. Verificar modelo solicitado vs modelos permitidos
        allowed_models = policy.get("allowed_models", ["gemini"])
        assigned_model = self._resolve_model(
            preferred=request.preferred_model,
            allowed=allowed_models,
        )

        if assigned_model is None:
            return PolicyResult(
                request_id=request.request_id,
                department=request.department,
                allowed=False,
                assigned_model=None,
                reason=(
                    f"Requested model '{request.preferred_model}' is not allowed "
                    f"for department '{request.department}'. "
                    f"Allowed: {allowed_models}"
                ),
            )

        # 4. Todo OK
        return PolicyResult(
            request_id=request.request_id,
            department=request.department,
            allowed=True,
            assigned_model=assigned_model,
            reason=None,
        )

    # ---------------------------------------------------------------------------
    # Helpers
    # ---------------------------------------------------------------------------

    def _resolve_model(
        self,
        preferred: Optional[ModelProvider],
        allowed: list[str],
    ) -> Optional[ModelProvider]:
        """
        Si el modelo preferido está permitido, lo usa.
        Si no hay preferencia, usa el primero de la lista de permitidos.
        Si el preferido no está permitido, retorna None.
        """
        if preferred is None:
            # Sin preferencia → usar el primero disponible
            return ModelProvider(allowed[0]) if allowed else None

        if preferred.value in allowed:
            return preferred

        return None  # modelo solicitado no permitido