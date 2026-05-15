import uuid
import time
import logging
import sys
import os

from fastapi import FastAPI, HTTPException, Security
from fastapi.security import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.status import HTTP_403_FORBIDDEN

# ---------------------------------------------------------------------------
# Path setup — allows imports from project root
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gateway.models import (
    AIRequest, NormalizedRequest, GatewayResponse, ModelProvider
)
from gateway.threat_detector import ThreatDetector, Action
from gateway.policy_engine import PolicyEngine
from gateway.model_router import ModelRouter
from gateway.response_validator import ResponseValidator, ValidationAction
from gateway.audit_logger import AuditLogger
from providers import get_provider
from config import settings

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "Centralized AI Governance Gateway. "
        "Every request passes through threat detection, policy enforcement, "
        "model routing, and response validation before reaching the user."
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve static dashboard files if the folder exists
if os.path.exists("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")

# ---------------------------------------------------------------------------
# Pipeline components — instantiated once at startup
# ---------------------------------------------------------------------------
threat_detector    = ThreatDetector(use_llm=False)
policy_engine      = PolicyEngine(policies_dir=settings.POLICIES_DIR)
model_router       = ModelRouter()
response_validator = ResponseValidator()
audit_logger       = AuditLogger(log_to_file=True)

# ---------------------------------------------------------------------------
# Auth — simple API Key via header
# ---------------------------------------------------------------------------
API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

VALID_API_KEYS: dict[str, dict] = {
    "key-finance-001":     {"user_id": "finance-user-1",  "department": "finance"},
    "key-engineering-001": {"user_id": "eng-user-1",      "department": "engineering"},
    "key-legal-001":       {"user_id": "legal-user-1",    "department": "hr"},
}


async def authenticate(api_key: str = Security(API_KEY_HEADER)) -> dict:
    if not api_key:
        raise HTTPException(
            status_code=HTTP_403_FORBIDDEN,
            detail="Missing API Key. Use the X-API-Key header.",
        )
    user = VALID_API_KEYS.get(api_key)
    if not user:
        raise HTTPException(
            status_code=HTTP_403_FORBIDDEN,
            detail="Invalid or unauthorized API Key.",
        )
    return user


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------
@app.get("/health", tags=["System"])
async def health():
    """Returns gateway status and available providers."""
    return {
        "status": "ok",
        "version": settings.APP_VERSION,
        "available_providers": [m.value for m in model_router.available_providers()],
    }


# ---------------------------------------------------------------------------
# Audit endpoints — for the dashboard
# ---------------------------------------------------------------------------
@app.get("/audit", tags=["Audit"])
async def get_audit_log():
    """Returns all recorded audit entries."""
    return audit_logger.get_all()


@app.get("/audit/summary", tags=["Audit"])
async def get_audit_summary():
    """Returns a summary of gateway activity."""
    return audit_logger.summary()


@app.get("/audit/blocked", tags=["Audit"])
async def get_blocked_requests():
    """Returns all blocked requests."""
    return audit_logger.get_blocked()


# ---------------------------------------------------------------------------
# Main endpoint — the full governance pipeline
# ---------------------------------------------------------------------------
@app.post("/v1/ai/request", response_model=GatewayResponse, tags=["Gateway"])
async def ai_request(
    request: AIRequest,
    user: dict = Security(authenticate),
):
    """
    Full governance pipeline:
    1. Normalize request
    2. Threat detection
    3. Policy enforcement
    4. Model routing
    5. AI model call
    6. Response validation
    7. Audit logging
    """
    start_time = time.time()
    request_id = str(uuid.uuid4())
    department = request.department or user.get("department")

    logger.info(f"[{request_id}] New request from user={user['user_id']} dept={department}")

    # --- 1. Normalize ---
    normalized = NormalizedRequest(
        request_id=request_id,
        user_id=user["user_id"],
        department=department,
        prompt=request.prompt,
        preferred_model=request.preferred_model,
        metadata=request.metadata or {},
    )

    # --- 2. Threat Detection ---
    threat = threat_detector.analyze(normalized.prompt)
    logger.info(f"[{request_id}] Threat: {threat.threat_type.value} | score={threat.risk_score} | action={threat.action.value}")

    if threat.action in (Action.BLOCK, Action.ESCALATE):
        audit_logger.log(
            request_id=request_id,
            user_id=user["user_id"],
            department=department,
            prompt=normalized.prompt,
            model_used=None,
            risk_score=threat.risk_score,
            threat_type=threat.threat_type.value,
            action=threat.action.value,
            policy_allowed=False,
            response_flagged=False,
            duration_ms=round((time.time() - start_time) * 1000, 2),
        )
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Request blocked by threat detection.",
                "threat_type": threat.threat_type.value,
                "risk_score": threat.risk_score,
                "action": threat.action.value,
            },
        )

    # --- 3. Policy Enforcement ---
    policy_result = policy_engine.evaluate(normalized)
    logger.info(f"[{request_id}] Policy: allowed={policy_result.allowed} model={policy_result.assigned_model}")

    if not policy_result.allowed:
        audit_logger.log(
            request_id=request_id,
            user_id=user["user_id"],
            department=department,
            prompt=normalized.prompt,
            model_used=None,
            risk_score=threat.risk_score,
            threat_type=threat.threat_type.value,
            action="block",
            policy_allowed=False,
            response_flagged=False,
            flag_reason=policy_result.reason,
            duration_ms=round((time.time() - start_time) * 1000, 2),
        )
        raise HTTPException(
            status_code=403,
            detail={
                "error": "Request blocked by policy engine.",
                "reason": policy_result.reason,
            },
        )

    # --- 4. Model Routing ---
    selected_model = model_router.route(normalized, policy_result)
    logger.info(f"[{request_id}] Routed to model: {selected_model.value}")

    # --- 5. AI Model Call ---
    try:
        provider = get_provider(selected_model)
        ai_response = await provider.complete(normalized)
    except Exception as e:
        logger.error(f"[{request_id}] Provider error: {e}")
        raise HTTPException(status_code=502, detail=f"AI provider error: {str(e)}")

    # --- 6. Response Validation ---
    validation = response_validator.validate(ai_response.raw_content)
    logger.info(f"[{request_id}] Validation: action={validation.action.value} findings={len(validation.findings)}")

    if validation.action == ValidationAction.BLOCK:
        audit_logger.log(
            request_id=request_id,
            user_id=user["user_id"],
            department=department,
            prompt=normalized.prompt,
            model_used=selected_model.value,
            risk_score=threat.risk_score,
            threat_type=threat.threat_type.value,
            action="block",
            policy_allowed=True,
            response_flagged=True,
            flag_reason=str([f.type.value for f in validation.findings]),
            duration_ms=round((time.time() - start_time) * 1000, 2),
        )
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Response blocked by validator.",
                "findings": [f.to_dict() for f in validation.findings],
            },
        )

    # Use redacted content if available, otherwise raw
    final_content = validation.redacted_response or ai_response.raw_content
    flagged = validation.action == ValidationAction.REDACT

    # --- 7. Audit Logging ---
    duration_ms = round((time.time() - start_time) * 1000, 2)
    audit_logger.log(
        request_id=request_id,
        user_id=user["user_id"],
        department=department,
        prompt=normalized.prompt,
        model_used=selected_model.value,
        risk_score=threat.risk_score,
        threat_type=threat.threat_type.value,
        action=threat.action.value,
        policy_allowed=True,
        response_flagged=flagged,
        flag_reason=str([f.type.value for f in validation.findings]) if flagged else None,
        duration_ms=duration_ms,
    )

    logger.info(f"[{request_id}] Completed in {duration_ms}ms")

    return GatewayResponse(
        request_id=request_id,
        content=final_content,
        model_used=selected_model,
        risk_score=threat.risk_score,
        flagged=flagged,
    )
