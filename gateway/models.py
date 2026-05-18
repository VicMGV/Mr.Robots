from pydantic import BaseModel, Field
from typing import Optional
from enum import Enum

class ModelProvider(str, Enum):
    OPENAI   = "openai"
    GEMINI   = "gemini"
    CLAUDE   = "claude"
    GROQ     = "groq"
    INTERNAL = "internal"


class ThreatAction(str, Enum):
    ALLOW    = "allow"
    WARN     = "warn"
    BLOCK    = "block"
    ESCALATE = "escalate"


class ThreatType(str, Enum):
    PROMPT_INJECTION  = "prompt_injection"
    JAILBREAK         = "jailbreak"
    DATA_EXFILTRATION = "data_exfiltration"
    POLICY_BYPASS     = "policy_bypass"
    NONE              = "none"


class AIRequest(BaseModel):

    prompt: str = Field(..., description="Prompt sent by the user")
    preferred_model: Optional[ModelProvider] = Field(
        default=None,
        description="Preferred model. The router may override it based on policies."
    )
    department: Optional[str] = Field(
        default=None,
        description="Requester's department."
    )
    metadata: Optional[dict] = Field(
        default_factory=dict,
        description="Additional context information."
    )


class NormalizedRequest(BaseModel):

    request_id: str
    user_id: str
    department: Optional[str]
    prompt: str
    preferred_model: Optional[ModelProvider]
    metadata: dict


class ThreatAnalysis(BaseModel):
    request_id: str
    threat_type: ThreatType
    risk_score: float = Field(..., ge=0.0, le=1.0, description="Score from 0.0 to 1.0")
    confidence: float = Field(..., ge=0.0, le=1.0)
    action: ThreatAction
    reason: Optional[str] = None

class PolicyResult(BaseModel):
    request_id: str
    department: Optional[str]
    allowed: bool
    assigned_model: Optional[ModelProvider]
    reason: Optional[str] = None


class AIResponse(BaseModel):
    request_id: str
    model_used: ModelProvider
    raw_content: str


class ValidatedResponse(BaseModel):
    request_id: str
    model_used: ModelProvider
    content: str
    flagged: bool = False
    flag_reason: Optional[str] = None

class GatewayResponse(BaseModel):
    request_id: str
    content: str
    model_used: ModelProvider
    risk_score: float
    flagged: bool = False