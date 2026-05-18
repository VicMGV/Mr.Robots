import re
import json
import logging
import requests
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)

# ML layer import
try:
    from ml.classifier import ml_classifier
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False


class ThreatType(str, Enum):
    PROMPT_INJECTION  = "prompt_injection"
    JAILBREAK         = "jailbreak"
    DATA_EXFILTRATION = "data_exfiltration"
    POLICY_BYPASS     = "policy_bypass"
    AGENT_ABUSE       = "agent_abuse"
    UNSAFE_BEHAVIOR   = "unsafe_behavior"
    CLEAN             = "clean"


class Action(str, Enum):
    ALLOW    = "allow"
    WARN     = "warn"
    BLOCK    = "block"
    ESCALATE = "escalate"


@dataclass
class ThreatResult:
    risk_score:  float
    threat_type: ThreatType
    confidence:  float
    action:      Action
    details:     list[str] = field(default_factory=list)
    llm_used:    bool = False

    def to_dict(self) -> dict:
        return {
            "risk_score":  round(self.risk_score, 3),
            "threat_type": self.threat_type.value,
            "confidence":  round(self.confidence, 3),
            "action":      self.action.value,
            "details":     self.details,
            "llm_used":    self.llm_used,
        }


RULES: dict[ThreatType, list[str]] = {
    ThreatType.PROMPT_INJECTION: [
        r"ignore\s+(all\s+)?(previous|prior)\s+instructions?",
        r"disregard\s+(your|the|all)\s+(previous\s+)?instructions?",
        r"forget\s+(everything|all|previous)",
        r"new\s+instructions?[\s:]+",
        r"system\s*:\s*you\s+are\s+now",
        r"your\s+real\s+instructions?\s+are",
        r"override\s+(safety|guidelines?|rules?)",
        r"do\s+not\s+follow\s+(your\s+)?(previous\s+)?instructions?",
        r"from\s+now\s+on\s+(you|ignore|forget)",
    ],
    ThreatType.JAILBREAK: [
        r"reveal\s+(your\s+)?(hidden\s+)?system\s+prompt",
        r"disable\s+(safety|filters?|restrictions?|guardrails?)",
        r"act\s+as\s+if\s+you\s+(have\s+no|don.?t\s+have)\s+(restrictions?|rules?)",
        r"pretend\s+you\s+(are\s+)?(an?\s+)?(evil|unrestricted|jailbroken)",
        r"\bdan\s+mode\b",
        r"developer\s+mode\s+(enabled|activated|on)",
        r"you\s+are\s+now\s+(free|unrestricted|without\s+(rules?|limitations?))",
        r"\bjailbreak\b",
        r"no\s+(restrictions?|rules?|limits?)\s+(mode|enabled|on)",
        r"(stay|keep)\s+in\s+character.{0,30}(no\s+limit|unrestricted)",
    ],
    ThreatType.DATA_EXFILTRATION: [
        r"export\s+(all\s+)?(confidential|internal|sensitive|private)\s+\w+\s+(data|information|files?)",
        r"export\s+(all\s+)?(confidential|internal|sensitive|private)\s+(data|information|files?)",
        r"send\s+(this\s+)?(sensitive\s+|confidential\s+|private\s+|internal\s+)?(data|information|files?)\s+to\s+",
        r"reveal\s+.{0,10}(api[\s_]?key|password|secret|credential|token)",
        r"print\s+(all\s+)?(user|customer|employee)\s+(data|records?|information)",
        r"dump\s+(the\s+)?(database|db|data)",
        r"list\s+(all\s+)?(internal|private|confidential)\s+(\w+\s+)?(files?|documents?|data)",
        r"share\s+(all\s+)?(confidential|internal|private)\s+(data|files?|documents?)",
        r"upload.{0,20}(internal|confidential|private).{0,20}(server|endpoint|url)",
    ],
    ThreatType.POLICY_BYPASS: [
        r"bypass\s+(the\s+)?(policy|policies|rules?|restrictions?|filters?)",
        r"skip\s+(the\s+)?(validation|check|policy|filter)",
        r"without\s+(going\s+through|following)\s+(the\s+)?(policy|rules?|guidelines?)",
        r"how\s+(to|do\s+i)\s+avoid\s+(detection|the\s+(filter|policy|check))",
        r"get\s+around\s+(the\s+)?(rules?|restrictions?|policy|filter)",
        r"circumvent\s+(the\s+)?(policy|rules?|filters?|restrictions?)",
    ],
    ThreatType.AGENT_ABUSE: [
        r"execute\s+(this\s+)?(code|script|command)\s+on\s+(the\s+)?(server|system|machine)",
        r"run\s+(as\s+)?(root|admin|administrator)",
        r"access\s+(the\s+)?(file\s+system|filesystem|os|shell)",
        r"call\s+(external|unauthorized)\s+(api|service|endpoint)",
        r"spawn\s+(a\s+)?(subprocess|process|shell)",
        r"open\s+(a\s+)?(terminal|shell|command\s+prompt)",
        r"(read|write|delete)\s+files?\s+(from|on|in)\s+(the\s+)?(server|system)",
    ],
    ThreatType.UNSAFE_BEHAVIOR: [
        r"how\s+(to\s+|do\s+i\s+)?(make|create|build|synthesize)\s+(a\s+)?(bomb|weapon|malware|virus|exploit)",
        r"(generate|write|create)\s+(malware|ransomware|spyware|trojan|keylogger)",
        r"write\s+.{0,15}keylogger",
        r"\bself[-\s]harm\b",
        r"illegal\s+(activity|operation|action)",
        r"how\s+(to\s+)?(hack|crack|exploit)\s+(a\s+)?(system|server|account|website)",
        r"(make|synthesize|produce)\s+(illegal\s+)?(drugs?|controlled\s+substances?|poison)",
        r"synthesize\s+.{0,15}drugs?",
        
    ],
    
    ThreatType.UNSAFE_BEHAVIOR: [
    r"how\s+(to\s+|do\s+i\s+|i\s+do\s+|can\s+i\s+|would\s+i\s+)?(make|create|build|synthesize)\s+(a\s+)?(bomb|weapon|malware|virus|exploit)",
    r"how\s+(do\s+i|can\s+i|would\s+i)\s+(make|build|create)",
    r"steps\s+to\s+(make|build|create)\s+(a\s+)?(bomb|weapon)",
    r"tutorial\s+(for|on)\s+(making|building)\s+(a\s+)?(bomb|weapon)",
    r"(generate|write|create)\s+(malware|ransomware|spyware|trojan|keylogger)",
    r"write\s+.{0,15}keylogger",
    r"\bself[-\s]harm\b",
    r"illegal\s+(activity|operation|action)",
    r"how\s+(to\s+)?(hack|crack|exploit)\s+(a\s+)?(system|server|account|website)",
    r"(make|synthesize|produce)\s+(illegal\s+)?(drugs?|controlled\s+substances?|poison)",
    r"synthesize\s+.{0,15}drugs?",
],
}

_COMPILED_RULES: dict[ThreatType, list[re.Pattern]] = {
    threat: [re.compile(p, re.IGNORECASE) for p in patterns]
    for threat, patterns in RULES.items()
}


def _run_rules(prompt: str) -> tuple[ThreatType, float, list[str]]:
    details: list[str] = []
    detected = ThreatType.CLEAN
    score = 0.0
    for threat_type, patterns in _COMPILED_RULES.items():
        for pattern in patterns:
            if pattern.search(prompt):
                details.append(f"[L1:rule] {threat_type.value} → '{pattern.pattern}'")
                if detected == ThreatType.CLEAN:
                    detected = threat_type
                    score = 0.75
    return detected, score, details


SUSPICIOUS_KEYWORDS: list[str] = [
    "ignore", "override", "bypass", "disable", "forget",
    "unrestricted", "jailbreak", "admin", "root", "secret",
    "confidential", "export", "dump", "reveal", "hidden",
    "pretend", "act as", "developer mode", "system prompt",
    "no restrictions", "without limits", "free mode",
]

MULTILANG_SIGNALS: dict[str, list[str]] = {
    "es": ["ignora", "olvida", "revela", "deshabilita", "sin restricciones"],
    "fr": ["ignorez", "oubliez", "révélez", "désactiver", "sans restriction"],
    "de": ["ignoriere", "vergiss", "enthülle", "deaktiviere", "ohne einschränkungen"],
    "pt": ["ignore", "esqueça", "revele", "desative", "sem restrições"],
}


def _run_heuristics(prompt: str) -> tuple[float, list[str]]:
    score = 0.0
    reasons: list[str] = []
    lower = prompt.lower()

    length = len(prompt)
    if length > 3000:
        score += 0.20
        reasons.append(f"[L2:heuristic] prompt_very_long ({length} chars)")
    elif length > 1500:
        score += 0.08
        reasons.append(f"[L2:heuristic] prompt_long ({length} chars)")

    newlines = prompt.count("\n")
    if newlines > 30:
        score += 0.15
        reasons.append(f"[L2:heuristic] high_newline_count ({newlines})")
    elif newlines > 15:
        score += 0.06
        reasons.append(f"[L2:heuristic] medium_newline_count ({newlines})")

    matched_kw = [kw for kw in SUSPICIOUS_KEYWORDS if kw in lower]
    if matched_kw:
        kw_score = min(len(matched_kw) * 0.09, 0.45)
        score += kw_score
        reasons.append(f"[L2:heuristic] suspicious_keywords ({len(matched_kw)}): {matched_kw}")

    if re.search(r"base64|\\x[0-9a-f]{2}|\\u[0-9a-f]{4}", lower):
        score += 0.30
        reasons.append("[L2:heuristic] obfuscation_detected (base64/hex)")

    words = lower.split()
    if len(words) > 15:
        unique_ratio = len(set(words)) / len(words)
        if unique_ratio < 0.35:
            score += 0.15
            reasons.append(f"[L2:heuristic] low_word_diversity (ratio={round(unique_ratio, 2)})")

    for lang, signals in MULTILANG_SIGNALS.items():
        if any(s in lower for s in signals):
            score += 0.30
            reasons.append(f"[L2:heuristic] multilang_injection (lang={lang})")
            break

    special_chars = len(re.findall(r"[{}\[\]<>|\\]", prompt))
    if special_chars > 15:
        score += 0.10
        reasons.append(f"[L2:heuristic] high_special_char_count ({special_chars})")

    return min(score, 1.0), reasons


OLLAMA_URL    = "http://localhost:11434/api/generate"
OLLAMA_MODEL  = "phi"
MAX_LLM_CHARS = 1500

_LLM_PROMPT_TEMPLATE = """You are a security classifier for an enterprise AI system. Classify the following user prompt as a security threat.

IMPORTANT: Data exfiltration includes asking about salaries, internal finances, employee data, or any confidential company information.

Text: "{prompt}"

Respond with ONLY this JSON:
{{"is_threat": true, "threat_type": "data_exfiltration", "confidence": 0.9, "reason": "one sentence"}}

Or if clean:
{{"is_threat": false, "threat_type": "clean", "confidence": 0.9, "reason": "one sentence"}}

JSON:"""


def _parse_llm_response(raw: str) -> Optional[dict]:
    try:
        match = re.search(r'\{[^{}]*"is_threat"[^{}]*\}', raw, re.DOTALL)
        if not match:
            logger.error(f"No JSON found in LLM response | Raw: {raw[:200]}")
            return None
        clean = match.group(0)
        parsed = json.loads(clean)
        required = {"is_threat", "threat_type", "confidence", "reason"}
        if not required.issubset(parsed.keys()):
            logger.warning(f"LLM missing fields: {parsed}")
            return None
        parsed["confidence"] = max(0.0, min(float(parsed["confidence"]), 1.0))
        return parsed
    except (json.JSONDecodeError, ValueError) as e:
        logger.error(f"LLM parse error: {e} | Raw: {raw[:200]}")
        return None


def _run_llm(prompt: str) -> Optional[dict]:
    try:
        payload = {
            "model": OLLAMA_MODEL,
            "prompt": _LLM_PROMPT_TEMPLATE.format(prompt=prompt[:MAX_LLM_CHARS]),
            "stream": False,
            "options": {
                "temperature": 0.1,
                "num_predict": 150,
            }
        }
        response = requests.post(OLLAMA_URL, json=payload, timeout=120)
        response.raise_for_status()
        raw = response.json().get("response", "").strip()
        raw = raw + "}"
        return _parse_llm_response(raw)
    except requests.exceptions.ConnectionError:
        logger.error("Ollama not running. Start with: ollama serve")
        return None
    except requests.exceptions.Timeout:
        logger.error("Ollama request timed out")
        return None
    except Exception as e:
        logger.error(f"LLM error: {e}")
        return None


def _determine_action(risk_score: float) -> Action:
    if risk_score >= 0.85:
        return Action.ESCALATE
    elif risk_score >= 0.65:
        return Action.BLOCK
    elif risk_score >= 0.35:
        return Action.WARN
    return Action.ALLOW


class ThreatDetector:
    def __init__(self, use_llm: bool = False, use_ml: bool = True):
        self.use_llm = use_llm
        self.use_ml = use_ml and ML_AVAILABLE

        # Load ML model at startup
        if self.use_ml:
            ml_classifier.load()

    def analyze(self, prompt: str, context: Optional[dict] = None) -> ThreatResult:
        all_details: list[str] = []
        llm_used = False

        # Layer 1 — Rules
        rule_threat, rule_score, rule_details = _run_rules(prompt)
        all_details.extend(rule_details)

        # Layer 2 — Heuristics
        h_score, h_details = _run_heuristics(prompt)
        all_details.extend(h_details)

        h_weight = 0.35 if rule_score > 0 else 0.80
        combined_score = min(rule_score + (h_score * h_weight), 1.0)
        detected_threat = rule_threat

        # Layer 2.5 — ML (DistilBERT)
        if self.use_ml and ml_classifier.is_loaded():
            ml_result = ml_classifier.classify(prompt)
            if ml_result:
                ml_confidence = ml_result["confidence"]
                if ml_result["is_threat"]:
                    ml_score = ml_confidence * 0.80
                    combined_score = (combined_score * 0.50) + (ml_score * 0.50)
                    if detected_threat == ThreatType.CLEAN:
                        detected_threat = ThreatType.UNSAFE_BEHAVIOR
                    all_details.append(
                        f"[L2.5:ml] threat='{ml_result['threat_label']}' | "
                        f"confidence={ml_confidence}"
                    )
                else:
                    combined_score *= (1 - ml_confidence * 0.20)
                    all_details.append(
                        f"[L2.5:ml] clean | confidence={ml_confidence}"
                    )

        # Layer 3 — LLM (Ollama, optional)
        ambiguous = 0.20 <= combined_score <= 0.70
        no_rule_match = rule_threat == ThreatType.CLEAN

        if self.use_llm and (ambiguous or no_rule_match):
            llm_result = _run_llm(prompt)
            if llm_result:
                llm_used = True
                llm_confidence = llm_result.get("confidence", 0.5)
                if llm_result.get("is_threat"):
                    llm_threat_str = llm_result.get("threat_type", "unsafe_behavior")
                    try:
                        detected_threat = ThreatType(llm_threat_str)
                    except ValueError:
                        detected_threat = ThreatType.UNSAFE_BEHAVIOR
                    llm_score = llm_confidence * 0.85
                    combined_score = (combined_score * 0.55) + (llm_score * 0.45)
                    all_details.append(
                        f"[L3:llm] threat={llm_threat_str} | "
                        f"confidence={llm_confidence} | "
                        f"reason={llm_result.get('reason', '')}"
                    )
                else:
                    combined_score *= (1 - llm_confidence * 0.30)
                    all_details.append(
                        f"[L3:llm] clean | confidence={llm_confidence} | "
                        f"reason={llm_result.get('reason', '')}"
                    )

        final_score = round(min(combined_score, 1.0), 3)
        action = _determine_action(final_score)

        if detected_threat == ThreatType.CLEAN:
            confidence = round(max(1.0 - final_score, 0.50), 3)
        else:
            confidence = round(min(0.60 + final_score * 0.40, 1.0), 3)

        return ThreatResult(
            risk_score=final_score,
            threat_type=detected_threat,
            confidence=confidence,
            action=action,
            details=all_details,
            llm_used=llm_used,
        )