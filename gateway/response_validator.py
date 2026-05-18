import re
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class ValidationAction(str, Enum):
    ALLOW  = "allow"
    REDACT = "redact"
    BLOCK  = "block"


class FindingType(str, Enum):
    API_KEY         = "api_key"
    CREDENTIAL      = "credential"
    PII_EMAIL       = "pii_email"
    PII_PHONE       = "pii_phone"
    PII_SSN         = "pii_ssn"
    PII_CREDIT_CARD = "pii_credit_card"
    PII_IBAN        = "pii_iban"
    FINANCIAL       = "financial_data"
    INTERNAL_IP     = "internal_ip"
    INTERNAL_URL    = "internal_url"
    DB_CONNECTION   = "db_connection_string"
    JWT_TOKEN       = "jwt_token"
    PRIVATE_KEY     = "private_key"
    MEDICAL         = "medical_data"
    SALARY          = "salary_data"
    SOURCE_CODE     = "source_code_leak"
    HALLUCINATION   = "critical_hallucination"


@dataclass
class Finding:
    type:     FindingType
    match:    str
    detail:   str
    severity: str

    def to_dict(self) -> dict:
        return {
            "type":     self.type.value,
            "match":    self.match[:60] + "..." if len(self.match) > 60 else self.match,
            "detail":   self.detail,
            "severity": self.severity,
        }


@dataclass
class ValidationResult:
    action:            ValidationAction
    findings:          list[Finding] = field(default_factory=list)
    redacted_response: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "action":            self.action.value,
            "findings":          [f.to_dict() for f in self.findings],
            "findings_count":    len(self.findings),
            "redacted_response": self.redacted_response,
        }


API_KEY_PATTERNS: list[tuple[str, str, str]] = [
    (r"sk-ant-[a-zA-Z0-9\-_]{20,}", "Anthropic API Key", "anthropic"),
    (r"sk-[a-zA-Z0-9]{20,}", "OpenAI API Key", "openai"),
    (r"AIza[0-9A-Za-z\-_]{35}", "Google API Key", "google"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID", "aws"),
    (r"(?:aws_secret|AWS_SECRET)[_\s]*(?:access_key)?[_\s]*[=:]\s*[a-zA-Z0-9/+=]{40}", "AWS Secret Key", "aws"),
    (r"ghp_[a-zA-Z0-9]{36}", "GitHub Personal Access Token", "github"),
    (r"ghs_[a-zA-Z0-9]{36}", "GitHub App Token", "github"),
    (r"xox[baprs]-[0-9A-Za-z\-]{10,}", "Slack Token", "slack"),
    (r"ya29\.[0-9A-Za-z\-_]+", "Google OAuth Token", "google"),
    (r"sk_(?:live|test)_[0-9a-zA-Z]{24,}", "Stripe Secret Key", "stripe"),
    (r"EAA[a-zA-Z0-9]+", "Facebook Access Token", "facebook"),
    (r"AC[a-z0-9]{32}", "Twilio Account SID", "twilio"),
    (r"(?:bearer|Bearer)\s+[a-zA-Z0-9\-_=]+\.[a-zA-Z0-9\-_=]+\.[a-zA-Z0-9\-_=]+", "Bearer Token", "generic"),
]

CREDENTIAL_PATTERNS: list[tuple[str, str]] = [
    (r"(?:password|passwd|pwd)\s*[=:]\s*\S+", "Password in plaintext"),
    (r"(?:secret|SECRET)\s*[=:]\s*[a-zA-Z0-9\-_!@#$%^&*]{8,}", "Secret value"),
    (r"(?:token|TOKEN)\s*[=:]\s*[a-zA-Z0-9\-_\.]{16,}", "Token value"),
    (r"(?:api_key|API_KEY|apikey|APIKEY)\s*[=:]\s*[a-zA-Z0-9\-_]{16,}", "Generic API key"),
    (r"(?:private_key|PRIVATE_KEY)\s*[=:]\s*\S+", "Private key value"),
    (r"mysql://[^\s]+|postgresql://[^\s]+|mongodb://[^\s]+|redis://[^\s]+", "DB connection string"),
    (r"(?:jdbc:[a-z]+://)[^\s]+", "JDBC connection string"),
    (r"Server=[^;]+;(?:Database|Initial Catalog)=[^;]+;(?:User Id|UID)=[^;]+;Password=[^;]+", "SQL Server connection string"),
]

JWT_PATTERN     = r"eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+"
PRIVATE_KEY_PATTERN = r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"

PII_PATTERNS: list[tuple[str, FindingType, str]] = [
    (r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", FindingType.PII_EMAIL, "Email address"),
    (r"\+?1?\s?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4}", FindingType.PII_PHONE, "US phone number"),
    (r"\b\d{3}-\d{2}-\d{4}\b", FindingType.PII_SSN, "US Social Security Number"),
    (r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b", FindingType.PII_CREDIT_CARD, "Credit card number"),
    (r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}(?:[A-Z0-9]{0,16})?\b", FindingType.PII_IBAN, "IBAN"),
]

FINANCIAL_PATTERNS: list[str] = [
    r"(?:salary|payroll|compensation)\s*(?:of|:)?\s*\$?\d+",
    r"(?:acquisition|merger)\s+(?:of)\s+\w+",
    r"(?:revenue|profit|earnings)\s*(?:projected|forecast)?\s*(?:of|:)?\s*\$?\d+",
    r"(?:budget)\s*(?:of|:)?\s*\$?\d+",
    r"(?:Q[1-4])\s+(?:quarter)\s+(?:results|numbers)",
    r"(?:account\s+number|routing\s+number)\s*:?\s*\d{8,}",
]

INTERNAL_PATTERNS: list[tuple[str, FindingType, str]] = [
    (r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
     FindingType.INTERNAL_IP, "Internal/private IP address"),
    (r"(?:https?://)?(?:internal|intranet|corp|dev|staging|prod)\.[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}",
     FindingType.INTERNAL_URL, "Internal URL/hostname"),
    (r"\\\\[a-zA-Z0-9\-]+\\[a-zA-Z0-9\-\\]+",
     FindingType.INTERNAL_URL, "Windows network path"),
]

MEDICAL_KEYWORDS = [
    "diagnosis", "medical record", "prescription", "patient id",
    "icd-10", "hipaa", "phi", "medical history", "clinical notes",
]

SALARY_KEYWORDS = [
    "salary", "payroll", "compensation", "bonus",
    "stock option", "annual income", "pay grade", "wage",
]

SOURCE_CODE_PATTERNS = [
    r"(?:def|function|class|import|require|include)\s+\w+.*\n(?:.*\n){5,}",
    r"(?:SELECT|INSERT|UPDATE|DELETE)\s+.{50,}",
    r"(?:private|protected|internal)\s+(?:static\s+)?(?:void|int|string|bool|class)\s+\w+",
]

HALLUCINATION_PATTERNS = [
    r"(?:i guarantee)\s+.{0,50}(?:will)",
    r"(?:as per our contract|our agreement states)",
    r"(?:legally)\s+(?:you must|you are required)",
    r"(?:the law requires|you are legally obligated)",
    r"(?:i can confirm)\s+.{0,30}(?:diagnosis|medical)",
]

REDACT_PATTERNS: list[tuple[str, str]] = [
    (r"sk-ant-[a-zA-Z0-9\-_]{20,}", "[REDACTED:ANTHROPIC_KEY]"),
    (r"sk-[a-zA-Z0-9]{20,}", "[REDACTED:OPENAI_KEY]"),
    (r"AIza[0-9A-Za-z\-_]{35}", "[REDACTED:GOOGLE_KEY]"),
    (r"AKIA[0-9A-Z]{16}", "[REDACTED:AWS_KEY]"),
    (r"ghp_[a-zA-Z0-9]{36}", "[REDACTED:GITHUB_TOKEN]"),
    (r"xox[baprs]-[0-9A-Za-z\-]{10,}", "[REDACTED:SLACK_TOKEN]"),
    (r"eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+", "[REDACTED:JWT_TOKEN]"),
    (r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "[REDACTED:PRIVATE_KEY]"),
    (r"((?:password|passwd|pwd)\s*[=:]\s*)\S+", r"\1[REDACTED]"),
    (r"((?:secret|SECRET)\s*[=:]\s*)[a-zA-Z0-9\-_!@#$%^&*]{8,}", r"\1[REDACTED]"),
    (r"((?:token|TOKEN)\s*[=:]\s*)[a-zA-Z0-9\-_\.]{16,}", r"\1[REDACTED]"),
    (r"((?:api_key|API_KEY|apikey)\s*[=:]\s*)[a-zA-Z0-9\-_]{16,}", r"\1[REDACTED]"),
    (r"(mysql|postgresql|mongodb|redis)://[^\s]+", r"\1://[REDACTED]"),
    (r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", "[REDACTED:EMAIL]"),
    (r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED:SSN]"),
    (r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b", "[REDACTED:CARD]"),
    (r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b", "[REDACTED:INTERNAL_IP]"),
]

BLOCKING_TYPES = {
    FindingType.API_KEY,
    FindingType.CREDENTIAL,
    FindingType.JWT_TOKEN,
    FindingType.PRIVATE_KEY,
    FindingType.PII_SSN,
    FindingType.PII_CREDIT_CARD,
    FindingType.PII_IBAN,
    FindingType.DB_CONNECTION,
}

REDACT_TYPES = {
    FindingType.PII_EMAIL,
    FindingType.PII_PHONE,
    FindingType.INTERNAL_IP,
    FindingType.INTERNAL_URL,
    FindingType.FINANCIAL,
    FindingType.SALARY,
    FindingType.MEDICAL,
}


def _detect_api_keys(response: str) -> list[Finding]:
    findings = []
    for pattern, label, provider in API_KEY_PATTERNS:
        for match in re.findall(pattern, response):
            findings.append(Finding(type=FindingType.API_KEY, match=match, detail=f"{label} ({provider})", severity="critical"))
    return findings


def _detect_credentials(response: str) -> list[Finding]:
    findings = []
    for pattern, label in CREDENTIAL_PATTERNS:
        for match in re.findall(pattern, response, re.IGNORECASE):
            findings.append(Finding(type=FindingType.CREDENTIAL, match=match, detail=label, severity="critical"))
    if re.search(JWT_PATTERN, response):
        findings.append(Finding(type=FindingType.JWT_TOKEN, match="[JWT TOKEN DETECTED]", detail="JSON Web Token found in response", severity="critical"))
    if re.search(PRIVATE_KEY_PATTERN, response):
        findings.append(Finding(type=FindingType.PRIVATE_KEY, match="[PRIVATE KEY DETECTED]", detail="Private key found in response", severity="critical"))
    return findings


def _detect_pii(response: str) -> list[Finding]:
    findings = []
    for pattern, finding_type, label in PII_PATTERNS:
        for match in re.findall(pattern, response):
            findings.append(Finding(type=finding_type, match=match, detail=label, severity="high"))
    return findings


def _detect_financial(response: str) -> list[Finding]:
    findings = []
    for pattern in FINANCIAL_PATTERNS:
        for match in re.findall(pattern, response, re.IGNORECASE):
            findings.append(Finding(type=FindingType.FINANCIAL, match=match, detail="Sensitive financial data detected", severity="high"))
    return findings


def _detect_internal_infrastructure(response: str) -> list[Finding]:
    findings = []
    for pattern, finding_type, label in INTERNAL_PATTERNS:
        for match in re.findall(pattern, response, re.IGNORECASE):
            findings.append(Finding(type=finding_type, match=match, detail=label, severity="high"))
    return findings


def _detect_medical(response: str) -> list[Finding]:
    lower = response.lower()
    matched = [kw for kw in MEDICAL_KEYWORDS if kw in lower]
    if matched:
        return [Finding(type=FindingType.MEDICAL, match=str(matched), detail="Medical/health data keywords detected", severity="high")]
    return []


def _detect_salary(response: str) -> list[Finding]:
    lower = response.lower()
    matched = [kw for kw in SALARY_KEYWORDS if kw in lower]
    if len(matched) >= 2:
        return [Finding(type=FindingType.SALARY, match=str(matched), detail="Salary/payroll data keywords detected", severity="high")]
    return []


def _detect_source_code(response: str) -> list[Finding]:
    for pattern in SOURCE_CODE_PATTERNS:
        if re.search(pattern, response, re.IGNORECASE | re.MULTILINE):
            return [Finding(type=FindingType.SOURCE_CODE, match="[SOURCE CODE BLOCK DETECTED]", detail="Possible proprietary source code leak", severity="medium")]
    return []


def _detect_hallucinations(response: str) -> list[Finding]:
    findings = []
    for pattern in HALLUCINATION_PATTERNS:
        for match in re.findall(pattern, response, re.IGNORECASE):
            findings.append(Finding(type=FindingType.HALLUCINATION, match=match, detail="Possible critical hallucination (legal/medical/contractual claim)", severity="high"))
    return findings


def _redact(response: str) -> str:
    redacted = response
    for pattern, replacement in REDACT_PATTERNS:
        redacted = re.sub(pattern, replacement, redacted, flags=re.IGNORECASE)
    return redacted


class ResponseValidator:
    def __init__(self, strict_mode: bool = False):
        self.strict_mode = strict_mode

    def validate(self, response: str, context: Optional[dict] = None) -> ValidationResult:
        all_findings: list[Finding] = []
        all_findings.extend(_detect_api_keys(response))
        all_findings.extend(_detect_credentials(response))
        all_findings.extend(_detect_pii(response))
        all_findings.extend(_detect_financial(response))
        all_findings.extend(_detect_internal_infrastructure(response))
        all_findings.extend(_detect_medical(response))
        all_findings.extend(_detect_salary(response))
        all_findings.extend(_detect_source_code(response))
        all_findings.extend(_detect_hallucinations(response))

        if not all_findings:
            return ValidationResult(action=ValidationAction.ALLOW, findings=[], redacted_response=response)

        blocking = [f for f in all_findings if f.type in BLOCKING_TYPES]
        redacting = [f for f in all_findings if f.type in REDACT_TYPES]

        if blocking or self.strict_mode:
            return ValidationResult(action=ValidationAction.BLOCK, findings=all_findings, redacted_response=None)

        if redacting:
            return ValidationResult(action=ValidationAction.REDACT, findings=all_findings, redacted_response=_redact(response))

        return ValidationResult(action=ValidationAction.ALLOW, findings=all_findings, redacted_response=response)
