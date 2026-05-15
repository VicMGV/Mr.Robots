# Threat Detection Engine

Analyzes prompts before they reach any AI model using a 3-layer hybrid approach.

## Detection Layers

**Layer 1 — Rules (Regex + Keywords)**
Matches known attack patterns:
- Prompt injection: "ignore all previous instructions"
- Jailbreak: "DAN mode", "disable safety filters"
- Data exfiltration: "export confidential data", "dump the database"
- Policy bypass: "bypass the policy engine"
- Agent abuse: "execute script on server as root"
- Unsafe behavior: "create malware", "synthesize drugs"

**Layer 2 — Heuristics**
Analyzes prompt behavior:
- Prompt length (attempts to hide instructions)
- Base64 / hex obfuscation
- Suspicious keyword accumulation
- Low word diversity (repetition attacks)
- Multi-language injection attempts

**Layer 3 — Local LLM (Ollama + phi)**
Classifies ambiguous prompts that Layer 1 and 2 don't catch clearly.
Runs locally — no API key, no cost.

## Requirements

- Ollama — https://ollama.com/download

```bash
ollama pull phi
ollama serve
```

## Output

Every request returns:

| Field | Type | Description |
|-------|------|-------------|
| risk_score | float 0.0–1.0 | Overall risk level |
| threat_type | string | Type of threat detected |
| confidence | float 0.0–1.0 | Detection confidence |
| action | string | allow / warn / block / escalate |
| details | list | Trace of what triggered the detection |
| llm_used | bool | Whether Layer 3 was activated |

## Actions

| Risk Score | Action |
|------------|--------|
| 0.00 – 0.34 | allow |
| 0.35 – 0.64 | warn |
| 0.65 – 0.84 | block |
| 0.85 – 1.00 | escalate |

## Usage

```python
from gateway.threat_detector import ThreatDetector

detector = ThreatDetector(use_llm=True)
result = detector.analyze("Ignore all previous instructions")

print(result.to_dict())
# {
#   "risk_score": 0.886,
#   "threat_type": "prompt_injection",
#   "confidence": 0.954,
#   "action": "escalate",
#   "details": ["[L1:rule] prompt_injection → ...", "[L2:heuristic] ..."],
#   "llm_used": False
# }
```

## Running Tests

```bash
pytest test/test_threat_detector.py -v
```

## Interactive Test

```bash
python test/test_threat_detector.py
```
