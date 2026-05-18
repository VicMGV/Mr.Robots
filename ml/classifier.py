import logging
import torch
from transformers import pipeline
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# We use a zero-shot classification model.
# This means it doesn't need to be retrained — it understands threat
# categories just from their labels, using natural language.
# Model: cross-encoder/nli-distilroberta-base (lightweight, fast)
# ---------------------------------------------------------------------------
MODEL_NAME = "cross-encoder/nli-distilroberta-base"

# Threat categories the model will classify against
THREAT_LABELS = [
    "prompt injection attack",
    "jailbreak attempt",
    "data exfiltration request",
    "policy bypass attempt",
    "agent abuse attempt",
    "unsafe or illegal content request",
    "normal safe request",
]

# If confidence for any threat label exceeds this, it's flagged
THREAT_THRESHOLD = 0.70


class MLThreatClassifier:
    """
    Zero-shot threat classifier using DistilRoBERTa.
    Detects threat type and confidence without needing labeled training data.
    Uses GPU if available for faster inference.
    """

    def __init__(self):
        self._pipeline = None
        self._device = self._get_device()
        self._loaded = False

    def _get_device(self) -> int:
        """Returns 0 for GPU, -1 for CPU."""
        if torch.cuda.is_available():
            logger.info(f"ML Classifier using GPU: {torch.cuda.get_device_name(0)}")
            return 0
        logger.warning("GPU not found, falling back to CPU.")
        return -1

    def load(self) -> None:
        """
        Loads the model into memory.
        Called once at startup — first load downloads the model (~250MB).
        Subsequent runs load from cache instantly.
        """
        if self._loaded:
            return
        try:
            logger.info(f"Loading ML model: {MODEL_NAME} on {'GPU' if self._device == 0 else 'CPU'}")
            self._pipeline = pipeline(
                "zero-shot-classification",
                model=MODEL_NAME,
                device=self._device,
            )
            self._loaded = True
            logger.info("ML model loaded successfully.")
        except Exception as e:
            logger.error(f"Failed to load ML model: {e}")
            self._loaded = False

    def is_loaded(self) -> bool:
        return self._loaded

    def classify(self, prompt: str) -> Optional[dict]:
        """
        Classifies a prompt against all threat labels.

        Returns:
        {
            "is_threat": True/False,
            "threat_label": "prompt injection attack",
            "confidence": 0.91,
            "all_scores": { label: score, ... }
        }
        Returns None if the model is not loaded.
        """
        if not self._loaded or self._pipeline is None:
            logger.warning("ML model not loaded, skipping classification.")
            return None

        try:
            result = self._pipeline(
                prompt[:512],           # DistilBERT max token limit
                candidate_labels=THREAT_LABELS,
                multi_label=False,      # pick the most likely single label
            )

            # Result is sorted by score descending
            top_label: str  = result["labels"][0]
            top_score: float = result["scores"][0]

            is_threat = (
                top_label != "normal safe request"
                and top_score >= THREAT_THRESHOLD
            )

            return {
                "is_threat":    is_threat,
                "threat_label": top_label,
                "confidence":   round(top_score, 4),
                "all_scores":   dict(zip(result["labels"], result["scores"])),
            }

        except Exception as e:
            logger.error(f"ML classification error: {e}")
            return None


# ---------------------------------------------------------------------------
# Singleton — one instance shared across the app
# ---------------------------------------------------------------------------
ml_classifier = MLThreatClassifier()