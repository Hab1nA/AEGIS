"""Deterministic scoring, tamper detection and candidate promotion."""

from .promotion import PairedObservation, PromotionDecision, PromotionPolicy, decide_promotion
from .scoring import EvaluationEvidence, QualityResult, TamperEvidence, detect_tampering, score_quality

__all__ = [
    "EvaluationEvidence",
    "PairedObservation",
    "PromotionDecision",
    "PromotionPolicy",
    "QualityResult",
    "TamperEvidence",
    "decide_promotion",
    "detect_tampering",
    "score_quality",
]
