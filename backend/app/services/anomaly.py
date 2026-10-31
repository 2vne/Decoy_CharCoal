from __future__ import annotations
import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

_model: Any = None
_trained: bool = False
_MIN_SAMPLES = 30

FEATURE_KEYS = [
    "num_commands",
    "num_distinct_commands",
    "num_usernames",
    "num_passwords",
    "num_distinct_usernames",
    "num_distinct_passwords",
    "median_gap_seconds",
    "total_events",
    "has_download",
    "has_persistence",
]


def _vector_to_list(fv: Dict[str, Any]) -> List[float]:
    return [float(fv.get(k, 0.0)) for k in FEATURE_KEYS]


def train_model(feature_vectors: List[Dict[str, Any]]) -> bool:
    global _model, _trained
    if len(feature_vectors) < _MIN_SAMPLES:
        return False

    try:
        from sklearn.ensemble import IsolationForest
        import numpy as np

        X = np.array([_vector_to_list(fv) for fv in feature_vectors])
        model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
        model.fit(X)
        _model = model
        _trained = True
        logger.info(f"Isolation Forest trained successfully on {len(feature_vectors)} samples")
        return True
    except Exception as e:
        logger.warning(f"Failed to train Isolation Forest: {e}")
        return False


def predict_anomaly(feature_vector: Dict[str, Any]) -> Tuple[bool, Optional[float]]:
    global _model, _trained
    if not _trained or _model is None:
        return False, None

    try:
        import numpy as np

        X = np.array([_vector_to_list(feature_vector)])
        pred = _model.predict(X)  # -1 = anomaly, 1 = normal
        score = -float(_model.score_samples(X)[0])
        is_anomaly = bool(pred[0] == -1)
        normalized_score = max(0.0, min(1.0, (score + 0.5)))
        return is_anomaly, round(normalized_score, 3)
    except Exception as e:
        logger.warning(f"Isolation Forest prediction error: {e}")
        return False, None


async def retrain_if_needed(db: Any) -> None:
    from sqlalchemy import select
    from app.models import Attacker

    stmt = select(Attacker.feature_vector).where(Attacker.feature_vector.isnot(None))
    res = await db.execute(stmt)
    vectors = [r[0] for r in res.all() if r[0]]
    if len(vectors) >= _MIN_SAMPLES:
        train_model(vectors)

