"""Dependency-free inference for the exported logistic-regression model.

The model is trained with scikit-learn in ml/train.py and exported to model.json
(scaler mean/scale + coefficients). Serving needs only the standard library, which
keeps the AWS Lambda package tiny and cold starts fast.
"""
from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Dict

from .features import FEATURES, MODEL_FEATURES

MODEL_PATH = Path(__file__).with_name("model.json")


class ThreatModel:
    def __init__(self, spec: dict):
        self.spec = spec
        self.features = spec["features"]
        assert self.features == MODEL_FEATURES, "model.json out of sync with features.py - re-run ml/train.py"
        assert set(self.features) <= set(FEATURES)
        self.mean = spec["mean"]
        self.scale = spec["scale"]
        self.coef = spec["coef"]
        self.intercept = spec["intercept"]
        self.threshold = spec.get("threshold", 0.5)

    @classmethod
    def load(cls, path: Path = MODEL_PATH) -> "ThreatModel":
        return cls(json.loads(Path(path).read_text()))

    def score(self, feats: Dict[str, float]) -> float:
        z = self.intercept
        for i, name in enumerate(self.features):
            x = math.log1p(feats[name]) if name in self.spec.get("log_features", []) else feats[name]
            z += self.coef[i] * (x - self.mean[i]) / self.scale[i]
        return 1.0 / (1.0 + math.exp(-z))

    def verdict(self, p: float) -> str:
        if p >= 0.85:
            return "block"
        if p >= self.threshold:
            return "suspicious"
        return "ok"
