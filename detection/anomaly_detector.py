"""Machine-learning backed anomaly detection for process telemetry."""

from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass
from statistics import median
from typing import Any, Iterable, Mapping

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler

from monitor.process_monitor import ProcessSnapshot


@dataclass(slots=True)
class AnomalyFinding:
    score: float
    is_anomaly: bool
    reasons: list[str]


class AnomalyDetector:
    """Detect abnormal process feature vectors using a rolling trusted baseline.

    The previous implementation trained on the same scan it scored, which can
    normalize already-active malware. This detector keeps prior trusted samples,
    scores current processes against that baseline, and only then lets the
    orchestrator add low-risk samples back into the baseline.
    """

    def __init__(self, config: Mapping[str, Any] | None = None):
        self.config = config or {}
        detection = self.config.get("detection", {}) if isinstance(self.config.get("detection"), Mapping) else {}
        self.minimum_training_samples = int(detection.get("minimum_training_samples", 8))
        self.contamination = float(detection.get("anomaly_contamination", 0.08))
        self.max_baseline_samples = int(detection.get("max_baseline_samples", 2048))
        self.retrain_every = max(1, int(detection.get("retrain_every_samples", 25)))
        self.model: IsolationForest | None = None
        self.scaler: RobustScaler | None = None
        self.baseline: deque[list[float]] = deque(maxlen=self.max_baseline_samples)
        self._samples_since_fit = 0

    def fit(self, snapshots: Iterable[ProcessSnapshot]) -> None:
        """Replace the baseline with explicit training snapshots."""

        self.baseline.clear()
        self.observe_trusted(snapshots)
        self._fit_model(force=True)

    def observe_trusted(self, snapshots: Iterable[ProcessSnapshot]) -> None:
        """Add trusted process samples to the rolling baseline."""

        count = 0
        for snapshot in snapshots:
            self.baseline.append(self._transform_features(snapshot.feature_vector()))
            count += 1
        self._samples_since_fit += count
        if len(self.baseline) >= self.minimum_training_samples and self._samples_since_fit >= self.retrain_every:
            self._fit_model(force=True)

    def score(self, snapshot: ProcessSnapshot) -> AnomalyFinding:
        vector = self._transform_features(snapshot.feature_vector())
        if self.model is not None and self.scaler is not None:
            scaled = self.scaler.transform([vector])
            prediction = int(self.model.predict(scaled)[0])
            raw_score = float(-self.model.decision_function(scaled)[0])
            score = max(0.0, min(100.0, 50.0 + raw_score * 100.0))
            is_anomaly = prediction == -1
            reasons = ["process behavior differs from rolling IsolationForest baseline"] if is_anomaly else []
            return AnomalyFinding(score=score if is_anomaly else min(score, 49.0), is_anomaly=is_anomaly, reasons=reasons)

        score = self._fallback_score(vector)
        is_anomaly = score >= 65.0
        reasons = ["process feature vector is an outlier in the rolling robust baseline"] if is_anomaly else []
        return AnomalyFinding(score=score, is_anomaly=is_anomaly, reasons=reasons)

    def _fit_model(self, force: bool = False) -> None:
        if len(self.baseline) < self.minimum_training_samples:
            self.model = None
            self.scaler = None
            return
        if not force and self._samples_since_fit < self.retrain_every:
            return
        training = list(self.baseline)
        self.scaler = RobustScaler()
        scaled = self.scaler.fit_transform(training)
        self.model = IsolationForest(contamination=self.contamination, random_state=42, n_estimators=150)
        self.model.fit(scaled)
        self._samples_since_fit = 0

    def _fallback_score(self, vector: list[float]) -> float:
        if not self.baseline:
            return 0.0
        columns = list(zip(*self.baseline))
        max_robust_z = 0.0
        for value, column in zip(vector, columns):
            center = median(column)
            deviations = [abs(item - center) for item in column]
            mad = median(deviations) or 1.0
            robust_z = abs((value - center) / (1.4826 * mad))
            max_robust_z = max(max_robust_z, robust_z)
        return min(100.0, max_robust_z * 28.0)

    @staticmethod
    def _transform_features(vector: list[float]) -> list[float]:
        """Log-scale non-negative telemetry to reduce resource spike bias."""

        return [math.log1p(max(0.0, value)) for value in vector]
