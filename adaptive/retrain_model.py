"""Model retraining helper."""

from __future__ import annotations

from detection.anomaly_detector import AnomalyDetector
from monitor.process_monitor import ProcessSnapshot


def retrain_detector(detector: AnomalyDetector, snapshots: list[ProcessSnapshot]) -> AnomalyDetector:
    detector.fit(snapshots)
    return detector
