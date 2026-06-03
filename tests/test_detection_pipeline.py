from __future__ import annotations

from adaptive.threat_scoring import ThreatScorer
from detection.anomaly_detector import AnomalyDetector
from detection.heuristic_analysis import BehaviorAnalyzer
from monitor.process_monitor import ProcessSnapshot


def make_snapshot(pid: int, cpu: float = 1.0, cmd: str = "python app.py") -> ProcessSnapshot:
    return ProcessSnapshot(
        pid=pid,
        name="python",
        command_line=cmd,
        cpu_percent=cpu,
        memory_percent=1.0,
        num_threads=4,
        open_files=3,
        connections=0,
    )


def test_behavior_analyzer_flags_suspicious_command_line():
    analyzer = BehaviorAnalyzer({"detection": {"suspicious_cmdline_patterns": ["base64"]}})

    finding = analyzer.analyze(make_snapshot(1, cmd="python -c base64payload"))

    assert finding.score > 0
    assert finding.reasons


def test_anomaly_detector_fallback_scores_outlier():
    detector = AnomalyDetector({"detection": {"minimum_training_samples": 99}})
    detector.fit([make_snapshot(pid) for pid in range(10)])

    finding = detector.score(make_snapshot(99, cpu=99.0))

    assert finding.score >= 65
    assert finding.is_anomaly


def test_threat_scorer_combines_findings():
    snapshot = make_snapshot(7, cmd="python -c base64payload")
    behavior = BehaviorAnalyzer({"detection": {"suspicious_cmdline_patterns": ["base64"]}}).analyze(snapshot)
    anomaly = AnomalyDetector({"detection": {"minimum_training_samples": 99}})
    anomaly.fit([make_snapshot(pid) for pid in range(10)])
    anomaly_finding = anomaly.score(make_snapshot(7, cpu=99.0))

    event = ThreatScorer().score(snapshot, anomaly_finding, behavior)

    assert event.pid == 7
    assert event.threat_score > 0
    assert "base64" in " ".join(event.reasons)


def test_policy_allowlist_reduces_score_without_suppressing_name_only_response():
    from core.policy_engine import PolicyEngine

    snapshot = make_snapshot(10, cpu=99.0)
    decision = PolicyEngine({"policy": {"allowlist": {"process_names": ["python"]}, "allowlist_score_reduction": 30}}).evaluate(snapshot)

    assert decision.action == "allow"
    assert not decision.suppress_response
    assert decision.score_adjustment < 0
