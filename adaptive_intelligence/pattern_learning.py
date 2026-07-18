"""Pattern learning over remembered immune-memory incidents."""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Iterable, Mapping

from adaptive_intelligence.models import LearnedPattern


class MemoryPatternLearner:
    """Aggregates immune-memory rows into reusable behavioral patterns."""

    def learn(self, memory_rows: Iterable[Mapping[str, Any]]) -> list[LearnedPattern]:
        grouped: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
        for row in memory_rows:
            pattern_key = str(row.get("pattern_key") or "")
            if pattern_key:
                grouped[pattern_key].append(row)

        patterns: list[LearnedPattern] = []
        for pattern_key, rows in grouped.items():
            features = Counter()
            confidences = []
            recurrences = []
            incident_types = Counter()
            last_seen = None
            for row in rows:
                incident_types[str(row.get("incident_type") or "unknown")] += 1
                confidences.append(float(row.get("confidence_score", 0.0)))
                recurrences.append(float(row.get("recurrence_score", 0.0)))
                last_seen = max(last_seen or str(row.get("observed_at") or ""), str(row.get("observed_at") or ""))
                fingerprint = row.get("fingerprint", {})
                if isinstance(fingerprint, Mapping):
                    features.update(str(feature) for feature in fingerprint.get("features", []))
            patterns.append(
                LearnedPattern(
                    pattern_key=pattern_key,
                    incident_type=incident_types.most_common(1)[0][0],
                    occurrences=len(rows),
                    average_confidence=round(sum(confidences) / max(1, len(confidences)), 2),
                    average_recurrence=round(sum(recurrences) / max(1, len(recurrences)), 2),
                    top_features=[feature for feature, _count in features.most_common(10)],
                    last_seen=last_seen,
                )
            )
        patterns.sort(key=lambda pattern: (pattern.occurrences, pattern.average_confidence, pattern.last_seen or ""), reverse=True)
        return patterns
