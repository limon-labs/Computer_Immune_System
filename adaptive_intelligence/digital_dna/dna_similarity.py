"""Digital DNA similarity and explainability."""

from __future__ import annotations

from typing import Any

from adaptive_intelligence.digital_dna.dna_models import DigitalDNA, DigitalDNAComparison


class DigitalDNASimilarity:
    """Compares Digital DNA records and returns structured explanations."""

    def compare(self, left: DigitalDNA, right: DigitalDNA) -> DigitalDNAComparison:
        left_features = self.features(left)
        right_features = self.features(right)
        matched = sorted(left_features & right_features)
        different = sorted(left_features ^ right_features)
        if not left_features or not right_features:
            similarity = 0.0
        else:
            similarity = round((len(matched) / len(left_features | right_features)) * 100.0, 2)
        confidence = round(min(100.0, (left.confidence + right.confidence) / 2.0 + min(10.0, len(matched))), 2)
        return DigitalDNAComparison(
            left_dna_id=left.dna_id,
            right_dna_id=right.dna_id,
            similarity_score=similarity,
            confidence=confidence,
            matched_features=matched,
            different_features=different,
            evolution_history=[*left.change_history[-5:], *right.change_history[-5:]],
        )

    def features(self, dna: DigitalDNA) -> set[str]:
        features: set[str] = set()
        self._add_mapping_features(features, "identity", dna.identity, include_values=("sha256", "publisher"))
        self._add_mapping_features(features, "lineage", dna.process_lineage, include_values=("parent_executable",))
        self._add_mapping_features(features, "behavior", dna.behavior_profile, include_values=("startup_behavior",))
        self._add_mapping_features(features, "network", dna.network_profile, include_values=("common_remote_ports", "protocol_usage"))
        self._add_mapping_features(features, "filesystem", dna.filesystem_profile, include_values=("frequently_accessed_directories", "temporary_file_usage"))
        self._add_mapping_features(features, "registry", dna.registry_profile, include_values=("startup_persistence", "registry_modification_patterns"))
        self._add_mapping_features(features, "security", dna.security_profile, include_values=("previous_incidents",))
        return features

    def _add_mapping_features(self, features: set[str], prefix: str, payload: dict[str, Any], include_values: tuple[str, ...]) -> None:
        for key in include_values:
            value = payload.get(key)
            if value in (None, "", [], {}):
                continue
            if isinstance(value, list):
                for item in value[:20]:
                    features.add(f"{prefix}.{key}:{item}")
            elif isinstance(value, dict):
                for item_key, item_value in sorted(value.items())[:20]:
                    features.add(f"{prefix}.{key}:{item_key}:{item_value}")
            else:
                features.add(f"{prefix}.{key}:{value}")
