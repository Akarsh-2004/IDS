from __future__ import annotations

import time
from typing import Any


class AlertPolicy:
    def __init__(self, dedupe_window_sec: int = 10) -> None:
        self.dedupe_window_sec = dedupe_window_sec
        self._last_seen: dict[str, float] = {}

    @staticmethod
    def severity_from_score(score: float) -> str:
        if score >= 0.9:
            return "critical"
        if score >= 0.75:
            return "high"
        if score >= 0.5:
            return "medium"
        return "low"

    def should_emit(self, fingerprint: str) -> bool:
        now = time.time()
        last = self._last_seen.get(fingerprint)
        if last and (now - last) < self.dedupe_window_sec:
            return False
        self._last_seen[fingerprint] = now
        return True

    def build_event(self, prediction: dict[str, Any], details: dict[str, Any], source: str) -> dict[str, Any] | None:
        intrusion_score = float((prediction.get("probabilities") or {}).get("intrusion", prediction["prediction"]))
        label = prediction["label"]
        if label != "intrusion":
            return None
        fingerprint = f"{source}:{details.get('src_ip','na')}:{details.get('dst_ip','na')}:{details.get('service','na')}"
        if not self.should_emit(fingerprint):
            return None
        severity = self.severity_from_score(intrusion_score)
        return {
            "label": label,
            "severity": severity,
            "score": intrusion_score,
            "source": source,
            "details": details,
        }
