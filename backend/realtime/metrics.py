from __future__ import annotations

import threading
import time


class RuntimeMetrics:
    def __init__(self) -> None:
        self.started_at = time.time()
        self.packet_count = 0
        self.flow_count = 0
        self.prediction_count = 0
        self.alert_count = 0
        self.dropped_count = 0
        self.queue_depth = 0
        self._lock = threading.Lock()

    def inc(self, field: str, value: int = 1) -> None:
        with self._lock:
            setattr(self, field, getattr(self, field) + value)

    def set_queue_depth(self, value: int) -> None:
        with self._lock:
            self.queue_depth = value

    def snapshot(self) -> dict[str, float | int]:
        with self._lock:
            elapsed = max(time.time() - self.started_at, 1e-6)
            return {
                "uptime_sec": round(elapsed, 2),
                "packet_count": self.packet_count,
                "flow_count": self.flow_count,
                "prediction_count": self.prediction_count,
                "alert_count": self.alert_count,
                "dropped_count": self.dropped_count,
                "queue_depth": self.queue_depth,
                "packets_per_sec": round(self.packet_count / elapsed, 2),
                "alerts_per_min": round((self.alert_count / elapsed) * 60.0, 2),
            }
