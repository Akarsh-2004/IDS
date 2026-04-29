from __future__ import annotations

import queue
import threading
import time
from pathlib import Path
from typing import Any

from model_pipeline import ModelMeta, load_model, load_model_meta, predict_one
from realtime.alerts import AlertPolicy
from realtime.capture import capture_live, capture_pcap_tail
from realtime.features import flow_to_model_features
from realtime.flows import FlowWindowBuilder
from realtime.metrics import RuntimeMetrics
from realtime.store import EventStore


class RealtimeEngine:
    def __init__(self, db_path: Path) -> None:
        self.metrics = RuntimeMetrics()
        self.store = EventStore(db_path)
        self.policy = AlertPolicy(dedupe_window_sec=10)
        self.flow_builder = FlowWindowBuilder(window_sec=5)
        self.queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=5000)
        self.model, self.feature_columns = load_model()
        self.meta: ModelMeta = load_model_meta()
        self._mode = "live"
        self._interface = ""
        self._pcap_path: Path | None = None
        self._thread_capture: threading.Thread | None = None
        self._thread_infer: threading.Thread | None = None
        self._stop_event = threading.Event()

    def configure(self, mode: str, interface: str | None = None, pcap_path: str | None = None) -> None:
        self._mode = mode
        self._interface = interface or ""
        self._pcap_path = Path(pcap_path) if pcap_path else None

    def is_running(self) -> bool:
        return bool(self._thread_capture and self._thread_capture.is_alive())

    def stop(self) -> None:
        self._stop_event.set()

    def _stop_check(self) -> bool:
        return self._stop_event.is_set()

    def _emit_packet(self, pkt: dict[str, Any]) -> None:
        self.metrics.inc("packet_count")
        try:
            self.queue.put_nowait(pkt)
            self.metrics.set_queue_depth(self.queue.qsize())
        except queue.Full:
            self.metrics.inc("dropped_count")

    def _capture_loop(self) -> None:
        if self._mode == "pcap":
            if not self._pcap_path:
                raise RuntimeError("pcap_path required for pcap mode")
            capture_pcap_tail(self._pcap_path, self._stop_check, self._emit_packet)
        else:
            if not self._interface:
                raise RuntimeError("interface required for live mode")
            capture_live(self._interface, self._stop_check, self._emit_packet)

    def _inference_loop(self) -> None:
        while not self._stop_check():
            try:
                pkt = self.queue.get(timeout=0.5)
            except queue.Empty:
                continue
            self.metrics.set_queue_depth(self.queue.qsize())
            flow_stats = self.flow_builder.update(pkt)
            self.metrics.inc("flow_count")
            features, details = flow_to_model_features(flow_stats, self.meta)
            prediction = predict_one(self.model, self.feature_columns, features, self.meta, strict=False)
            self.metrics.inc("prediction_count")
            event_data = self.policy.build_event(prediction, details, source=self._mode)
            if event_data:
                self.store.add_event(**event_data)
                self.metrics.inc("alert_count")

    def start(self) -> None:
        if self.is_running():
            return
        self._stop_event.clear()
        self.metrics = RuntimeMetrics()
        self._thread_capture = threading.Thread(target=self._capture_loop, daemon=True)
        self._thread_infer = threading.Thread(target=self._inference_loop, daemon=True)
        self._thread_capture.start()
        self._thread_infer.start()

    def status(self) -> dict[str, Any]:
        return {
            "running": self.is_running(),
            "mode": self._mode,
            "interface": self._interface,
            "pcap_path": str(self._pcap_path) if self._pcap_path else None,
            "metrics": self.metrics.snapshot(),
        }

    def heartbeat(self) -> dict[str, Any]:
        return {"type": "heartbeat", "ts": time.time(), "metrics": self.metrics.snapshot()}
