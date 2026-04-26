from __future__ import annotations

import queue
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import json

import numpy as np
import pandas as pd

from config import (
    ACTIVE_TIMEOUT_SEC,
    ACTIVITY_GAP_SEC,
    ALERT_JSON_PATH,
    ALERT_LOG_PATH,
    AUTO_BLACKLIST_ML_DETECTIONS,
    BATCH_SIZE,
    BATCH_WAIT_SEC,
    BLOCK_ON_MALICIOUS_ML,
    ENABLE_WHITELIST_SHORTCIRCUIT,
    FLOW_IDLE_TIMEOUT_SEC,
    LABEL_MAP,
    MODEL_CONFIDENCE_THRESHOLD,
    MODEL_PATH,
    PREPROCESSOR_PATH,
    TRAIN_HEADER_SOURCE,
)
from protocol_module import FlowKey, FlowState, PacketEvent, canonicalize_packet
from signature_engine import IOCDecision, IOCStore

try:
    import joblib
except Exception:  # pragma: no cover - optional dependency in runtime
    joblib = None

try:
    import tensorflow as tf
except Exception as exc:  # pragma: no cover - optional dependency in runtime
    tf = None
    TF_IMPORT_ERROR = exc
else:
    TF_IMPORT_ERROR = None


@dataclass(slots=True)
class InferenceItem:
    flow_key: FlowKey
    features: dict[str, float]
    initiator_ip: str


@dataclass(slots=True)
class ClassifiedFlow:
    flow_key: FlowKey
    features: dict[str, float]
    verdict: str
    label: str
    confidence: float
    reason: str
    action_ip: str | None = None


class Preprocessor:
    def __init__(self, feature_order: list[str], preprocessor_path: Path | None = None) -> None:
        self.feature_order = feature_order
        self.preprocessor_path = preprocessor_path
        self.transformer = None
        if preprocessor_path and preprocessor_path.exists() and joblib is not None:
            self.transformer = joblib.load(preprocessor_path)

    def transform(self, rows: list[dict[str, float]]) -> np.ndarray:
        frame = pd.DataFrame(rows)
        frame = frame.reindex(columns=self.feature_order, fill_value=0.0)
        frame = frame.apply(pd.to_numeric, errors='coerce').fillna(0.0)
        if self.transformer is None:
            return frame.to_numpy(dtype=np.float32, copy=False)
        transformed = self.transformer.transform(frame)
        return np.asarray(transformed, dtype=np.float32)


class MLEngine:
    def __init__(self, model_path: Path, feature_order: list[str], preprocessor_path: Path | None = None) -> None:
        if tf is None:
            raise RuntimeError(
                'TensorFlow is not installed in this runtime. Install tensorflow>=2.15 on the IDS host before using the ML stage.'
            ) from TF_IMPORT_ERROR
        self.model = tf.keras.models.load_model(model_path)
        self.preprocessor = Preprocessor(feature_order, preprocessor_path)

    def predict_batch(self, rows: list[dict[str, float]]) -> tuple[np.ndarray, np.ndarray]:
        matrix = self.preprocessor.transform(rows)
        probabilities = self.model.predict(matrix, verbose=0)
        labels = np.argmax(probabilities, axis=1)
        scores = np.max(probabilities, axis=1)
        return labels, scores


class FlowShard(threading.Thread):
    _ioc_lock = threading.Lock()

    def __init__(
        self,
        shard_id: int,
        packet_queue: queue.Queue[PacketEvent],
        inference_queue: queue.Queue[InferenceItem],
        ioc_store: IOCStore,
        stop_event: threading.Event,
    ) -> None:
        super().__init__(name=f'flow-shard-{shard_id}', daemon=True)
        self.shard_id = shard_id
        self.packet_queue = packet_queue
        self.inference_queue = inference_queue
        self.ioc_store = ioc_store
        self.stop_event = stop_event
        self.flows: dict[FlowKey, FlowState] = {}
        self.alert_json_path = ALERT_JSON_PATH
        self.alert_log_path = ALERT_LOG_PATH

    def run(self) -> None:
        while not self.stop_event.is_set():
            try:
                packet = self.packet_queue.get(timeout=0.5)
            except queue.Empty:
                self.flush_expired()
                continue
            self.handle_packet(packet)
            self.flush_expired(reference_time=packet.timestamp)
            self.packet_queue.task_done()

    def handle_packet(self, packet: PacketEvent) -> None:
        ioc_decision = self.ioc_store.decide(
            packet.src_ip,
            packet.dst_ip,
            packet.dst_port,
            whitelist_shortcircuit=ENABLE_WHITELIST_SHORTCIRCUIT,
        )
        if ioc_decision is not None:
            self._log_ioc(packet, ioc_decision)
            return

        flow_key, is_forward = canonicalize_packet(packet)
        flow = self.flows.get(flow_key)
        if flow is None:
            flow = FlowState(flow_key, packet, is_forward, ACTIVITY_GAP_SEC, ACTIVITY_GAP_SEC)
            self.flows[flow_key] = flow
            return
        flow.update(packet, is_forward=is_forward)
        if flow.packet_count >= 4:
            self.emit_flow(flow_key)

    def flush_expired(self, reference_time: float | None = None) -> None:
        now = time.time() if reference_time is None else reference_time
        expired = [
            flow_key
            for flow_key, flow in self.flows.items()
            if (now - flow.last_seen_ts) >= FLOW_IDLE_TIMEOUT_SEC or (now - flow.start_ts) >= ACTIVE_TIMEOUT_SEC
        ]
        for flow_key in expired:
            self.emit_flow(flow_key)

    def emit_flow(self, flow_key: FlowKey) -> None:
        flow = self.flows.pop(flow_key, None)
        if flow is None:
            return
        features = flow.to_feature_dict()
        self.inference_queue.put(InferenceItem(flow_key=flow_key, features=features, initiator_ip=flow.initiator_ip))

    def _log_ioc(self, packet: PacketEvent, decision: IOCDecision) -> None:
        line = (
            f'[IOC] verdict={decision.verdict} reason={decision.reason} matched={decision.matched_value} '
            f'src={packet.src_ip}:{packet.src_port} dst={packet.dst_ip}:{packet.dst_port}'
        )
        print(line)
        if decision.verdict == 'BLOCK':
            timestamp = datetime.utcnow().isoformat(timespec='seconds') + 'Z'
            record = {
                'timestamp': timestamp,
                'event_type': 'BLOCK',
                'verdict': 'BLOCK',
                'label': 'IOC',
                'confidence': 1.0,
                'reason': decision.reason,
                'src_ip': packet.src_ip,
                'src_port': packet.src_port,
                'dst_ip': packet.dst_ip,
                'dst_port': packet.dst_port,
                'protocol': packet.protocol,
                'action_ip': str(decision.matched_value),
                'ml_triggered_block': False,
            }
            self.alert_json_path.parent.mkdir(parents=True, exist_ok=True)
            self.alert_log_path.parent.mkdir(parents=True, exist_ok=True)
            with FlowShard._ioc_lock:
                with self.alert_json_path.open('a', encoding='utf-8') as f:
                    f.write(json.dumps(record) + '\n')
                with self.alert_log_path.open('a', encoding='utf-8') as f:
                    f.write(f'{timestamp} {line}\n')


class InferenceWorker(threading.Thread):
    def __init__(
        self,
        inference_queue: queue.Queue[InferenceItem],
        stop_event: threading.Event,
        feature_order: list[str],
        ioc_store: IOCStore,
    ) -> None:
        super().__init__(name='ml-inference', daemon=True)
        self.inference_queue = inference_queue
        self.stop_event = stop_event
        self.ioc_store = ioc_store
        self.ml_engine = MLEngine(MODEL_PATH, feature_order, PREPROCESSOR_PATH)
        self.alert_log_path = ALERT_LOG_PATH
        self.alert_json_path = ALERT_JSON_PATH
        self._alert_lock = threading.Lock()

    def run(self) -> None:
        while not self.stop_event.is_set():
            batch = self._collect_batch()
            if not batch:
                continue
            flow_keys = [item.flow_key for item in batch]
            feature_rows = [item.features for item in batch]
            initiator_ips = [item.initiator_ip for item in batch]
            labels, scores = self.ml_engine.predict_batch(feature_rows)
            for flow_key, features, initiator_ip, label_idx, score in zip(flow_keys, feature_rows, initiator_ips, labels, scores, strict=True):
                label = LABEL_MAP.get(int(label_idx), f'UNKNOWN_{int(label_idx)}')
                verdict = 'ALLOW'
                reason = 'benign_or_low_confidence'
                action_ip = None
                if label != 'BENIGN' and float(score) >= MODEL_CONFIDENCE_THRESHOLD:
                    verdict = 'BLOCK' if BLOCK_ON_MALICIOUS_ML else 'ALERT'
                    reason = 'ml_detected_malicious_flow'
                    if AUTO_BLACKLIST_ML_DETECTIONS:
                        action_ip = initiator_ip
                        was_added = self.ioc_store.add_to_blacklist(initiator_ip)
                        verdict = 'BLOCK'
                        reason = 'ml_detected_malicious_flow_auto_blacklisted_new' if was_added else 'ml_detected_malicious_flow_ip_already_blacklisted'
                result = ClassifiedFlow(flow_key, features, verdict, label, float(score), reason, action_ip)
                self._emit_result(result)

    def _collect_batch(self) -> list[InferenceItem]:
        batch: list[InferenceItem] = []
        deadline = time.time() + BATCH_WAIT_SEC
        while len(batch) < BATCH_SIZE and not self.stop_event.is_set():
            timeout = max(deadline - time.time(), 0.05)
            try:
                item = self.inference_queue.get(timeout=timeout)
            except queue.Empty:
                break
            batch.append(item)
            self.inference_queue.task_done()
        return batch

    def _emit_result(self, result: ClassifiedFlow) -> None:
        action = f' action_ip={result.action_ip}' if result.action_ip else ''
        line = (
            f'verdict={result.verdict} label={result.label} confidence={result.confidence:.4f} '
            f'flow={result.flow_key.src_ip}:{result.flow_key.src_port}->{result.flow_key.dst_ip}:{result.flow_key.dst_port}/'
            f'{result.flow_key.protocol} reason={result.reason}{action}'
        )
        if result.verdict == 'BLOCK':
            print(f'[BLOCK][ML] *** BLOCKED *** {line}')
            self._write_alert_log(f'[BLOCK][ML] {line}')
            self._write_alert_json(result, 'BLOCK')
        elif result.verdict == 'ALERT':
            print(f'[ALERT][ML] {line}')
            self._write_alert_log(f'[ALERT][ML] {line}')
            self._write_alert_json(result, 'ALERT')
        else:
            print(f'[ML] {line}')

    def _write_alert_log(self, line: str) -> None:
        timestamp = datetime.utcnow().isoformat(timespec='seconds') + 'Z'
        self.alert_log_path.parent.mkdir(parents=True, exist_ok=True)
        with self._alert_lock:
            with self.alert_log_path.open('a', encoding='utf-8') as handle:
                handle.write(f'{timestamp} {line}\n')

    def _write_alert_json(self, result: ClassifiedFlow, event_type: str) -> None:
        timestamp = datetime.utcnow().isoformat(timespec='seconds') + 'Z'
        record = {
            'timestamp': timestamp,
            'event_type': event_type,
            'verdict': result.verdict,
            'label': result.label,
            'confidence': round(result.confidence, 6),
            'reason': result.reason,
            'src_ip': result.flow_key.src_ip,
            'src_port': result.flow_key.src_port,
            'dst_ip': result.flow_key.dst_ip,
            'dst_port': result.flow_key.dst_port,
            'protocol': result.flow_key.protocol,
            'action_ip': result.action_ip,
            'ml_triggered_block': result.verdict == 'BLOCK' and 'ml_detected' in result.reason,
        }
        self.alert_json_path.parent.mkdir(parents=True, exist_ok=True)
        with self._alert_lock:
            with self.alert_json_path.open('a', encoding='utf-8') as handle:
                handle.write(json.dumps(record) + '\n')
                

def load_feature_order(train_csv_path: Path) -> list[str]:
    header = pd.read_csv(train_csv_path, nrows=0)
    columns = header.columns.tolist()
    if not columns or columns[-1] != 'Classification':
        raise ValueError('Expected the last column in the CICIDS training CSV to be Classification.')
    return columns[:-1]
