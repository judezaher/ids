from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from math import sqrt
from typing import Any

import numpy as np


@dataclass(slots=True, frozen=True)
class FlowKey:
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: int


@dataclass(slots=True)
class PacketEvent:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    packet_length: int
    payload_length: int
    header_length: int
    tcp_window_size: int
    fin: int = 0
    rst: int = 0
    psh: int = 0
    ack: int = 0
    urg: int = 0
    cwr: int = 0
    ece: int = 0


class BulkTracker:
    def __init__(self, gap_sec: float) -> None:
        self.gap_sec = gap_sec
        self.current_bytes = 0
        self.current_packets = 0
        self.current_start: float | None = None
        self.last_ts: float | None = None
        self.bulk_bytes: list[int] = []
        self.bulk_packets: list[int] = []
        self.bulk_rates: list[float] = []

    def update(self, ts: float, payload_length: int) -> None:
        if payload_length <= 0:
            return
        if self.current_start is None:
            self.current_start = ts
            self.last_ts = ts
            self.current_bytes = payload_length
            self.current_packets = 1
            return
        if self.last_ts is not None and (ts - self.last_ts) <= self.gap_sec:
            self.current_bytes += payload_length
            self.current_packets += 1
            self.last_ts = ts
            return
        self._finalize_group()
        self.current_start = ts
        self.last_ts = ts
        self.current_bytes = payload_length
        self.current_packets = 1

    def close(self) -> None:
        self._finalize_group()

    def _finalize_group(self) -> None:
        if self.current_start is None or self.last_ts is None:
            return
        if self.current_packets >= 4:
            duration = max(self.last_ts - self.current_start, 1e-9)
            self.bulk_bytes.append(self.current_bytes)
            self.bulk_packets.append(self.current_packets)
            self.bulk_rates.append(self.current_bytes / duration)
        self.current_bytes = 0
        self.current_packets = 0
        self.current_start = None
        self.last_ts = None

    @property
    def bytes_avg(self) -> float:
        return float(np.mean(self.bulk_bytes)) if self.bulk_bytes else 0.0

    @property
    def packets_avg(self) -> float:
        return float(np.mean(self.bulk_packets)) if self.bulk_packets else 0.0

    @property
    def rate_avg(self) -> float:
        return float(np.mean(self.bulk_rates)) if self.bulk_rates else 0.0


@dataclass(slots=True)
class DirectionStats:
    packet_lengths: list[int] = field(default_factory=list)
    iats: list[float] = field(default_factory=list)
    total_bytes: int = 0
    total_payload_bytes: int = 0
    total_header_bytes: int = 0
    packets_with_data: int = 0
    psh_flags: int = 0
    urg_flags: int = 0
    init_window_bytes: int | None = None
    last_ts: float | None = None
    bulk: BulkTracker | None = None

    def attach_bulk(self, gap_sec: float) -> None:
        if self.bulk is None:
            self.bulk = BulkTracker(gap_sec)

    def update(self, packet: PacketEvent) -> None:
        self.packet_lengths.append(packet.packet_length)
        self.total_bytes += packet.packet_length
        self.total_payload_bytes += packet.payload_length
        self.total_header_bytes += packet.header_length
        if packet.payload_length > 0:
            self.packets_with_data += 1
        self.psh_flags += int(packet.psh > 0)
        self.urg_flags += int(packet.urg > 0)
        if self.init_window_bytes is None and packet.tcp_window_size > 0:
            self.init_window_bytes = packet.tcp_window_size
        if self.last_ts is not None:
            self.iats.append(max(packet.timestamp - self.last_ts, 0.0))
        self.last_ts = packet.timestamp
        if self.bulk is not None:
            self.bulk.update(packet.timestamp, packet.payload_length)


class FlowState:
    def __init__(self, flow_key: FlowKey, first_packet: PacketEvent, first_packet_is_forward: bool, activity_gap_sec: float, bulk_gap_sec: float) -> None:
        self.flow_key = flow_key
        self.start_ts = first_packet.timestamp
        self.last_seen_ts = first_packet.timestamp
        self.activity_gap_sec = activity_gap_sec
        self.initiator_ip = first_packet.src_ip
        self.initiator_port = first_packet.src_port
        self.responder_ip = first_packet.dst_ip
        self.responder_port = first_packet.dst_port
        self.segment_start_ts = first_packet.timestamp
        self.active_periods: list[float] = []
        self.idle_periods: list[float] = []
        self.forward = DirectionStats()
        self.backward = DirectionStats()
        self.forward.attach_bulk(bulk_gap_sec)
        self.backward.attach_bulk(bulk_gap_sec)
        self.packet_lengths: list[int] = []
        self.flow_iats: list[float] = []
        self.fin_count = 0
        self.rst_count = 0
        self.psh_count = 0
        self.ack_count = 0
        self.urg_count = 0
        self.cwr_count = 0
        self.ece_count = 0
        self._update_direction(first_packet, is_forward=first_packet_is_forward)

    @property
    def packet_count(self) -> int:
        return len(self.packet_lengths)

    def update(self, packet: PacketEvent, is_forward: bool) -> None:
        gap = max(packet.timestamp - self.last_seen_ts, 0.0)
        if gap > 0:
            self.flow_iats.append(gap)
        if gap > self.activity_gap_sec:
            self.active_periods.append(max(self.last_seen_ts - self.segment_start_ts, 0.0))
            self.idle_periods.append(gap)
            self.segment_start_ts = packet.timestamp
        self.last_seen_ts = packet.timestamp
        self._update_direction(packet, is_forward=is_forward)

    def close(self) -> None:
        self.forward.bulk.close()
        self.backward.bulk.close()
        self.active_periods.append(max(self.last_seen_ts - self.segment_start_ts, 0.0))

    def _update_direction(self, packet: PacketEvent, is_forward: bool) -> None:
        self.packet_lengths.append(packet.packet_length)
        self.fin_count += int(packet.fin > 0)
        self.rst_count += int(packet.rst > 0)
        self.psh_count += int(packet.psh > 0)
        self.ack_count += int(packet.ack > 0)
        self.urg_count += int(packet.urg > 0)
        self.cwr_count += int(packet.cwr > 0)
        self.ece_count += int(packet.ece > 0)
        if is_forward:
            self.forward.update(packet)
        else:
            self.backward.update(packet)

    def to_feature_dict(self) -> dict[str, float]:
        self.close()
        duration = max(self.last_seen_ts - self.start_ts, 1e-9)
        forward_count = len(self.forward.packet_lengths)
        backward_count = len(self.backward.packet_lengths)
        total_packets = forward_count + backward_count
        total_bytes = self.forward.total_bytes + self.backward.total_bytes

        features = {
            'Dst Port': float(self.flow_key.dst_port),
            'Protocol': float(self.flow_key.protocol),
            'Flow Duration': duration,
            'Total Bwd packets': float(backward_count),
            'Total Length of Fwd Packet': float(self.forward.total_bytes),
            'Total Length of Bwd Packet': float(self.backward.total_bytes),
            'Fwd Packet Length Max': _safe_max(self.forward.packet_lengths),
            'Fwd Packet Length Min': _safe_min(self.forward.packet_lengths),
            'Fwd Packet Length Mean': _safe_mean(self.forward.packet_lengths),
            'Fwd Packet Length Std': _safe_std(self.forward.packet_lengths),
            'Bwd Packet Length Max': _safe_max(self.backward.packet_lengths),
            'Bwd Packet Length Min': _safe_min(self.backward.packet_lengths),
            'Bwd Packet Length Std': _safe_std(self.backward.packet_lengths),
            'Flow_Bytes': total_bytes / duration,
            'Flow_Packets': total_packets / duration,
            'Flow IAT Mean': _safe_mean(self.flow_iats),
            'Flow IAT Std': _safe_std(self.flow_iats),
            'Flow IAT Max': _safe_max(self.flow_iats),
            'Flow IAT Min': _safe_min(self.flow_iats),
            'Fwd IAT Total': float(sum(self.forward.iats)),
            'Fwd IAT Mean': _safe_mean(self.forward.iats),
            'Fwd IAT Std': _safe_std(self.forward.iats),
            'Fwd IAT Max': _safe_max(self.forward.iats),
            'Fwd IAT Min': _safe_min(self.forward.iats),
            'Bwd IAT Total': float(sum(self.backward.iats)),
            'Bwd IAT Mean': _safe_mean(self.backward.iats),
            'Bwd IAT Std': _safe_std(self.backward.iats),
            'Bwd IAT Max': _safe_max(self.backward.iats),
            'Bwd IAT Min': _safe_min(self.backward.iats),
            'Fwd PSH Flags': float(self.forward.psh_flags),
            'Bwd PSH Flags': float(self.backward.psh_flags),
            'Fwd URG Flags': float(self.forward.urg_flags),
            'Bwd URG Flags': float(self.backward.urg_flags),
            'Bwd Header Length': float(self.backward.total_header_bytes),
            'Fwd_Packets': forward_count / duration,
            'Bwd Packets/s': backward_count / duration,
            'Packet Length Min': _safe_min(self.packet_lengths),
            'Packet Length Max': _safe_max(self.packet_lengths),
            'Packet Length Mean': _safe_mean(self.packet_lengths),
            'Packet Length Std': _safe_std(self.packet_lengths),
            'Packet Length Variance': _safe_var(self.packet_lengths),
            'FIN Flag Count': float(self.fin_count),
            'RST Flag Count': float(self.rst_count),
            'PSH Flag Count': float(self.psh_count),
            'ACK Flag Count': float(self.ack_count),
            'URG Flag Count': float(self.urg_count),
            'CWR Flag Count': float(self.cwr_count),
            'ECE Flag Count': float(self.ece_count),
            'Down/Up Ratio': float(backward_count) / max(float(forward_count), 1.0),
            'Average Packet Size': _safe_mean(self.packet_lengths),
            'Fwd Segment Size Avg': _safe_mean(self.forward.packet_lengths),
            'Bwd Segment Size Avg': _safe_mean(self.backward.packet_lengths),
            'Fwd Bytes/Bulk Avg': self.forward.bulk.bytes_avg if self.forward.bulk else 0.0,
            'Fwd Packet/Bulk Avg': self.forward.bulk.packets_avg if self.forward.bulk else 0.0,
            'Fwd Bulk Rate Avg': self.forward.bulk.rate_avg if self.forward.bulk else 0.0,
            'Bwd Bytes/Bulk Avg': self.backward.bulk.bytes_avg if self.backward.bulk else 0.0,
            'Bwd Packet/Bulk Avg': self.backward.bulk.packets_avg if self.backward.bulk else 0.0,
            'Bwd Bulk Rate Avg': self.backward.bulk.rate_avg if self.backward.bulk else 0.0,
            'Subflow Fwd Packets': float(forward_count),
            'Subflow Fwd Bytes': float(self.forward.total_bytes),
            'Subflow Bwd Packets': float(backward_count),
            'Subflow Bwd Bytes': float(self.backward.total_bytes),
            'Bwd Init Win Bytes': float(self.backward.init_window_bytes or 0),
            'Fwd Act Data Pkts': float(self.forward.packets_with_data),
            'Active Mean': _safe_mean(self.active_periods),
            'Active Std': _safe_std(self.active_periods),
            'Active Max': _safe_max(self.active_periods),
            'Active Min': _safe_min(self.active_periods),
            'Idle Mean': _safe_mean(self.idle_periods),
            'Idle Std': _safe_std(self.idle_periods),
            'Idle Max': _safe_max(self.idle_periods),
            'Idle Min': _safe_min(self.idle_periods),
        }
        return features


def canonicalize_packet(packet: PacketEvent) -> tuple[FlowKey, bool]:
    forward_key = FlowKey(packet.src_ip, packet.src_port, packet.dst_ip, packet.dst_port, packet.protocol)
    reverse_key = FlowKey(packet.dst_ip, packet.dst_port, packet.src_ip, packet.src_port, packet.protocol)
    if _flow_tuple(forward_key) <= _flow_tuple(reverse_key):
        return forward_key, True
    return reverse_key, False


def _flow_tuple(key: FlowKey) -> tuple[Any, ...]:
    return key.src_ip, key.src_port, key.dst_ip, key.dst_port, key.protocol


def _safe_mean(values: list[float] | list[int]) -> float:
    return float(np.mean(values)) if values else 0.0


def _safe_std(values: list[float] | list[int]) -> float:
    return float(np.std(values)) if values else 0.0


def _safe_var(values: list[float] | list[int]) -> float:
    return float(np.var(values)) if values else 0.0


def _safe_min(values: list[float] | list[int]) -> float:
    return float(np.min(values)) if values else 0.0


def _safe_max(values: list[float] | list[int]) -> float:
    return float(np.max(values)) if values else 0.0
