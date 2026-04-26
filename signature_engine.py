from __future__ import annotations

import csv
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import pandas as pd


def _read_single_column_csv(path: Path) -> set[str]:
    if not path.exists():
        return set()
    df = pd.read_csv(path)
    if df.empty:
        return set()
    series = df.iloc[:, 0].dropna().astype(str).str.strip()
    return {value for value in series.tolist() if value}


def _read_port_csv(path: Path) -> set[int]:
    if not path.exists():
        return set()
    df = pd.read_csv(path)
    if df.empty:
        return set()
    series = pd.to_numeric(df.iloc[:, 0], errors="coerce").dropna().astype(int)
    return set(series.tolist())


@dataclass(slots=True)
class IOCDecision:
    verdict: str
    reason: str
    matched_value: str | int | None = None


class IOCStore:
    def __init__(
        self,
        blacklist_path: Path,
        whitelist_path: Path,
        blacklisted_ports_path: Path,
        *,
        flush_batch_size: int = 100,
        flush_interval_sec: float = 2.0,
    ) -> None:
        self.blacklist_path = blacklist_path
        self.whitelist_path = whitelist_path
        self.blacklisted_ports_path = blacklisted_ports_path
        self.flush_batch_size = max(int(flush_batch_size), 1)
        self.flush_interval_sec = max(float(flush_interval_sec), 0.2)
        self.blacklist: set[str] = set()
        self.whitelist: set[str] = set()
        self.blacklisted_ports: set[int] = set()
        self._pending_blacklist: set[str] = set()
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self.reload()
        self._writer_thread = threading.Thread(target=self._flush_loop, name='ioc-blacklist-writer', daemon=True)
        self._writer_thread.start()

    def reload(self) -> None:
        with self._lock:
            self.blacklist = _read_single_column_csv(self.blacklist_path)
            self.whitelist = _read_single_column_csv(self.whitelist_path)
            self.blacklisted_ports = _read_port_csv(self.blacklisted_ports_path)

    def stop(self) -> None:
        self._stop_event.set()
        if self._writer_thread.is_alive():
            self._writer_thread.join(timeout=self.flush_interval_sec + 1.0)
        self.flush_blacklist(force=True)

    def add_to_blacklist(self, value: str) -> bool:
        value = value.strip()
        if not value:
            return False
        with self._lock:
            if value in self.blacklist:
                return False
            self.blacklist.add(value)
            self._pending_blacklist.add(value)
            pending_count = len(self._pending_blacklist)
        if pending_count >= self.flush_batch_size:
            self.flush_blacklist()
        return True

    def add_to_whitelist(self, value: str) -> None:
        value = value.strip()
        if not value:
            return
        with self._lock:
            if value in self.whitelist:
                return
            self.whitelist.add(value)
            values = sorted(self.whitelist)
        self._persist_full(self.whitelist_path, values)

    def decide(self, src_ip: str, dst_ip: str, dst_port: int | None, whitelist_shortcircuit: bool = True) -> IOCDecision | None:
        with self._lock:
            if whitelist_shortcircuit and (src_ip in self.whitelist or dst_ip in self.whitelist):
                matched = src_ip if src_ip in self.whitelist else dst_ip
                return IOCDecision('ALLOW', 'endpoint_in_whitelist', matched)

            if src_ip in self.blacklist:
                return IOCDecision('BLOCK', 'src_ip_in_blacklist', src_ip)
            if dst_ip in self.blacklist:
                return IOCDecision('BLOCK', 'dst_ip_in_blacklist', dst_ip)
            if dst_port is not None and dst_port in self.blacklisted_ports:
                return IOCDecision('BLOCK', 'dst_port_in_blacklisted_ports', dst_port)
        return None

    def flush_blacklist(self, force: bool = False) -> None:
        with self._lock:
            if not self._pending_blacklist:
                return
            if not force and len(self._pending_blacklist) < self.flush_batch_size:
                return
            pending = sorted(self._pending_blacklist)
            self._pending_blacklist.clear()
        self._append_values(self.blacklist_path, pending)

    def _flush_loop(self) -> None:
        while not self._stop_event.wait(self.flush_interval_sec):
            self.flush_blacklist(force=True)

    @staticmethod
    def _persist_full(path: Path, values: list[str]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('w', newline='') as handle:
            writer = csv.writer(handle)
            writer.writerow(['value'])
            for value in values:
                writer.writerow([value])

    @staticmethod
    def _append_values(path: Path, values: list[str]) -> None:
        if not values:
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        needs_header = not path.exists() or path.stat().st_size == 0
        with path.open('a', newline='') as handle:
            writer = csv.writer(handle)
            if needs_header:
                writer.writerow(['value'])
            for value in values:
                writer.writerow([value])
