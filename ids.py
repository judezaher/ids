from __future__ import annotations

import queue
import threading

from config import (
    BLACKLIST_FLUSH_BATCH_SIZE,
    BLACKLIST_FLUSH_INTERVAL_SEC,
    BLACKLIST_PATH,
    BLACKLISTED_PORTS_PATH,
    INTERFACES,
    SHARD_COUNT,
    TRAIN_HEADER_SOURCE,
    WHITELIST_PATH,
)
from decision_engine import FlowShard, InferenceWorker, load_feature_order
from packet_capture import stream_packets
from protocol_module import PacketEvent
from signature_engine import IOCStore


def shard_index(packet: PacketEvent) -> int:
    return hash((packet.src_ip, packet.src_port, packet.dst_ip, packet.dst_port, packet.protocol)) % SHARD_COUNT


def capture_loop(interface: str, shard_queues: list[queue.Queue[PacketEvent]], stop_event: threading.Event) -> None:
    for packet in stream_packets(interface):
        if stop_event.is_set():
            break
        shard_queues[shard_index(packet)].put(packet)


def main() -> None:
    stop_event = threading.Event()
    ioc_store = IOCStore(
        BLACKLIST_PATH,
        WHITELIST_PATH,
        BLACKLISTED_PORTS_PATH,
        flush_batch_size=BLACKLIST_FLUSH_BATCH_SIZE,
        flush_interval_sec=BLACKLIST_FLUSH_INTERVAL_SEC,
    )
    feature_order = load_feature_order(TRAIN_HEADER_SOURCE)

    shard_queues = [queue.Queue(maxsize=5000) for _ in range(SHARD_COUNT)]
    inference_queue: queue.Queue = queue.Queue(maxsize=5000)

    flow_shards = [
        FlowShard(i, shard_queues[i], inference_queue, ioc_store, stop_event)
        for i in range(SHARD_COUNT)
    ]
    for shard in flow_shards:
        shard.start()

    inference_worker = InferenceWorker(inference_queue, stop_event, feature_order, ioc_store)
    inference_worker.start()

    capture_threads = [
        threading.Thread(target=capture_loop, args=(interface, shard_queues, stop_event), daemon=True, name=f'capture-{interface}')
        for interface in INTERFACES
    ]
    for thread in capture_threads:
        thread.start()

    try:
        for thread in capture_threads:
            thread.join()
    except KeyboardInterrupt:
        print('\nStopping IDS...')
    finally:
        stop_event.set()
        for q in shard_queues:
            q.join()
        inference_queue.join()
        ioc_store.stop()


if __name__ == '__main__':
    main()
