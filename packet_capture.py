from __future__ import annotations

import subprocess
from collections.abc import Iterator

from config import TSHARK_FIELDS, TSHARK_PATH
from protocol_module import PacketEvent


FIELD_SEPARATOR = "\t"


def build_tshark_command(interface: str) -> list[str]:
    cmd = [
        TSHARK_PATH,
        "-l",
        "-n",
        "-i",
        interface,
        "-T",
        "fields",
    ]

    for field in TSHARK_FIELDS:
        cmd.extend(["-e", field])

    cmd.extend([
        "-E", f"separator={FIELD_SEPARATOR}",
        "-E", "header=n",
        "-E", "occurrence=f",
        "-f", "ip",
    ])

    return cmd


def stream_packets(interface: str) -> Iterator[PacketEvent]:
    process = subprocess.Popen(
        build_tshark_command(interface),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    try:
        assert process.stdout is not None

        for line in process.stdout:
            packet = parse_tshark_line(line.rstrip("\n"))
            if packet is not None:
                yield packet

    finally:
        try:
            process.terminate()
            process.wait(timeout=3)
        except Exception:
            process.kill()


def parse_tshark_line(line: str) -> PacketEvent | None:
    if not line:
        return None

    parts = line.split(FIELD_SEPARATOR)

    # Azure/Linux tshark may return fewer fields for some packets.
    # Instead of dropping the packet, fill missing values with empty strings.
    if len(parts) < len(TSHARK_FIELDS):
        parts += [""] * (len(TSHARK_FIELDS) - len(parts))

    # If tshark returns extra fields, ignore extras.
    if len(parts) > len(TSHARK_FIELDS):
        parts = parts[:len(TSHARK_FIELDS)]

    values = dict(zip(TSHARK_FIELDS, parts))

    src_ip = values.get("ip.src", "")
    dst_ip = values.get("ip.dst", "")

    if not src_ip or not dst_ip:
        return None

    protocol = _to_int(values.get("ip.proto", ""))

    tcp_src = _to_int(values.get("tcp.srcport", ""))
    tcp_dst = _to_int(values.get("tcp.dstport", ""))
    udp_src = _to_int(values.get("udp.srcport", ""))
    udp_dst = _to_int(values.get("udp.dstport", ""))

    src_port = tcp_src or udp_src
    dst_port = tcp_dst or udp_dst

    ip_header_length = _to_int(values.get("ip.hdr_len", ""))
    tcp_header_length = _to_int(values.get("tcp.hdr_len", ""))
    udp_length = _to_int(values.get("udp.length", ""))

    udp_header_length = 8 if udp_length else 0
    transport_header_length = tcp_header_length or udp_header_length
    header_length = ip_header_length + transport_header_length

    payload_length = _to_int(values.get("tcp.len", ""))

    if payload_length == 0 and udp_length > 0:
        payload_length = max(udp_length - 8, 0)

    return PacketEvent(
        timestamp=_to_float(values.get("frame.time_epoch", "")),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        packet_length=_to_int(values.get("ip.len", "")),
        payload_length=payload_length,
        header_length=header_length,
        tcp_window_size=_to_int(values.get("tcp.window_size_value", "")),
        fin=_to_int(values.get("tcp.flags.fin", "")),
        rst=_to_int(values.get("tcp.flags.reset", "")),
        psh=_to_int(values.get("tcp.flags.push", "")),
        ack=_to_int(values.get("tcp.flags.ack", "")),
        urg=_to_int(values.get("tcp.flags.urg", "")),
        cwr=_to_int(values.get("tcp.flags.cwr", "")),
        ece=_to_int(values.get("tcp.flags.ece", "")),
    )


def _to_int(value: str) -> int:
    try:
        return int(float(value)) if value else 0
    except ValueError:
        return 0


def _to_float(value: str) -> float:
    try:
        return float(value) if value else 0.0
    except ValueError:
        return 0.0
