import os
import select
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from scapy.all import Ether, IP, Raw, TCP, UDP, rdpcap


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "mininet"))

from topology import HOSTS, P4NatNetwork


class PacketCapture:
    def __init__(self, host, interface, output, capture_filter):
        self.host = host
        self.interface = interface
        self.output = output
        self.capture_filter = capture_filter
        self.process = None

    def start(self):
        self.process = self.host.popen(
            [
                "tcpdump",
                "--immediate-mode",
                "-U",
                "-n",
                "-i",
                self.interface,
                "-w",
                str(self.output),
                self.capture_filter,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        deadline = time.monotonic() + 3.0
        diagnostic = []
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                break
            readable, _, _ = select.select([self.process.stderr], [], [], 0.1)
            if not readable:
                continue
            line = self.process.stderr.readline().decode("utf-8", errors="replace")
            diagnostic.append(line)
            if "listening on" in line:
                return
        self.stop()
        detail = "".join(diagnostic).strip()
        raise RuntimeError(f"tcpdump did not become ready on {self.interface}: {detail}")

    def stop(self):
        if self.process is None:
            return
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGINT)
            try:
                self.process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=1.0)
        if self.process.stderr is not None:
            self.process.stderr.close()
        self.process = None

    def packets(self):
        return list(rdpcap(str(self.output)))


def internet_checksum(data):
    if len(data) % 2:
        data += b"\x00"
    words = sum(
        (data[index] << 8) | data[index + 1]
        for index in range(0, len(data), 2)
    )
    while words >> 16:
        words = (words & 0xFFFF) + (words >> 16)
    return (~words) & 0xFFFF


def udp_checksum_valid(packet):
    if not packet.haslayer(IP) or not packet.haslayer(UDP):
        return False
    raw_ip = bytes(packet[IP])
    if len(raw_ip) < 20 or raw_ip[0] >> 4 != 4:
        return False
    header_length = (raw_ip[0] & 0x0F) * 4
    total_length = struct.unpack("!H", raw_ip[2:4])[0]
    if (
        header_length < 20
        or total_length < header_length + 8
        or total_length > len(raw_ip)
        or raw_ip[9] != socket.IPPROTO_UDP
    ):
        return False
    udp_length = struct.unpack("!H", raw_ip[header_length + 4 : header_length + 6])[0]
    if (
        udp_length < 8
        or udp_length != total_length - header_length
        or packet[UDP].len != udp_length
    ):
        return False
    udp = raw_ip[header_length : header_length + udp_length]
    checksum = struct.unpack("!H", udp[6:8])[0]
    pseudo_header = raw_ip[12:20] + struct.pack(
        "!BBH", 0, socket.IPPROTO_UDP, udp_length
    )
    return checksum != 0 and internet_checksum(pseudo_header + udp) == 0


def udp_payload_for_checksum_result_zero(src_ip, dst_ip, sport, dport, prefix):
    """Append a word that makes the UDP checksum calculation return zero."""
    if len(prefix) % 2:
        raise ValueError("UDP checksum correction prefix must have even length")
    udp_length = 8 + len(prefix) + 2
    pseudo_header = (
        socket.inet_aton(src_ip)
        + socket.inet_aton(dst_ip)
        + struct.pack("!BBH", 0, socket.IPPROTO_UDP, udp_length)
    )
    udp_header = struct.pack("!HHHH", sport, dport, udp_length, 0)
    correction = internet_checksum(pseudo_header + udp_header + prefix + b"\x00\x00")
    payload = prefix + struct.pack("!H", correction)
    if internet_checksum(pseudo_header + udp_header + payload) != 0:
        raise AssertionError("failed to construct UDP checksum correction")
    return payload


def tcp_checksum_valid(packet):
    tcp = bytes(packet[TCP])
    pseudo_header = (
        socket.inet_aton(packet[IP].src)
        + socket.inet_aton(packet[IP].dst)
        + struct.pack("!BBH", 0, packet[IP].proto, len(tcp))
    )
    return internet_checksum(pseudo_header + tcp) == 0


def send_udp(
    host,
    interface,
    src_mac,
    dst_mac,
    src_ip,
    dst_ip,
    sport,
    dport,
    token,
    ip_id,
    zero_checksum=False,
    ip_flags=0,
):
    script = """
import sys
from scapy.all import Ether, IP, Raw, UDP, sendp

packet = (
    Ether(src=sys.argv[2], dst=sys.argv[3])
    / IP(
        src=sys.argv[4],
        dst=sys.argv[5],
        ttl=64,
        id=int(sys.argv[8]),
        flags=int(sys.argv[11]),
    )
    / UDP(sport=int(sys.argv[6]), dport=int(sys.argv[7]))
    / Raw(bytes.fromhex(sys.argv[9]))
)
if sys.argv[10] == "1":
    packet[UDP].chksum = 0
sendp(packet, iface=sys.argv[1], count=1, verbose=False)
"""
    process = host.popen(
        [
            sys.executable,
            "-c",
            script,
            interface,
            src_mac,
            dst_mac,
            src_ip,
            dst_ip,
            str(sport),
            str(dport),
            str(ip_id),
            token.hex(),
            "1" if zero_checksum else "0",
            str(ip_flags),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        _, stderr = process.communicate(timeout=3.0)
    except subprocess.TimeoutExpired as error:
        process.kill()
        process.communicate()
        raise RuntimeError("packet injection timed out") from error
    if process.returncode != 0:
        detail = stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"packet injection failed: {detail}")


def send_tcp(
    host,
    interface,
    src_mac,
    dst_mac,
    src_ip,
    dst_ip,
    sport,
    dport,
    flags,
    sequence,
    acknowledgment,
    token,
    ip_id,
):
    script = """
import sys
from scapy.all import Ether, IP, Raw, TCP, sendp

packet = (
    Ether(src=sys.argv[2], dst=sys.argv[3])
    / IP(src=sys.argv[4], dst=sys.argv[5], ttl=64, id=int(sys.argv[11]))
    / TCP(
        sport=int(sys.argv[6]),
        dport=int(sys.argv[7]),
        flags=int(sys.argv[8]),
        seq=int(sys.argv[9]),
        ack=int(sys.argv[10]),
    )
    / Raw(bytes.fromhex(sys.argv[12]))
)
sendp(packet, iface=sys.argv[1], count=1, verbose=False)
"""
    process = host.popen(
        [
            sys.executable,
            "-c",
            script,
            interface,
            src_mac,
            dst_mac,
            src_ip,
            dst_ip,
            str(sport),
            str(dport),
            str(flags),
            str(sequence),
            str(acknowledgment),
            str(ip_id),
            token.hex(),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        _, stderr = process.communicate(timeout=3.0)
    except subprocess.TimeoutExpired as error:
        process.kill()
        process.communicate()
        raise RuntimeError("packet injection timed out") from error
    if process.returncode != 0:
        detail = stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"packet injection failed: {detail}")


def ipv4_test_frame(source, packet):
    config = HOSTS[source]
    return bytes(
        Ether(src=config["mac"], dst=config["switch_mac"])
        / packet
    )


def send_raw_frame(host, interface, frame):
    script = """
import socket
import sys

frame = bytes.fromhex(sys.argv[2])
with socket.socket(
    socket.AF_PACKET,
    socket.SOCK_RAW,
    socket.htons(0x0003),
) as raw_socket:
    raw_socket.bind((sys.argv[1], 0))
    raw_socket.send(frame)
"""
    process = host.popen(
        [sys.executable, "-c", script, interface, frame.hex()],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        _, stderr = process.communicate(timeout=3.0)
    except subprocess.TimeoutExpired as error:
        process.kill()
        process.communicate()
        raise RuntimeError("raw packet injection timed out") from error
    if process.returncode != 0:
        detail = stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"raw packet injection failed: {detail}")


class PacketIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.geteuid() != 0:
            raise RuntimeError("packet integration tests require root privileges")
        cls.runtime = P4NatNetwork(
            controller=ROOT / "build" / "p4natctl",
            p4info=ROOT / "build" / "nat.p4info.txtpb",
            device_config=ROOT / "build" / "nat.json",
            grpc_port=int(os.environ.get("P4NAT_GRPC_PORT", "9559")),
            thrift_port=int(os.environ.get("P4NAT_THRIFT_PORT", "9090")),
        )
        cls.runtime.start()
        if cls.runtime.controller_output != "configured and verified 13 table entries":
            cls.runtime.close()
            raise AssertionError(
                f"unexpected controller output: {cls.runtime.controller_output!r}"
            )

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "runtime"):
            cls.runtime.close()

    def assert_forwarded(
        self,
        source,
        destination,
        sport,
        dport,
        token,
        ip_id,
        ip_flags=0,
    ):
        source_host = self.runtime.net.get(source)
        destination_host = self.runtime.net.get(destination)
        outside_host = self.runtime.net.get("h3")
        source_config = HOSTS[source]
        destination_config = HOSTS[destination]
        source_ip = source_config["address"].split("/", 1)[0]
        destination_ip = destination_config["address"].split("/", 1)[0]
        capture_filter = (
            f"udp and src host {source_ip} and dst host {destination_ip} "
            f"and src port {sport} and dst port {dport}"
        )

        with tempfile.TemporaryDirectory(prefix="p4-nat-packets-") as directory:
            intended = PacketCapture(
                destination_host,
                destination_host.defaultIntf().name,
                Path(directory) / "intended.pcap",
                capture_filter,
            )
            unintended = PacketCapture(
                outside_host,
                outside_host.defaultIntf().name,
                Path(directory) / "outside.pcap",
                capture_filter,
            )
            try:
                intended.start()
                unintended.start()
                send_udp(
                    source_host,
                    source_host.defaultIntf().name,
                    source_config["mac"],
                    source_config["switch_mac"],
                    source_ip,
                    destination_ip,
                    sport,
                    dport,
                    token,
                    ip_id,
                    ip_flags=ip_flags,
                )
                time.sleep(0.25)
            finally:
                intended.stop()
                unintended.stop()

            intended_packets = intended.packets()
            unintended_packets = unintended.packets()

        self.assertEqual(
            len(intended_packets),
            1,
            f"{source}->{destination}: expected one destination packet, got {len(intended_packets)}",
        )
        self.assertEqual(
            len(unintended_packets),
            0,
            f"{source}->{destination}: observed {len(unintended_packets)} unexpected outside packets",
        )

        packet = intended_packets[0]
        self.assertEqual(packet[Ether].src, destination_config["switch_mac"])
        self.assertEqual(packet[Ether].dst, destination_config["mac"])
        self.assertEqual(packet[IP].src, source_ip)
        self.assertEqual(packet[IP].dst, destination_ip)
        self.assertEqual(packet[IP].ttl, 63)
        self.assertEqual(packet[IP].id, ip_id)
        self.assertEqual(int(packet[IP].flags), ip_flags)
        self.assertEqual(packet[UDP].sport, sport)
        self.assertEqual(packet[UDP].dport, dport)
        self.assertEqual(bytes(packet[Raw].load), token)
        self.assertTrue(
            udp_checksum_valid(packet),
            f"{source}->{destination}: invalid forwarded UDP checksum",
        )

        raw_ip = bytes(packet[IP])
        header_length = (raw_ip[0] & 0x0F) * 4
        self.assertEqual(
            internet_checksum(raw_ip[:header_length]),
            0,
            f"{source}->{destination}: invalid forwarded IPv4 checksum",
        )

    def assert_tcp_translation(
        self,
        source,
        destination,
        unintended,
        input_src_ip,
        input_dst_ip,
        output_src_ip,
        output_dst_ip,
        sport,
        dport,
        flags,
        sequence,
        acknowledgment,
        token,
        ip_id,
    ):
        source_host = self.runtime.net.get(source)
        destination_host = self.runtime.net.get(destination)
        unintended_host = self.runtime.net.get(unintended)
        source_config = HOSTS[source]
        destination_config = HOSTS[destination]
        capture_filter = f"tcp and src port {sport} and dst port {dport}"
        direction = f"{input_src_ip}->{input_dst_ip}"

        with tempfile.TemporaryDirectory(prefix="p4-nat-tcp-") as directory:
            before = PacketCapture(
                source_host,
                source_host.defaultIntf().name,
                Path(directory) / "before.pcap",
                capture_filter,
            )
            after = PacketCapture(
                destination_host,
                destination_host.defaultIntf().name,
                Path(directory) / "after.pcap",
                capture_filter,
            )
            unexpected = PacketCapture(
                unintended_host,
                unintended_host.defaultIntf().name,
                Path(directory) / "unexpected.pcap",
                capture_filter,
            )
            try:
                before.start()
                after.start()
                unexpected.start()
                send_tcp(
                    source_host,
                    source_host.defaultIntf().name,
                    source_config["mac"],
                    source_config["switch_mac"],
                    input_src_ip,
                    input_dst_ip,
                    sport,
                    dport,
                    flags,
                    sequence,
                    acknowledgment,
                    token,
                    ip_id,
                )
                time.sleep(0.25)
            finally:
                before.stop()
                after.stop()
                unexpected.stop()

            before_packets = before.packets()
            after_packets = after.packets()
            unexpected_packets = unexpected.packets()

        self.assertEqual(
            len(before_packets),
            1,
            f"{direction}: expected one input packet, got {len(before_packets)}",
        )
        self.assertEqual(
            len(after_packets),
            1,
            f"{direction}: expected one output packet, got {len(after_packets)}",
        )
        self.assertEqual(
            len(unexpected_packets),
            0,
            f"{direction}: observed {len(unexpected_packets)} packets on {unintended}",
        )

        input_packet = before_packets[0]
        output_packet = after_packets[0]
        self.assertEqual(input_packet[Ether].src, source_config["mac"])
        self.assertEqual(input_packet[Ether].dst, source_config["switch_mac"])
        self.assertEqual(output_packet[Ether].src, destination_config["switch_mac"])
        self.assertEqual(output_packet[Ether].dst, destination_config["mac"])
        self.assertEqual(input_packet[IP].src, input_src_ip)
        self.assertEqual(input_packet[IP].dst, input_dst_ip)
        self.assertEqual(output_packet[IP].src, output_src_ip)
        self.assertEqual(output_packet[IP].dst, output_dst_ip)
        self.assertEqual(input_packet[IP].ttl, 64)
        self.assertEqual(output_packet[IP].ttl, input_packet[IP].ttl - 1)
        self.assertEqual(input_packet[IP].id, ip_id)
        self.assertEqual(output_packet[IP].id, input_packet[IP].id)

        self.assertEqual(input_packet[TCP].sport, sport)
        self.assertEqual(input_packet[TCP].dport, dport)
        self.assertEqual(output_packet[TCP].sport, input_packet[TCP].sport)
        self.assertEqual(output_packet[TCP].dport, input_packet[TCP].dport)
        self.assertEqual(int(input_packet[TCP].flags), flags)
        self.assertEqual(int(output_packet[TCP].flags), int(input_packet[TCP].flags))
        self.assertEqual(input_packet[TCP].seq, sequence)
        self.assertEqual(input_packet[TCP].ack, acknowledgment)
        self.assertEqual(output_packet[TCP].seq, input_packet[TCP].seq)
        self.assertEqual(output_packet[TCP].ack, input_packet[TCP].ack)
        self.assertEqual(bytes(input_packet[Raw].load), token)
        self.assertEqual(bytes(output_packet[Raw].load), bytes(input_packet[Raw].load))

        for label, packet in (("input", input_packet), ("output", output_packet)):
            raw_ip = bytes(packet[IP])
            header_length = (raw_ip[0] & 0x0F) * 4
            self.assertEqual(
                internet_checksum(raw_ip[:header_length]),
                0,
                f"{direction}: invalid {label} IPv4 checksum",
            )
            self.assertTrue(
                tcp_checksum_valid(packet),
                f"{direction}: invalid {label} TCP checksum",
            )

    def assert_udp_translation(
        self,
        source,
        destination,
        unintended,
        input_src_ip,
        input_dst_ip,
        output_src_ip,
        output_dst_ip,
        sport,
        dport,
        token,
        ip_id,
        zero_checksum,
        expected_input_checksum=None,
        expected_output_checksum=None,
    ):
        source_host = self.runtime.net.get(source)
        destination_host = self.runtime.net.get(destination)
        unintended_host = self.runtime.net.get(unintended)
        source_config = HOSTS[source]
        destination_config = HOSTS[destination]
        capture_filter = f"udp and src port {sport} and dst port {dport}"
        direction = f"UDP {input_src_ip}->{input_dst_ip}"

        with tempfile.TemporaryDirectory(prefix="p4-nat-udp-") as directory:
            before = PacketCapture(
                source_host,
                source_host.defaultIntf().name,
                Path(directory) / "before.pcap",
                capture_filter,
            )
            after = PacketCapture(
                destination_host,
                destination_host.defaultIntf().name,
                Path(directory) / "after.pcap",
                capture_filter,
            )
            unexpected = PacketCapture(
                unintended_host,
                unintended_host.defaultIntf().name,
                Path(directory) / "unexpected.pcap",
                capture_filter,
            )
            try:
                before.start()
                after.start()
                unexpected.start()
                send_udp(
                    source_host,
                    source_host.defaultIntf().name,
                    source_config["mac"],
                    source_config["switch_mac"],
                    input_src_ip,
                    input_dst_ip,
                    sport,
                    dport,
                    token,
                    ip_id,
                    zero_checksum=zero_checksum,
                )
                time.sleep(0.25)
            finally:
                before.stop()
                after.stop()
                unexpected.stop()

            before_packets = before.packets()
            after_packets = after.packets()
            unexpected_packets = unexpected.packets()

        self.assertEqual(
            len(before_packets),
            1,
            f"{direction}: expected one input packet, got {len(before_packets)}",
        )
        self.assertEqual(
            len(after_packets),
            1,
            f"{direction}: expected one output packet, got {len(after_packets)}",
        )
        self.assertEqual(
            len(unexpected_packets),
            0,
            f"{direction}: observed {len(unexpected_packets)} packets on {unintended}",
        )

        input_packet = before_packets[0]
        output_packet = after_packets[0]
        self.assertEqual(input_packet[Ether].src, source_config["mac"])
        self.assertEqual(input_packet[Ether].dst, source_config["switch_mac"])
        self.assertEqual(output_packet[Ether].src, destination_config["switch_mac"])
        self.assertEqual(output_packet[Ether].dst, destination_config["mac"])
        self.assertEqual(input_packet[IP].src, input_src_ip)
        self.assertEqual(input_packet[IP].dst, input_dst_ip)
        self.assertEqual(output_packet[IP].src, output_src_ip)
        self.assertEqual(output_packet[IP].dst, output_dst_ip)
        self.assertEqual(input_packet[IP].ttl, 64)
        self.assertEqual(output_packet[IP].ttl, input_packet[IP].ttl - 1)
        self.assertEqual(input_packet[IP].id, ip_id)
        self.assertEqual(output_packet[IP].id, input_packet[IP].id)
        self.assertEqual(input_packet[UDP].sport, sport)
        self.assertEqual(input_packet[UDP].dport, dport)
        self.assertEqual(output_packet[UDP].sport, input_packet[UDP].sport)
        self.assertEqual(output_packet[UDP].dport, input_packet[UDP].dport)
        expected_udp_length = 8 + len(token)
        self.assertEqual(input_packet[UDP].len, expected_udp_length)
        self.assertEqual(output_packet[UDP].len, input_packet[UDP].len)
        self.assertEqual(bytes(input_packet[Raw].load), token)
        self.assertEqual(bytes(output_packet[Raw].load), bytes(input_packet[Raw].load))

        for label, packet in (("input", input_packet), ("output", output_packet)):
            raw_ip = bytes(packet[IP])
            header_length = (raw_ip[0] & 0x0F) * 4
            self.assertEqual(
                internet_checksum(raw_ip[:header_length]),
                0,
                f"{direction}: invalid {label} IPv4 checksum",
            )
            if zero_checksum:
                self.assertEqual(
                    packet[UDP].chksum,
                    0,
                    f"{direction}: {label} UDP zero checksum was not preserved",
                )
            else:
                self.assertNotEqual(
                    packet[UDP].chksum,
                    0,
                    f"{direction}: {label} UDP checksum is zero",
                )
                self.assertTrue(
                    udp_checksum_valid(packet),
                    f"{direction}: invalid {label} UDP checksum",
                )
        if expected_input_checksum is not None:
            self.assertEqual(
                input_packet[UDP].chksum,
                expected_input_checksum,
                f"{direction}: unexpected encoded input UDP checksum",
            )
        if expected_output_checksum is not None:
            self.assertEqual(
                output_packet[UDP].chksum,
                expected_output_checksum,
                f"{direction}: unexpected encoded output UDP checksum",
            )

    def assert_dropped(self, label, source, frame):
        identifier = struct.unpack("!H", frame[18:20])[0]
        capture_filter = f"ip and ip[4:2] = {identifier}"
        source_host = self.runtime.net.get(source)

        with tempfile.TemporaryDirectory(prefix="p4-nat-drop-") as directory:
            captures = {
                name: PacketCapture(
                    self.runtime.net.get(name),
                    self.runtime.net.get(name).defaultIntf().name,
                    Path(directory) / f"{name}.pcap",
                    capture_filter,
                )
                for name in HOSTS
            }
            try:
                for capture in captures.values():
                    capture.start()
                send_raw_frame(
                    source_host,
                    source_host.defaultIntf().name,
                    frame,
                )
                time.sleep(0.25)
            finally:
                for capture in captures.values():
                    capture.stop()

            observed = {
                name: len(capture.packets())
                for name, capture in captures.items()
            }

        self.assertEqual(
            observed[source],
            1,
            f"{label}: expected one source observation on {source}, got {observed[source]}",
        )
        for name, count in observed.items():
            if name != source:
                self.assertEqual(
                    count,
                    0,
                    f"{label}: observed {count} unexpected packets on {name}",
                )

    def test_h1_to_h2_is_not_translated(self):
        self.assert_forwarded(
            "h1",
            "h2",
            sport=40101,
            dport=40201,
            token=b"inside-h1-to-h2-5b339ac1",
            ip_id=0x1201,
        )

    def test_h2_to_h1_is_not_translated(self):
        self.assert_forwarded(
            "h2",
            "h1",
            sport=40102,
            dport=40202,
            token=b"inside-h2-to-h1-f7d6418e",
            ip_id=0x1202,
        )

    def test_h1_to_h2_df_packet_is_forwarded(self):
        self.assert_forwarded(
            "h1",
            "h2",
            sport=40103,
            dport=40203,
            token=b"inside-df-h1-to-h2-1c6a8e42",
            ip_id=0x1203,
            ip_flags=0x2,
        )

    def test_outbound_h1_tcp_translation(self):
        self.assert_tcp_translation(
            source="h1",
            destination="h3",
            unintended="h2",
            input_src_ip="10.0.1.1",
            input_dst_ip="10.0.3.1",
            output_src_ip="192.0.2.1",
            output_dst_ip="10.0.3.1",
            sport=40001,
            dport=8080,
            flags=0x18,
            sequence=0x13572468,
            acknowledgment=0x10203040,
            token=b"tcp-out-h1-c85d7b31",
            ip_id=0x1301,
        )

    def test_inbound_h1_tcp_translation(self):
        self.assert_tcp_translation(
            source="h3",
            destination="h1",
            unintended="h2",
            input_src_ip="10.0.3.1",
            input_dst_ip="192.0.2.1",
            output_src_ip="10.0.3.1",
            output_dst_ip="10.0.1.1",
            sport=8081,
            dport=40011,
            flags=0x12,
            sequence=0x23456789,
            acknowledgment=0x20304050,
            token=b"tcp-in-h1-7fb29a64",
            ip_id=0x1302,
        )

    def test_outbound_h2_tcp_translation(self):
        self.assert_tcp_translation(
            source="h2",
            destination="h3",
            unintended="h1",
            input_src_ip="10.0.2.1",
            input_dst_ip="10.0.3.1",
            output_src_ip="192.0.2.2",
            output_dst_ip="10.0.3.1",
            sport=40002,
            dport=8082,
            flags=0x11,
            sequence=0x3456789A,
            acknowledgment=0x30405060,
            token=b"tcp-out-h2-3291e5ad",
            ip_id=0x1303,
        )

    def test_inbound_h2_tcp_translation(self):
        self.assert_tcp_translation(
            source="h3",
            destination="h2",
            unintended="h1",
            input_src_ip="10.0.3.1",
            input_dst_ip="192.0.2.2",
            output_src_ip="10.0.3.1",
            output_dst_ip="10.0.2.1",
            sport=8083,
            dport=40012,
            flags=0x10,
            sequence=0x456789AB,
            acknowledgment=0x40506070,
            token=b"tcp-in-h2-a64c813f",
            ip_id=0x1304,
        )

    def test_outbound_h1_udp_translation(self):
        self.assert_udp_translation(
            source="h1",
            destination="h3",
            unintended="h2",
            input_src_ip="10.0.1.1",
            input_dst_ip="10.0.3.1",
            output_src_ip="192.0.2.1",
            output_dst_ip="10.0.3.1",
            sport=41001,
            dport=9080,
            token=b"udp-out-h1-684fa2d3",
            ip_id=0x1401,
            zero_checksum=False,
        )

    def test_inbound_h1_udp_translation(self):
        self.assert_udp_translation(
            source="h3",
            destination="h1",
            unintended="h2",
            input_src_ip="10.0.3.1",
            input_dst_ip="192.0.2.1",
            output_src_ip="10.0.3.1",
            output_dst_ip="10.0.1.1",
            sport=9081,
            dport=41011,
            token=b"udp-in-h1-c18b6375",
            ip_id=0x1402,
            zero_checksum=False,
        )

    def test_outbound_h1_udp_zero_checksum(self):
        self.assert_udp_translation(
            source="h1",
            destination="h3",
            unintended="h2",
            input_src_ip="10.0.1.1",
            input_dst_ip="10.0.3.1",
            output_src_ip="192.0.2.1",
            output_dst_ip="10.0.3.1",
            sport=41002,
            dport=9082,
            token=b"udp-zero-out-58d10e7c",
            ip_id=0x1403,
            zero_checksum=True,
        )

    def test_inbound_h1_udp_zero_checksum(self):
        self.assert_udp_translation(
            source="h3",
            destination="h1",
            unintended="h2",
            input_src_ip="10.0.3.1",
            input_dst_ip="192.0.2.1",
            output_src_ip="10.0.3.1",
            output_dst_ip="10.0.1.1",
            sport=9083,
            dport=41012,
            token=b"udp-zero-in-b04c923a",
            ip_id=0x1404,
            zero_checksum=True,
        )

    def test_outbound_h1_udp_zero_result_is_encoded_as_ffff(self):
        sport = 41003
        dport = 9084
        token = udp_payload_for_checksum_result_zero(
            "192.0.2.1",
            "10.0.3.1",
            sport,
            dport,
            b"udp-ffff-h1-edge",
        )
        self.assert_udp_translation(
            source="h1",
            destination="h3",
            unintended="h2",
            input_src_ip="10.0.1.1",
            input_dst_ip="10.0.3.1",
            output_src_ip="192.0.2.1",
            output_dst_ip="10.0.3.1",
            sport=sport,
            dport=dport,
            token=token,
            ip_id=0x1405,
            zero_checksum=False,
            expected_output_checksum=0xFFFF,
        )

    def test_outbound_h1_udp_input_zero_result_is_encoded_as_ffff(self):
        sport = 41004
        dport = 9085
        token = udp_payload_for_checksum_result_zero(
            "10.0.1.1",
            "10.0.3.1",
            sport,
            dport,
            b"udp-in-ffff-h1-x",
        )
        self.assert_udp_translation(
            source="h1",
            destination="h3",
            unintended="h2",
            input_src_ip="10.0.1.1",
            input_dst_ip="10.0.3.1",
            output_src_ip="192.0.2.1",
            output_dst_ip="10.0.3.1",
            sport=sport,
            dport=dport,
            token=token,
            ip_id=0x1406,
            zero_checksum=False,
            expected_input_checksum=0xFFFF,
        )

    def test_invalid_packets_fail_closed(self):
        def tcp_frame(source, src_ip, dst_ip, identifier, sport, dport, ttl=64):
            frame = ipv4_test_frame(
                source,
                IP(
                    src=src_ip,
                    dst=dst_ip,
                    id=identifier,
                    ttl=ttl,
                )
                / TCP(
                    sport=sport,
                    dport=dport,
                    flags=0x18,
                    seq=identifier,
                    ack=identifier + 1,
                )
                / Raw(f"drop-{identifier:04x}".encode()),
            )
            self.assertTrue(
                tcp_checksum_valid(Ether(frame)),
                f"TCP fixture {identifier:#06x} has an invalid checksum",
            )
            return frame

        bad_ipv4_checksum = bytearray(
            tcp_frame(
                "h1",
                "10.0.1.1",
                "10.0.3.1",
                0x1507,
                43007,
                9307,
            )
        )
        bad_ipv4_checksum[24] ^= 0x01

        bad_tcp_data_offset = ipv4_test_frame(
            "h1",
            IP(
                src="10.0.1.1",
                dst="10.0.3.1",
                id=0x150C,
            )
            / TCP(
                sport=43012,
                dport=9312,
                dataofs=4,
                flags=0x18,
                seq=0x150C,
                ack=0x150D,
            )
            / Raw(b"drop-tcp-offset-150c"),
        )
        self.assertTrue(
            tcp_checksum_valid(Ether(bad_tcp_data_offset)),
            "TCP data-offset fixture has an invalid checksum",
        )

        cases = [
            (
                "outbound private NAT miss",
                "h1",
                tcp_frame(
                    "h1",
                    "10.0.1.99",
                    "10.0.3.1",
                    0x1501,
                    43001,
                    9301,
                ),
            ),
            (
                "inbound public NAT miss",
                "h3",
                tcp_frame(
                    "h3",
                    "10.0.3.1",
                    "192.0.2.99",
                    0x1502,
                    9302,
                    43002,
                ),
            ),
            (
                "route miss after outbound NAT",
                "h1",
                tcp_frame(
                    "h1",
                    "10.0.1.1",
                    "203.0.113.1",
                    0x1503,
                    43003,
                    9303,
                ),
            ),
            (
                "NAT TTL one",
                "h1",
                tcp_frame(
                    "h1",
                    "10.0.1.1",
                    "10.0.3.1",
                    0x1504,
                    43004,
                    9304,
                    ttl=1,
                ),
            ),
            (
                "NAT TTL zero",
                "h1",
                tcp_frame(
                    "h1",
                    "10.0.1.1",
                    "10.0.3.1",
                    0x1505,
                    43005,
                    9305,
                    ttl=0,
                ),
            ),
            (
                "inside TTL one",
                "h1",
                tcp_frame(
                    "h1",
                    "10.0.1.1",
                    "10.0.2.1",
                    0x1506,
                    43006,
                    9306,
                    ttl=1,
                ),
            ),
            (
                "invalid IPv4 checksum",
                "h1",
                bytes(bad_ipv4_checksum),
            ),
            (
                "IPv4 options",
                "h1",
                ipv4_test_frame(
                    "h1",
                    IP(
                        src="10.0.1.1",
                        dst="10.0.2.1",
                        id=0x1508,
                        proto=99,
                        options=b"\x01\x01\x01\x01",
                    )
                    / Raw(b"drop-options-1508"),
                ),
            ),
            (
                "first IPv4 fragment",
                "h1",
                ipv4_test_frame(
                    "h1",
                    IP(
                        src="10.0.1.1",
                        dst="10.0.2.1",
                        id=0x1509,
                        flags="MF",
                    )
                    / UDP(
                        sport=44009,
                        dport=9409,
                        chksum=0,
                    )
                    / Raw(b"drop-first-fragment-1509"),
                ),
            ),
            (
                "non-first IPv4 fragment",
                "h1",
                ipv4_test_frame(
                    "h1",
                    IP(
                        src="10.0.1.1",
                        dst="10.0.2.1",
                        id=0x150A,
                        frag=1,
                        proto=socket.IPPROTO_UDP,
                    )
                    / Raw(
                        struct.pack(
                            "!HHHH",
                            44010,
                            9410,
                            8 + len(b"drop-later-fragment-150a"),
                            0,
                        )
                        + b"drop-later-fragment-150a"
                    ),
                ),
            ),
            (
                "unsupported outbound protocol",
                "h1",
                ipv4_test_frame(
                    "h1",
                    IP(
                        src="10.0.1.1",
                        dst="10.0.3.1",
                        id=0x150B,
                        proto=99,
                    )
                    / Raw(b"drop-protocol-150b"),
                ),
            ),
            (
                "TCP data offset below five",
                "h1",
                bad_tcp_data_offset,
            ),
            (
                "truncated TCP header",
                "h1",
                ipv4_test_frame(
                    "h1",
                    IP(
                        src="10.0.1.1",
                        dst="10.0.3.1",
                        id=0x150D,
                        proto=socket.IPPROTO_TCP,
                    )
                    / Raw(
                        struct.pack("!HHII", 43013, 9313, 0x150D, 0x150E)
                    ),
                ),
            ),
            (
                "UDP length below eight",
                "h1",
                ipv4_test_frame(
                    "h1",
                    IP(
                        src="10.0.1.1",
                        dst="10.0.3.1",
                        id=0x150E,
                    )
                    / UDP(
                        sport=44014,
                        dport=9414,
                        len=7,
                        chksum=0,
                    ),
                ),
            ),
            (
                "UDP length differs from IPv4 payload",
                "h1",
                ipv4_test_frame(
                    "h1",
                    IP(
                        src="10.0.1.1",
                        dst="10.0.3.1",
                        id=0x150F,
                    )
                    / UDP(
                        sport=44015,
                        dport=9415,
                        len=8,
                        chksum=0,
                    )
                    / Raw(b"drop-udp-length-150f"),
                ),
            ),
            (
                "IPv4 total length below header length",
                "h1",
                ipv4_test_frame(
                    "h1",
                    IP(
                        src="10.0.1.1",
                        dst="10.0.2.1",
                        id=0x1510,
                        len=19,
                        proto=99,
                    )
                    / Raw(b"drop-short-length-1510"),
                ),
            ),
            (
                "IPv4 total length exceeds received packet",
                "h1",
                ipv4_test_frame(
                    "h1",
                    IP(
                        src="10.0.1.1",
                        dst="10.0.2.1",
                        id=0x1511,
                        len=100,
                        proto=99,
                    )
                    / Raw(b"drop-long-length-1511"),
                ),
            ),
            (
                "IPv4 version not four",
                "h1",
                ipv4_test_frame(
                    "h1",
                    IP(
                        version=5,
                        ihl=5,
                        src="10.0.1.1",
                        dst="10.0.2.1",
                        id=0x1512,
                        proto=99,
                    )
                    / Raw(b"drop-version-five-1512"),
                ),
            ),
        ]

        identifiers = [struct.unpack("!H", frame[18:20])[0] for _, _, frame in cases]
        self.assertEqual(len(identifiers), len(set(identifiers)))
        for label, _, frame in cases:
            header_length = (frame[14] & 0x0F) * 4
            checksum = internet_checksum(frame[14 : 14 + header_length])
            with self.subTest(fixture=label):
                if label == "invalid IPv4 checksum":
                    self.assertNotEqual(checksum, 0)
                else:
                    self.assertEqual(checksum, 0)
        for label, source, frame in cases:
            with self.subTest(case=label):
                self.assert_dropped(label, source, frame)


if __name__ == "__main__":
    unittest.main(verbosity=2)
