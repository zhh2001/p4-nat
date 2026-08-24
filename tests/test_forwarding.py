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


def wait_for_line(process, expected, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            detail = (stderr or stdout).decode("utf-8", errors="replace").strip()
            raise RuntimeError(
                f"process exited with status {process.returncode}: {detail}"
            )
        readable, _, _ = select.select([process.stdout], [], [], 0.1)
        if readable:
            line = process.stdout.readline().decode("utf-8", errors="replace").strip()
            if line == expected:
                return
            raise RuntimeError(f"unexpected process output: {line!r}")
    raise TimeoutError(f"timed out waiting for process output {expected!r}")


def stop_child(process):
    if process is None:
        return
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=1.0)
    for stream in (process.stdout, process.stderr):
        if stream is not None and not stream.closed:
            stream.close()


def communicate_child(process, label, timeout):
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        process.kill()
        process.communicate()
        raise RuntimeError(f"{label} timed out") from error
    if process.returncode != 0:
        detail = (stderr or stdout).decode("utf-8", errors="replace").strip()
        raise RuntimeError(
            f"{label} exited with status {process.returncode}: {detail}"
        )
    return stdout


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
        switch = cls.runtime.net.get("s1")
        cls.runtime_path = Path(cls.runtime._runtime_dir.name)
        cls.switch_pid = switch.process.pid
        cls.switch_interfaces = tuple(
            switch.intfs[port].name for port in (1, 2, 3)
        )
        cls.runtime_ports = (cls.runtime.grpc_port, cls.runtime.thrift_port)
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
        source_config = HOSTS[source]
        destination_config = HOSTS[destination]
        source_ip = source_config["address"].split("/", 1)[0]
        destination_ip = destination_config["address"].split("/", 1)[0]
        unintended = next(name for name in HOSTS if name not in {source, destination})
        capture_filter = (
            f"udp and src host {source_ip} and dst host {destination_ip} "
            f"and src port {sport} and dst port {dport}"
        )

        with tempfile.TemporaryDirectory(prefix="p4-nat-packets-") as directory:
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
                for capture in captures.values():
                    capture.stop()

            observed = {
                name: capture.packets()
                for name, capture in captures.items()
            }

        self.assertEqual(
            len(observed[source]),
            1,
            f"{source}->{destination}: expected one source packet, got {len(observed[source])}",
        )
        self.assertEqual(
            len(observed[destination]),
            1,
            f"{source}->{destination}: expected one destination packet, "
            f"got {len(observed[destination])}",
        )
        self.assertEqual(
            len(observed[unintended]),
            0,
            f"{source}->{destination}: observed {len(observed[unintended])} "
            f"packets on {unintended}",
        )

        input_packet = observed[source][0]
        output_packet = observed[destination][0]
        self.assertEqual(input_packet[Ether].src, source_config["mac"])
        self.assertEqual(input_packet[Ether].dst, source_config["switch_mac"])
        self.assertEqual(output_packet[Ether].src, destination_config["switch_mac"])
        self.assertEqual(output_packet[Ether].dst, destination_config["mac"])
        for packet in (input_packet, output_packet):
            self.assertEqual(packet[IP].src, source_ip)
            self.assertEqual(packet[IP].dst, destination_ip)
            self.assertEqual(packet[IP].id, ip_id)
            self.assertEqual(int(packet[IP].flags), ip_flags)
            self.assertEqual(packet[UDP].sport, sport)
            self.assertEqual(packet[UDP].dport, dport)
            self.assertEqual(bytes(packet[Raw].load), token)
        self.assertEqual(input_packet[IP].ttl, 64)
        self.assertEqual(output_packet[IP].ttl, input_packet[IP].ttl - 1)

        for label, packet in (("input", input_packet), ("output", output_packet)):
            raw_ip = bytes(packet[IP])
            header_length = (raw_ip[0] & 0x0F) * 4
            self.assertEqual(
                internet_checksum(raw_ip[:header_length]),
                0,
                f"{source}->{destination}: invalid {label} IPv4 checksum",
            )
            self.assertTrue(
                udp_checksum_valid(packet),
                f"{source}->{destination}: invalid {label} UDP checksum",
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

    def test_controller_readback_and_runtime_readiness(self):
        switch = self.runtime.net.get("s1")
        self.assertIsNotNone(switch.process)
        self.assertIsNone(switch.process.poll())
        for port in (1, 2, 3):
            self.assertEqual(switch.intfs[port].name, f"s1-eth{port}")
        for port in (self.runtime.grpc_port, self.runtime.thrift_port):
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                pass
        self.assertEqual(
            self.runtime.controller_output,
            "configured and verified 13 table entries",
        )

        result = subprocess.run(
            [
                str(ROOT / "build" / "p4natctl"),
                "--address",
                f"127.0.0.1:{self.runtime.grpc_port}",
                "--device-id",
                str(self.runtime.device_id),
                "--p4info",
                str(ROOT / "build" / "nat.p4info.txtpb"),
                "--device-config",
                str(ROOT / "build" / "nat.json"),
                "--verify-only",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=5.0,
        )
        self.assertEqual(result.returncode, 0, result.stderr.strip())
        self.assertEqual(result.stdout.strip(), "verified 13 table entries")

    def test_real_tcp_socket_translation(self):
        server_script = """
import socket
import sys

address = sys.argv[1]
port = int(sys.argv[2])
expected = bytes.fromhex(sys.argv[3])
response = bytes.fromhex(sys.argv[4])
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.settimeout(5.0)
    server.bind((address, port))
    server.listen(1)
    print("READY", flush=True)
    connection, peer = server.accept()
    with connection:
        connection.settimeout(5.0)
        received = bytearray()
        while len(received) < len(expected):
            chunk = connection.recv(len(expected) - len(received))
            if not chunk:
                break
            received.extend(chunk)
        if bytes(received) != expected:
            raise RuntimeError(f"received {bytes(received)!r}, expected {expected!r}")
        connection.sendall(response)
        print(f"{peer[0]} {peer[1]} {bytes(received).hex()}", flush=True)
"""
        client_script = """
import socket
import sys

source_address = sys.argv[1]
source_port = int(sys.argv[2])
destination_address = sys.argv[3]
destination_port = int(sys.argv[4])
request = bytes.fromhex(sys.argv[5])
expected = bytes.fromhex(sys.argv[6])
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
    client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    client.settimeout(5.0)
    client.bind((source_address, source_port))
    client.connect((destination_address, destination_port))
    client.sendall(request)
    received = bytearray()
    while len(received) < len(expected):
        chunk = client.recv(len(expected) - len(received))
        if not chunk:
            break
        received.extend(chunk)
    if bytes(received) != expected:
        raise RuntimeError(f"received {bytes(received)!r}, expected {expected!r}")
    print(bytes(received).hex(), flush=True)
"""
        source_port = 45001
        destination_port = 18080
        request = b"real-tcp-request-6d32a9f1"
        response = b"real-tcp-response-b17e403c"
        h1 = self.runtime.net.get("h1")
        h3 = self.runtime.net.get("h3")
        server = h3.popen(
            [
                sys.executable,
                "-c",
                server_script,
                "10.0.3.1",
                str(destination_port),
                request.hex(),
                response.hex(),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        client = None
        server_output = b""
        client_output = b""

        with tempfile.TemporaryDirectory(prefix="p4-nat-socket-") as directory:
            capture_filter = f"tcp and port {destination_port}"
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
                wait_for_line(server, "READY", timeout=3.0)
                for capture in captures.values():
                    capture.start()
                client = h1.popen(
                    [
                        sys.executable,
                        "-c",
                        client_script,
                        "10.0.1.1",
                        str(source_port),
                        "10.0.3.1",
                        str(destination_port),
                        request.hex(),
                        response.hex(),
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                client_output = communicate_child(client, "TCP client", timeout=6.0)
                server_output = communicate_child(server, "TCP server", timeout=6.0)
                time.sleep(0.25)
            finally:
                for capture in captures.values():
                    capture.stop()
                stop_child(client)
                stop_child(server)

            observed = {
                name: capture.packets()
                for name, capture in captures.items()
            }

        self.assertEqual(client_output.decode().strip(), response.hex())
        peer_ip, peer_port, received = server_output.decode().strip().split()
        self.assertEqual(peer_ip, "192.0.2.1")
        self.assertEqual(int(peer_port), source_port)
        self.assertEqual(received, request.hex())

        def packets_with_payload(name, payload):
            return [
                packet
                for packet in observed[name]
                if packet.haslayer(TCP) and bytes(packet[TCP].payload) == payload
            ]

        request_inside = packets_with_payload("h1", request)
        request_outside = packets_with_payload("h3", request)
        response_outside = packets_with_payload("h3", response)
        response_inside = packets_with_payload("h1", response)
        self.assertEqual(len(request_inside), 1, "request multiplicity on h1")
        self.assertEqual(len(request_outside), 1, "request multiplicity on h3")
        self.assertEqual(len(response_outside), 1, "response multiplicity on h3")
        self.assertEqual(len(response_inside), 1, "response multiplicity on h1")
        self.assertEqual(len(observed["h2"]), 0, "real TCP traffic leaked to h2")

        request_input = request_inside[0]
        request_output = request_outside[0]
        response_input = response_outside[0]
        response_output = response_inside[0]
        expected = (
            (
                request_input,
                HOSTS["h1"]["mac"],
                HOSTS["h1"]["switch_mac"],
                "10.0.1.1",
                "10.0.3.1",
                source_port,
                destination_port,
                64,
                request,
            ),
            (
                request_output,
                HOSTS["h3"]["switch_mac"],
                HOSTS["h3"]["mac"],
                "192.0.2.1",
                "10.0.3.1",
                source_port,
                destination_port,
                63,
                request,
            ),
            (
                response_input,
                HOSTS["h3"]["mac"],
                HOSTS["h3"]["switch_mac"],
                "10.0.3.1",
                "192.0.2.1",
                destination_port,
                source_port,
                64,
                response,
            ),
            (
                response_output,
                HOSTS["h1"]["switch_mac"],
                HOSTS["h1"]["mac"],
                "10.0.3.1",
                "10.0.1.1",
                destination_port,
                source_port,
                63,
                response,
            ),
        )
        for packet, src_mac, dst_mac, src_ip, dst_ip, sport, dport, ttl, payload in expected:
            self.assertEqual(packet[Ether].src, src_mac)
            self.assertEqual(packet[Ether].dst, dst_mac)
            self.assertEqual(packet[IP].src, src_ip)
            self.assertEqual(packet[IP].dst, dst_ip)
            self.assertEqual(packet[IP].ttl, ttl)
            self.assertEqual(packet[TCP].sport, sport)
            self.assertEqual(packet[TCP].dport, dport)
            self.assertEqual(bytes(packet[TCP].payload), payload)
            raw_ip = bytes(packet[IP])
            header_length = (raw_ip[0] & 0x0F) * 4
            self.assertEqual(internet_checksum(raw_ip[:header_length]), 0)
            self.assertTrue(tcp_checksum_valid(packet))

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

        bad_tcp_checksum = bytearray(
            tcp_frame(
                "h1",
                "10.0.1.1",
                "10.0.3.1",
                0x1513,
                43019,
                9319,
            )
        )
        bad_tcp_checksum[14 + 20 + 16] ^= 0x01
        self.assertFalse(tcp_checksum_valid(Ether(bad_tcp_checksum)))

        bad_udp_checksum = ipv4_test_frame(
            "h1",
            IP(
                src="10.0.1.1",
                dst="10.0.3.1",
                id=0x1514,
            )
            / UDP(
                sport=44020,
                dport=9420,
                chksum=0xFFFF,
            )
            / Raw(b"drop-bad-udp-checksum-1514"),
        )
        self.assertFalse(udp_checksum_valid(Ether(bad_udp_checksum)))

        oversized_tcp_data_offset = ipv4_test_frame(
            "h1",
            IP(
                src="10.0.1.1",
                dst="10.0.3.1",
                id=0x1516,
            )
            / TCP(
                sport=43022,
                dport=9322,
                dataofs=15,
                flags=0x18,
                seq=0x1516,
                ack=0x1517,
            )
            / Raw(b"drop-tcp-offset-1516"),
        )
        self.assertTrue(
            tcp_checksum_valid(Ether(oversized_tcp_data_offset)),
            "oversized TCP data-offset fixture has an invalid checksum",
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
            (
                "invalid TCP checksum",
                "h1",
                bytes(bad_tcp_checksum),
            ),
            (
                "invalid nonzero UDP checksum",
                "h1",
                bad_udp_checksum,
            ),
            (
                "unsupported inbound protocol",
                "h3",
                ipv4_test_frame(
                    "h3",
                    IP(
                        src="10.0.3.1",
                        dst="192.0.2.1",
                        id=0x1515,
                        proto=99,
                    )
                    / Raw(b"drop-inbound-protocol-1515"),
                ),
            ),
            (
                "TCP data offset exceeds transport length",
                "h1",
                oversized_tcp_data_offset,
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


class SuccessfulRuntimeCleanupTest(unittest.TestCase):
    def test_successful_runtime_cleanup(self):
        self.assertIsNone(PacketIntegrationTest.runtime.net)
        self.assertIsNone(PacketIntegrationTest.runtime._runtime_dir)
        self.assertFalse(PacketIntegrationTest.runtime_path.exists())
        self.assertFalse(
            (Path("/proc") / str(PacketIntegrationTest.switch_pid)).exists()
        )
        for interface in PacketIntegrationTest.switch_interfaces:
            self.assertFalse((Path("/sys/class/net") / interface).exists())
        for port in PacketIntegrationTest.runtime_ports:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.bind(("127.0.0.1", port))


if __name__ == "__main__":
    unittest.main(verbosity=2)
