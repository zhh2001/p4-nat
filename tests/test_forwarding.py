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

from scapy.all import Ether, IP, Raw, UDP, rdpcap


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
    udp = bytes(packet[UDP])
    pseudo_header = (
        socket.inet_aton(packet[IP].src)
        + socket.inet_aton(packet[IP].dst)
        + struct.pack("!BBH", 0, packet[IP].proto, len(udp))
    )
    return packet[UDP].chksum != 0 and internet_checksum(pseudo_header + udp) == 0


def send_udp(host, interface, src_mac, dst_mac, src_ip, dst_ip, sport, dport, token, ip_id):
    script = """
import sys
from scapy.all import Ether, IP, Raw, UDP, sendp

packet = (
    Ether(src=sys.argv[2], dst=sys.argv[3])
    / IP(src=sys.argv[4], dst=sys.argv[5], ttl=64, id=int(sys.argv[8]))
    / UDP(sport=int(sys.argv[6]), dport=int(sys.argv[7]))
    / Raw(bytes.fromhex(sys.argv[9]))
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


class InsideForwardingTest(unittest.TestCase):
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
        if cls.runtime.controller_output != "configured and verified 9 table entries":
            cls.runtime.close()
            raise AssertionError(
                f"unexpected controller output: {cls.runtime.controller_output!r}"
            )

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "runtime"):
            cls.runtime.close()

    def assert_forwarded(self, source, destination, sport, dport, token, ip_id):
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
