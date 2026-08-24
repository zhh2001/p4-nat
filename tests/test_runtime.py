import os
import socket
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "mininet"))

from topology import P4NatNetwork


def unused_local_port(excluded=()):
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        if port not in excluded:
            return port


class ConfigurationFailureNetwork(P4NatNetwork):
    failure_message = "intentional controller configuration failure"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.runtime_path = None
        self.switch_pid = None
        self.switch_interfaces = ()

    def _configure_pipeline(self):
        switch = self.net.get("s1")
        if switch.process is None or switch.process.poll() is not None:
            raise RuntimeError("switch is not running before configuration")
        self.runtime_path = Path(self._runtime_dir.name)
        self.switch_pid = switch.process.pid
        self.switch_interfaces = tuple(
            switch.intfs[port].name for port in (1, 2, 3)
        )
        raise RuntimeError(self.failure_message)


class RuntimeCleanupTest(unittest.TestCase):
    def test_configuration_failure_cleans_runtime(self):
        if os.geteuid() != 0:
            raise RuntimeError("runtime integration tests require root privileges")

        grpc_port = unused_local_port()
        thrift_port = unused_local_port((grpc_port,))
        expected_interfaces = tuple(f"s1-eth{port}" for port in (1, 2, 3))
        for interface in expected_interfaces:
            self.assertFalse(
                (Path("/sys/class/net") / interface).exists(),
                f"interface {interface} exists before the test",
            )

        runtime = ConfigurationFailureNetwork(
            controller=sys.executable,
            p4info=ROOT / "build" / "nat.p4info.txtpb",
            device_config=ROOT / "build" / "nat.json",
            grpc_port=grpc_port,
            thrift_port=thrift_port,
        )
        try:
            with self.assertRaisesRegex(RuntimeError, runtime.failure_message):
                runtime.start()
        finally:
            runtime.close()

        self.assertIsNone(runtime.net)
        self.assertIsNone(runtime._runtime_dir)
        self.assertIsNotNone(runtime.runtime_path)
        self.assertFalse(runtime.runtime_path.exists())
        self.assertIsNotNone(runtime.switch_pid)
        self.assertFalse((Path("/proc") / str(runtime.switch_pid)).exists())
        self.assertEqual(runtime.switch_interfaces, expected_interfaces)
        for interface in runtime.switch_interfaces:
            self.assertFalse((Path("/sys/class/net") / interface).exists())
        for port in (grpc_port, thrift_port):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.bind(("127.0.0.1", port))


if __name__ == "__main__":
    unittest.main(verbosity=2)
