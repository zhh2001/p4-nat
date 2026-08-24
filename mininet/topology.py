#!/usr/bin/env python3

import argparse
import os
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path

from mininet.cli import CLI
from mininet.net import Mininet
from mininet.node import Switch
from mininet.topo import Topo


HOSTS = {
    "h1": {
        "address": "10.0.1.1/24",
        "mac": "00:00:00:00:01:01",
        "gateway": "10.0.1.254",
        "switch_mac": "00:aa:00:00:01:01",
        "routes": ("10.0.2.0/24", "10.0.3.0/24"),
    },
    "h2": {
        "address": "10.0.2.1/24",
        "mac": "00:00:00:00:02:01",
        "gateway": "10.0.2.254",
        "switch_mac": "00:aa:00:00:02:01",
        "routes": ("10.0.1.0/24", "10.0.3.0/24"),
    },
    "h3": {
        "address": "10.0.3.1/24",
        "mac": "00:00:00:00:03:01",
        "gateway": "10.0.3.254",
        "switch_mac": "00:aa:00:00:03:01",
        "routes": ("10.0.1.0/24", "10.0.2.0/24", "192.0.2.0/24"),
    },
}


def _wait_for_port(port, process, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"simple_switch_grpc exited with status {process.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(f"timed out waiting for TCP port {port}")


class P4RuntimeSwitch(Switch):
    def __init__(
        self,
        name,
        grpc_port,
        thrift_port,
        device_id,
        runtime_dir,
        executable="simple_switch_grpc",
        **params,
    ):
        super().__init__(name, **params)
        self.grpc_port = int(grpc_port)
        self.thrift_port = int(thrift_port)
        self.device_id = int(device_id)
        self.runtime_dir = Path(runtime_dir)
        self.executable = executable
        self.process = None
        self._log_file = None

    def start(self, controllers):
        executable = shutil.which(self.executable)
        if executable is None:
            raise RuntimeError(f"{self.executable} is not installed")

        interfaces = []
        for port in (1, 2, 3):
            intf = self.intfs.get(port)
            if intf is None:
                raise RuntimeError(f"{self.name} has no interface on port {port}")
            interfaces.extend(("-i", f"{port}@{intf.name}"))

        notification_socket = self.runtime_dir / "notifications.ipc"
        command = [
            executable,
            "--no-p4",
            "--device-id",
            str(self.device_id),
            "--thrift-port",
            str(self.thrift_port),
            "--notifications-addr",
            f"ipc://{notification_socket}",
            "--log-level",
            "warn",
            *interfaces,
            "--",
            "--grpc-server-addr",
            f"127.0.0.1:{self.grpc_port}",
        ]
        self._log_file = (self.runtime_dir / "simple_switch_grpc.log").open(
            "w", encoding="utf-8"
        )
        self.process = self.popen(
            command,
            stdout=self._log_file,
            stderr=subprocess.STDOUT,
            close_fds=True,
        )
        try:
            _wait_for_port(self.grpc_port, self.process, timeout=5.0)
            _wait_for_port(self.thrift_port, self.process, timeout=5.0)
        except Exception as error:
            self._log_file.flush()
            detail = (self.runtime_dir / "simple_switch_grpc.log").read_text(
                encoding="utf-8", errors="replace"
            )
            self._stop_process()
            if detail.strip():
                raise RuntimeError(f"{error}:\n{detail.rstrip()}") from error
            raise

    def _stop_process(self):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=1.0)
        self.process = None
        if self._log_file is not None:
            self._log_file.close()
            self._log_file = None

    def stop(self, deleteIntfs=True):
        self._stop_process()
        super().stop(deleteIntfs=deleteIntfs)


class NatTopology(Topo):
    def build(self, grpc_port, thrift_port, device_id, runtime_dir, switch_executable):
        switch = self.addSwitch(
            "s1",
            cls=P4RuntimeSwitch,
            grpc_port=grpc_port,
            thrift_port=thrift_port,
            device_id=device_id,
            runtime_dir=runtime_dir,
            executable=switch_executable,
        )
        for port, name in enumerate(("h1", "h2", "h3"), start=1):
            config = HOSTS[name]
            host = self.addHost(name, ip=config["address"], mac=config["mac"])
            self.addLink(host, switch, port1=0, port2=port)


def _run_host_command(host, command):
    stdout, stderr, status = host.pexec(command)
    if status != 0:
        rendered = " ".join(command)
        detail = stderr.strip() or stdout.strip()
        raise RuntimeError(f"{host.name}: {rendered} failed: {detail}")


def _configure_host(host, config):
    interface = host.defaultIntf().name
    _run_host_command(host, ["ip", "-4", "address", "flush", "dev", interface])
    _run_host_command(host, ["ip", "address", "add", config["address"], "dev", interface])
    _run_host_command(
        host,
        [
            "ip",
            "neighbor",
            "replace",
            config["gateway"],
            "lladdr",
            config["switch_mac"],
            "nud",
            "permanent",
            "dev",
            interface,
        ],
    )
    for prefix in config["routes"]:
        _run_host_command(
            host,
            [
                "ip",
                "route",
                "replace",
                prefix,
                "via",
                config["gateway"],
                "dev",
                interface,
            ],
        )
    _run_host_command(
        host,
        [
            "ethtool",
            "--offload",
            interface,
            "rx",
            "off",
            "tx",
            "off",
            "sg",
            "off",
            "tso",
            "off",
            "gso",
            "off",
            "gro",
            "off",
            "lro",
            "off",
        ],
    )


def _check_port_available(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        try:
            probe.bind(("127.0.0.1", port))
        except OSError as error:
            raise RuntimeError(f"TCP port {port} is already in use") from error


class P4NatNetwork:
    def __init__(
        self,
        controller,
        p4info,
        device_config,
        grpc_port=9559,
        thrift_port=9090,
        device_id=1,
        switch_executable="simple_switch_grpc",
        controller_timeout=25.0,
    ):
        self.controller = Path(controller)
        self.p4info = Path(p4info)
        self.device_config = Path(device_config)
        self.grpc_port = int(grpc_port)
        self.thrift_port = int(thrift_port)
        self.device_id = int(device_id)
        self.switch_executable = switch_executable
        self.controller_timeout = controller_timeout
        self.net = None
        self.controller_output = ""
        self._runtime_dir = None

    def start(self):
        if self.net is not None:
            raise RuntimeError("network is already running")
        if self.grpc_port == self.thrift_port:
            raise ValueError("P4Runtime and Thrift ports must differ")
        for path in (self.controller, self.p4info, self.device_config):
            if not path.is_file():
                raise FileNotFoundError(path)
        _check_port_available(self.grpc_port)
        _check_port_available(self.thrift_port)

        self._runtime_dir = tempfile.TemporaryDirectory(prefix="p4-nat-")
        topology = NatTopology(
            grpc_port=self.grpc_port,
            thrift_port=self.thrift_port,
            device_id=self.device_id,
            runtime_dir=self._runtime_dir.name,
            switch_executable=self.switch_executable,
        )
        self.net = Mininet(topo=topology, controller=None, waitConnected=False)
        try:
            self.net.start()
            for name, config in HOSTS.items():
                _configure_host(self.net.get(name), config)
            self._configure_pipeline()
        except Exception:
            self.close()
            raise
        return self

    def _configure_pipeline(self):
        command = [
            str(self.controller),
            "--address",
            f"127.0.0.1:{self.grpc_port}",
            "--device-id",
            str(self.device_id),
            "--p4info",
            str(self.p4info),
            "--device-config",
            str(self.device_config),
        ]
        try:
            result = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=self.controller_timeout,
            )
        except subprocess.TimeoutExpired as error:
            raise RuntimeError("controller configuration timed out") from error
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip()
            raise RuntimeError(
                f"controller exited with status {result.returncode}: {detail}"
            )
        self.controller_output = result.stdout.strip()

    def close(self):
        try:
            if self.net is not None:
                self.net.stop()
        finally:
            self.net = None
            if self._runtime_dir is not None:
                self._runtime_dir.cleanup()
                self._runtime_dir = None

    def __enter__(self):
        return self.start()

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False


def _parse_args():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description="run the P4 static NAT topology")
    parser.add_argument("--controller", default=root / "build" / "p4natctl", type=Path)
    parser.add_argument("--p4info", default=root / "build" / "nat.p4info.txtpb", type=Path)
    parser.add_argument("--device-config", default=root / "build" / "nat.json", type=Path)
    parser.add_argument("--grpc-port", default=9559, type=int)
    parser.add_argument("--thrift-port", default=9090, type=int)
    parser.add_argument("--device-id", default=1, type=int)
    parser.add_argument("--switch", default="simple_switch_grpc")
    return parser.parse_args()


def main():
    if os.geteuid() != 0:
        raise SystemExit("Mininet requires root privileges")

    args = _parse_args()
    with P4NatNetwork(
        controller=args.controller,
        p4info=args.p4info,
        device_config=args.device_config,
        grpc_port=args.grpc_port,
        thrift_port=args.thrift_port,
        device_id=args.device_id,
        switch_executable=args.switch,
    ) as runtime:
        CLI(runtime.net)


if __name__ == "__main__":
    main()
