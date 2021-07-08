import contextlib
import dataclasses
import logging
import selectors
import shlex
import socket
import waiting
import subprocess
import json
import sys
import time
from contextlib import ExitStack
from threading import Thread
import typing

import pexpect
import pytest
from nsenter import Namespace
from linux_tcp_info import tcp_info

logger = logging.getLogger(__name__)


def shell_quote(arg):
    return shlex.quote(str(arg))


def dict_subset(d, keys, default=None):
    return {k: d.get(k, default) for k in keys}


def vars_subset(o, keys, default=None):
    return {k: getattr(o, k, default) for k in keys}


@dataclasses.dataclass
class Opts:
    himtu: int = 9300
    """High value of MTU"""

    server_himtu: typing.Optional[int] = None
    middle_himtu: typing.Optional[int] = None

    tcp_mtu_probing: int = 1
    """Value of /proc/sys/net/ipv4/tcp_mtu_probing on client"""

    tcp_base_mss: typing.Optional[int] = None
    """Value of /proc/sys/net/ipv4/tcp_base_mss on client"""

    tcp_timestamps: typing.Optional[int] = None
    """Value of /proc/sys/net/ipv4/tcp_timestamps on client"""

    tcp_recovery: typing.Optional[int] = None
    """Value of /proc/sys/net/ipv4/tcp_recovery on client"""

    icmp_blackhole: bool = True
    """If true then suppress ICMPs"""

    middle_delay: str = ""
    """Delay to be introduced, taking a suffix like 'ms'"""


class NamespaceSetup:
    """Create a triple-namespace setup"""

    client_netns_name = "ns_client"
    middle_netns_name = "ns_middle"
    server_netns_name = "ns_server"
    client_ipaddr = "12.0.0.1"
    server_ipaddr = "23.0.0.3"

    def __init__(self, opts=None):
        self.opts = opts or Opts()

    def __enter__(self):
        script = f"""
set -e -x
ip netns add ns_client
ip netns add ns_middle
ip netns add ns_server

ip netns exec ns_client ip link add veth_middle type veth peer name veth_client netns ns_middle
ip netns exec ns_client ip addr add dev veth_middle 12.0.0.1/24
ip netns exec ns_client ip link set veth_middle up mtu "{self.opts.himtu}"
ip netns exec ns_middle ip addr add dev veth_client 12.0.0.2/24
ip netns exec ns_middle ip link set veth_client up mtu "{self.opts.himtu}"

ip netns exec ns_server ip link add veth_middle type veth peer name veth_server netns ns_middle
ip netns exec ns_server ip addr add dev veth_middle 23.0.0.3/24
ip netns exec ns_server ip link set veth_middle up mtu "{self.opts.server_himtu or self.opts.himtu}"
ip netns exec ns_middle ip addr add dev veth_server 23.0.0.2/24
ip netns exec ns_middle ip link set veth_server up mtu "{self.opts.middle_himtu or self.opts.himtu}"

ip netns exec ns_client ip route add 23.0.0.0/24 via 12.0.0.2
ip netns exec ns_server ip route add 12.0.0.0/24 via 23.0.0.2
ip netns exec ns_middle sysctl -w net.ipv4.ip_forward=1

# Do proper skb segmentation, no optimizations
ip netns exec ns_client ethtool -K veth_middle gso off tso off

# Explicit tcp mtu probing
ip netns exec ns_client sysctl -w net.ipv4.tcp_mtu_probing={self.opts.tcp_mtu_probing}
"""

        def optional_sysctl_cmd(key: str, val):
            if val is None:
                return ""
            else:
                return f"ip netns exec ns_client sysctl -w {key}={val}\n"

        script += optional_sysctl_cmd("net.ipv4.tcp_base_mss", self.opts.tcp_base_mss)
        script += optional_sysctl_cmd(
            "net.ipv4.tcp_timestamps", self.opts.tcp_timestamps
        )
        script += optional_sysctl_cmd("net.ipv4.tcp_recovery", self.opts.tcp_recovery)
        if self.opts.icmp_blackhole:
            script += """
ip netns exec ns_middle iptables -A INPUT -p icmp -j REJECT
ip netns exec ns_middle iptables -A OUTPUT -p icmp -j REJECT
"""
        if self.opts.middle_delay:
            script += f"""
ip netns exec ns_middle tc qdisc add dev veth_client root netem delay {self.opts.middle_delay}
ip netns exec ns_middle tc qdisc add dev veth_server root netem delay {self.opts.middle_delay}
"""
        self.run_in_host(script)
        return self

    def __exit__(self, *args):
        script = """
for netns in ns_client ns_middle ns_server; do
    if ip netns list | grep -q "$netns"; then
        ip netns del "$netns"
    fi
done
"""
        self.run_in_host(script)

    def run_in_host(self, script, **kw):
        return subprocess.run(script, shell=True, check=True, **kw)

    def run_in_netns(self, netns: str, script: str, **kw):
        cmd = f"ip netns exec {netns} bash -c {shell_quote(script)}"
        return subprocess.run(cmd, **kw, shell=True, check=True)


class SimpleServerThread(Thread):
    def __init__(self, socket, mode="recv"):
        self.listen_socket = socket
        self.mode = mode
        super().__init__()

    def read_echo(self, conn, events):
        data = conn.recv(1000)
        if len(data) == 0:
            print("closing", conn)
            self.sel.unregister(conn)
        else:
            if self.mode == "echo":
                conn.sendall(data)
            elif self.mode == "recv":
                pass
            else:
                raise ValueError(f"Unknown mode {self.mode}")

    def run(self):
        self.should_loop = True
        with ExitStack() as self.exit_stack:
            self.exit_stack.push(self.listen_socket)
            self.listen_socket.listen(1)
            conn, _addr = self.listen_socket.accept()
            conn = self.exit_stack.enter_context(conn)
            conn.setblocking(False)
            self.sel = self.exit_stack.enter_context(selectors.DefaultSelector())
            self.sel.register(conn, selectors.EVENT_READ, self.read_echo)
            while self.should_loop:
                for key, events in self.sel.select(timeout=1):
                    callback = key.data
                    callback(key.fileobj, events)

    def stop(self):
        """Try to stop nicely"""
        self.should_loop = False
        self.join()


def recvall(sock, todo):
    """Receive exactly todo bytes unless EOF"""
    data = bytes()
    while True:
        chunk = sock.recv(todo)
        if not len(chunk):
            return data
        data += chunk
        todo -= len(chunk)
        if todo == 0:
            return data
        assert todo > 0


class PexpectReaderThread:
    """Thread which reads from a pexpect spawn until EOF or stopped

    All data is thrown away so this should be paired with a logfile
    """

    __slots__ = (
        "thread",
        "spawn",
        "should_run",
    )

    def __init__(self, spawn, name=None):
        self.spawn = spawn
        self.thread = Thread(target=self.thread_main, daemon=True)
        if name:
            self.thread.name = name

    def start(self):
        self.should_run = True
        self.thread.start()

    def stop(self):
        if self.thread is None:
            return
        self.should_run = False
        self.thread.join()

    def thread_main(self):
        while self.should_run:
            try:
                self.spawn.read_nonblocking(128, 1)
            except pexpect.EOF:
                logger.debug("got EOF")
                self.should_run = False
            except pexpect.TIMEOUT:
                pass


def pexpect_nice_close(spawn):
    try:
        spawn.sendcontrol("c")
        spawn.expect(pexpect.EOF)
    finally:
        spawn.close()


def tcpdump_expect_listening(spawn):
    """Wait for tcpdump to begin listening"""
    spawn.expect("tcpdump:")
    spawn.expect("listening on ")


@contextlib.contextmanager
def client_tcpdumper():
    cmd = f"ip netns exec ns_client tcpdump -i veth_middle --packet-buffered"
    cmd += " -n"
    # Print a delta (micro-second resolution) between current and previous line on each dump line.
    cmd += " -ttt"
    spawn = pexpect.spawn(cmd, logfile=sys.stdout.buffer)
    tcpdump_expect_listening(spawn)
    reader = PexpectReaderThread(spawn)
    reader.start()
    yield spawn
    reader.stop()
    pexpect_nice_close(spawn)
    logger.info(
        "tcpdump exit status %s signal status %s", spawn.exitstatus, spawn.signalstatus
    )


def nstat_json(command_prefix: str = ""):
    runres = subprocess.run(
        f"{command_prefix}nstat -a --zeros --json",
        shell=True,
        check=True,
        stdout=subprocess.PIPE,
        encoding="utf-8",
    )
    return json.loads(runres.stdout)


@pytest.fixture
def exit_stack():
    with ExitStack() as exit_stack:
        yield exit_stack


def test_echo(exit_stack):
    # Just test connect
    opts = Opts(
        icmp_blackhole=False,
        himtu=9040,
        middle_himtu=3040,
        tcp_mtu_probing=0,
        tcp_timestamps=0,
    )
    setup = exit_stack.enter_context(NamespaceSetup(opts))
    exit_stack.enter_context(client_tcpdumper())
    with Namespace("/var/run/netns/ns_server", "net"):
        listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listen_socket = exit_stack.push(listen_socket)
    listen_socket.bind(("23.0.0.3", 5001))
    server_thread = SimpleServerThread(listen_socket, mode="echo")
    server_thread.start()
    exit_stack.callback(server_thread.stop)

    with Namespace("/var/run/netns/ns_client", "net"):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket = exit_stack.push(client_socket)

    # FIXME: server is not guaranteed to be listening before connect
    # sleep to ensure setup
    time.sleep(1)

    client_socket.settimeout(1.0)
    client_socket.bind(("12.0.0.1", 0))
    client_socket.connect(("23.0.0.3", 5001))

    assert tcp_info.from_socket(client_socket).tcpi_snd_mss == 9000
    assert tcp_info.from_socket(client_socket).tcpi_snd_cwnd == 10
    client_socket.sendall(b"0" * 10000)
    buf = recvall(client_socket, 10000)
    assert len(buf) == 10000
    assert tcp_info.from_socket(client_socket).tcpi_snd_mss == 3000
    assert tcp_info.from_socket(client_socket).tcpi_snd_cwnd >= 10


def test_cwnd(exit_stack):
    """Attempt to examine incorrect cwnd limit behavior in tcp_mtu_probe"""
    opts = Opts(
        middle_delay="10ms",
        tcp_mtu_probing=2,
        tcp_base_mss=1000,
        tcp_timestamps=0,
        middle_himtu=3000,
        himtu=9040,
    )
    setup = exit_stack.enter_context(NamespaceSetup(opts))
    exit_stack.enter_context(client_tcpdumper())
    with Namespace("/var/run/netns/ns_server", "net"):
        listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listen_socket = exit_stack.push(listen_socket)
    listen_socket.bind(("23.0.0.3", 5001))
    server_thread = SimpleServerThread(listen_socket)
    server_thread.start()
    exit_stack.callback(server_thread.stop)

    with Namespace("/var/run/netns/ns_client", "net"):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket = exit_stack.push(client_socket)

    # FIXME: server is not guaranteed to be listening before connect
    # sleep to ensure setup
    time.sleep(1)

    def wait(pred, **kw):
        kw.setdefault("timeout_seconds", 0.01)
        kw.setdefault("sleep_seconds", 0.001)
        waiting.wait(pred, **kw)

    client_socket.settimeout(1.0)
    client_socket.bind(("12.0.0.1", 0))
    client_socket.connect(("23.0.0.3", 5001))

    # send 2x3000 bytes slowly so that cwnd is raised from 10 to 12
    # don't wait too much after sending or cwnd will reset-after-idle
    assert tcp_info.from_socket(client_socket).tcpi_snd_cwnd == 10
    client_socket.sendall(b"0" * 3000)
    time.sleep(0.010)
    client_socket.sendall(b"0" * 3000)
    time.sleep(0.030)
    # logger.info("sent 3000 + 3000")

    def check():
        info = tcp_info.from_socket(client_socket)
        result = (
            info.tcpi_snd_cwnd == 12
            and info.tcpi_unacked == 0
            and info.tcpi_bytes_sent == 6000
            and info.tcpi_bytes_acked == 6001
        )
        if not result:
            names = [
                "tcpi_snd_cwnd",
                "tcpi_unacked",
                "tcpi_bytes_sent",
                "tcpi_bytes_acked",
            ]
            logger.info("wait: %s", vars_subset(info, names))
        return result

    wait(check)

    # sent 4000 + 5000 bytes so that the cwnd is partially filled
    assert tcp_info.from_socket(client_socket).tcpi_snd_cwnd == 12
    client_socket.sendall(b"0" * 4000)
    client_socket.sendall(b"0" * 5000)
    # logger.info("sent 4000 + 5000")
    assert tcp_info.from_socket(client_socket).tcpi_snd_cwnd == 12

    def check():
        info = tcp_info.from_socket(client_socket)
        result = (
            info.tcpi_snd_cwnd == 12
            and info.tcpi_unacked == 9
            and info.tcpi_bytes_sent == 15000
            and info.tcpi_bytes_acked == 6001
        )
        if not result:
            names = [
                "tcpi_snd_cwnd",
                "tcpi_unacked",
                "tcpi_bytes_sent",
                "tcpi_bytes_acked",
            ]
            logger.info("wait: %s", vars_subset(info, names))
        return result

    wait(check)

    # sent 9000 bytes. This is enough data to trigger a probe but cwnd is too tiny!
    client_socket.sendall(b"0" * 9000)
    # logger.info("sent 9000")

    def check():
        info = tcp_info.from_socket(client_socket)
        result = (
            info.tcpi_snd_cwnd == 11
            and info.tcpi_unacked == 11
            and info.tcpi_bytes_sent == 21000
            and info.tcpi_bytes_acked == 6001
        )
        if not result:
            names = [
                "tcpi_snd_cwnd",
                "tcpi_unacked",
                "tcpi_bytes_sent",
                "tcpi_bytes_acked",
            ]
            logger.info("wait: %s", vars_subset(info, names))
        return result

    wait(check)
    time.sleep(1)

    # This behavior is incorrect but the impact is ambiguous.
    # As ACKs are returned from the earlier 4000+5000 burst the probe trail is
    # sent and enough sacks are accumulated for the probe to fail.
    nstat = nstat_json(command_prefix="ip netns exec ns_client ")
    # logger.info("nstat:\n%s", json.dumps(nstat, indent=2))
    names = [
        "TcpRetransSegs",
        "TcpExtTCPMTUPFail",
        "TcpExtTCPMTUPSuccess",
        "TcpExtTCPTimeouts",
    ]
    logger.info("nstat: %s", dict_subset(nstat["kernel"], names))
    assert nstat["kernel"]["TcpRetransSegs"] == 5
    assert nstat["kernel"]["TcpExtTCPMTUPSuccess"] == 0
    assert nstat["kernel"]["TcpExtTCPTimeouts"] == 0
    # why does this fail?
    # assert nstat["kernel"]["TcpExtTCPMTUPFail"] == 1


def test_ping_mtu(exit_stack):
    opts = Opts(
        middle_himtu=3000,
        himtu=6000,
    )
    setup = exit_stack.enter_context(NamespaceSetup(opts))

    def mtu_to_icmp_size(mtu):
        return mtu - 20 - 8

    def can_ping_client_to_server(mtu):
        res = subprocess.run(
            f"ip netns exec {setup.client_netns_name}"
            f" ping {setup.server_ipaddr} -c1 -w1"
            f" -s {mtu_to_icmp_size(mtu)}",
            shell=True,
        )
        return res.returncode == 0

    def can_ping_server_to_client(mtu):
        res = subprocess.run(
            f"ip netns exec {setup.server_netns_name}"
            f" ping {setup.client_ipaddr} -c1 -w1"
            f" -s {mtu_to_icmp_size(mtu)}",
            shell=True,
        )
        return res.returncode == 0

    assert can_ping_client_to_server(100)
    assert can_ping_server_to_client(100)

    assert can_ping_client_to_server(opts.middle_himtu)
    assert can_ping_client_to_server(opts.middle_himtu - 1)
    assert can_ping_client_to_server(opts.middle_himtu + 1) == False
    assert can_ping_server_to_client(opts.middle_himtu)
