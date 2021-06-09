import pytest
import logging
import socket
from threading import Thread
from contextlib import ExitStack
from nsenter import Namespace
import dataclasses
import selectors
import subprocess

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class Opts:
    himtu: int = 9300


class NamespaceSetup:
    """Create a triple-namespace setup"""
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
ip netns exec ns_server ip link set veth_middle up mtu "{self.opts.himtu}"
ip netns exec ns_middle ip addr add dev veth_server 23.0.0.2/24
ip netns exec ns_middle ip link set veth_server up mtu "{self.opts.himtu}"

ip netns exec ns_client ip route add 23.0.0.0/24 via 12.0.0.2
ip netns exec ns_server ip route add 12.0.0.0/24 via 23.0.0.2
ip netns exec ns_middle sysctl -w net.ipv4.ip_forward=1

# Do proper skb segmentation, no optimizations
ip netns exec ns_client ethtool -K veth_middle gso off tso off

# Explicit tcp mtu probing
ip netns exec ns_client sysctl -w net.ipv4.tcp_mtu_probing=1

# ICMP blackhole:
ip netns exec ns_middle iptables -A INPUT -p icmp -j REJECT
ip netns exec ns_middle iptables -A OUTPUT -p icmp -j REJECT
"""
        self.run_in_host(script)

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

    def run_in_netns(self, netns:str, script:str, **kw):
        import shlex
        cmd = f"ip netns exec {netns} bash -c {shlex.quote(script)}"
        return subprocess.run(cmd, **kw, shell=True, check=True)


class EchoServerThread(Thread):
    def __init__(self, socket):
        self.listen_socket = socket
        super().__init__()

    def read_echo(self, conn, events):
        data = conn.recv(1000)
        if len(data) == 0:
            print('closing', conn)
            self.sel.unregister(conn)
        else:
            conn.sendall(data)

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


class TestMain:
    def test_basic(self):
        with ExitStack() as exit_stack:
            setup = exit_stack.enter_context(NamespaceSetup())
            subprocess.run("ls -latr /var/run/netns/", shell=True, check=True)
            with Namespace("/var/run/netns/ns_server", "net"):
                listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                listen_socket = exit_stack.push(listen_socket)
            listen_socket.bind(('23.0.0.3', 5001))
            server_thread = EchoServerThread(listen_socket)
            server_thread.start()
            exit_stack.callback(server_thread.stop)

            # FIXME: server is not guaranteed to be listening before connect

            with Namespace("/var/run/netns/ns_client", "net"):
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_socket = exit_stack.push(client_socket)

            client_socket.settimeout(1.0)
            client_socket.bind(('12.0.0.1', 0))
            client_socket.connect(('23.0.0.3', 5001))

            client_socket.sendall(b'0' * 5000)
            data = recvall(client_socket, 5000)
            assert len(data) == 5000

            client_socket.sendall(b'0' * 5000)
            data = recvall(client_socket, 5000)
            assert len(data) == 5000
