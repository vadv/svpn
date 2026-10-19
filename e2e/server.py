"""Expose SSH and test echo services only inside the Compose network."""

import os
import pathlib
import signal
import socketserver
import subprocess
import threading


class TCP(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(20)
        while data := self.request.recv(65536):
            self.request.sendall(data)
        self.request.sendall(b"EOF")


class UDP(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(data, self.client_address)


class TCPServer(socketserver.ThreadingTCPServer):
    # The default backlog of five is smaller than the concurrent test batch.
    request_queue_size = 128
    allow_reuse_address = True
    daemon_threads = True


for service in (TCPServer(("0.0.0.0", 9000), TCP), socketserver.ThreadingUDPServer(("0.0.0.0", 9000), UDP)):
    threading.Thread(target=service.serve_forever, daemon=True).start()

pathlib.Path("/run/sshd").mkdir(exist_ok=True)
config = pathlib.Path("/tmp/sshd_config")
config.write_text("""Port 22
ListenAddress 0.0.0.0
HostKey /keys/host
AuthorizedKeysFile /keys/client.pub
PermitRootLogin prohibit-password
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
StrictModes yes
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
PrintMotd no
LogLevel ERROR
""")
# Unlock only the disposable root account; SSH still accepts public keys only.
subprocess.run(["passwd", "-d", "root"], check=True, stdout=subprocess.DEVNULL)
sshd = subprocess.Popen(["/usr/sbin/sshd", "-D", "-e", "-f", str(config)])


def stop(_signal, _frame):
    sshd.terminate()


signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
print("SSH and echo services ready", flush=True)
os._exit(sshd.wait())
