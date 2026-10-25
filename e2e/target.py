"""Echo that first reports the peer IP: proves the source address seen after masquerading."""

import socketserver
import threading


class ReportEcho(socketserver.BaseRequestHandler):
    def handle(self):
        peer = f"{self.request.getpeername()[0]}\n".encode()
        self.request.sendall(peer)
        while data := self.request.recv(65536):
            self.request.sendall(data)


class UdpEcho(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(data, self.client_address)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class UdpServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


udp = UdpServer(("0.0.0.0", 9000), UdpEcho)
threading.Thread(target=udp.serve_forever, daemon=True).start()
Server(("0.0.0.0", 9000), ReportEcho).serve_forever()
