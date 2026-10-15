"""Echo that first reports the peer IP: proves the source address seen after masquerading."""
import socketserver


class ReportEcho(socketserver.BaseRequestHandler):
    def handle(self):
        peer = f'{self.request.getpeername()[0]}\n'.encode()
        self.request.sendall(peer)
        while data := self.request.recv(65536):
            self.request.sendall(data)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


Server(('0.0.0.0', 9000), ReportEcho).serve_forever()
