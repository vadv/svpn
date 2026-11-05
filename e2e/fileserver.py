"""File server for the jobs suite: plain GETs from /files.

The suite writes fixture files (CSV databases) into the shared volume from
the client container; svpn jobs download them over HTTP exactly as they
would from db-ip. Requests are logged for download assertions.
"""

import http.server
import socketserver


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory="/files", **kwargs)

    def log_message(self, fmt, *args):
        print(f"HTTP {self.address_string()} {fmt % args}", flush=True)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


Server(("0.0.0.0", 80), Handler).serve_forever()
