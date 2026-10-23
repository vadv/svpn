"""Keep two TCP sockets idle until the Compose test sends 'wake' over SSH stdin."""

import contextlib
import socket
import sys
import time

from _lib import recv_exact

with contextlib.ExitStack() as stack:
    listener = stack.enter_context(socket.socket())
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((sys.argv[1], 9002))
    listener.listen(2)
    listener.settimeout(10)
    print("listening", flush=True)
    clients = [stack.enter_context(listener.accept()[0]) for _ in range(2)]
    for stream in clients:
        stream.settimeout(35)
        stream.sendall(b"ready")
    # Do not read either socket until the idle period ends.
    if sys.stdin.readline() == "wake\n":
        assert recv_exact(clients[0], 6) == b"resume"
        assert clients[0].recv(1) == b""
        clients[1].sendall(b"resume")
        clients[1].shutdown(socket.SHUT_WR)
        time.sleep(20)
        clients[0].sendall(b"resume")
        clients[0].shutdown(socket.SHUT_WR)
        assert recv_exact(clients[1], 5) == b"after"
        assert clients[1].recv(1) == b""
        print("half-close survived", flush=True)
