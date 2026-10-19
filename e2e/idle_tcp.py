"""Keep two TCP sockets idle until the Compose test sends 'wake' over SSH stdin."""

import contextlib
import socket
import sys

with contextlib.ExitStack() as stack:
    listener = stack.enter_context(socket.socket())
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((sys.argv[1], 9002))
    listener.listen(2)
    listener.settimeout(10)
    print("listening", flush=True)
    clients = [stack.enter_context(listener.accept()[0]) for _ in range(2)]
    for stream in clients:
        stream.settimeout(5)
        stream.sendall(b"ready")
    # Neither socket has a read timeout running during the idle period.
    if sys.stdin.readline() == "wake\n":
        try:
            clients[1].sendall(b"resume")
            received = clients[1].recv(1)
        except (ConnectionResetError, BrokenPipeError):
            print("target reset", flush=True)
        else:
            raise AssertionError(f"expected TCP reset, received {received!r}")
