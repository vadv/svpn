"""File-backed DNS A-record server for the sticky suite.

Records live in /dns/records (`name ip` per line, `#` comments); the file is
reloaded when its mtime changes, so the suite rewrites answers without any
signalling. NODATA answers as NOERROR with zero records: the resolver treats
that as a successful refresh with an empty set, which is what lets stale pins
purge.
"""

import pathlib
import socket
import struct

RECORDS = pathlib.Path("/dns/records")
TTL = 5
T_A = 1
CLASS_IN = 1


def load():
    table = {}
    try:
        text = RECORDS.read_text()
    except OSError:
        return table
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, _, ip = line.partition(" ")
        name = name.strip().rstrip(".").lower()
        ip = ip.strip()
        if name and ip:
            table[name] = ip
    return table


def question(data):
    """Parse (transaction_id, qname, qtype); qname without trailing dot."""
    if len(data) < 12:
        return None
    ident, _flags, qdcount = struct.unpack_from("!HHH", data, 0)
    if qdcount < 1:
        return None
    offset = 12
    labels = []
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0:
            return None  # compression in questions: not worth supporting
        offset += 1
        labels.append(data[offset : offset + length].decode("ascii", "replace").lower())
        offset += length
    if offset + 4 > len(data):
        return None
    qtype, _qclass = struct.unpack_from("!HH", data, offset)
    return ident, ".".join(labels), qtype


def answer(ident, qname, ip):
    encoded = b"".join(bytes([len(label)]) + label.encode() for label in qname.split("."))
    tail = struct.pack("!HHIH", T_A, CLASS_IN, TTL, 4) + socket.inet_aton(ip)
    response = (
        struct.pack("!HHHHHH", ident, 0x8180, 1, 1, 0, 0)
        + encoded
        + b"\0"
        + struct.pack("!HH", T_A, CLASS_IN)
        + b"\xc0\x0c"
        + tail
    )
    return response


def nodata(ident, qname, qtype):
    encoded = b"".join(bytes([len(label)]) + label.encode() for label in qname.split("."))
    return (
        struct.pack("!HHHHHH", ident, 0x8180, 1, 0, 0, 0)
        + encoded
        + b"\0"
        + struct.pack("!HH", qtype, CLASS_IN)
    )


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 53))
    table, stamp = {}, -1
    while True:
        try:
            data, peer = sock.recvfrom(4096)
        except InterruptedError:
            continue
        try:
            mtime = RECORDS.stat().st_mtime_ns
        except OSError:
            mtime = -1
        if mtime != stamp:
            table, stamp = load(), mtime
        parsed = question(data)
        if parsed is None:
            print(f"DNS unparsable from {peer}", flush=True)
            continue
        ident, qname, qtype = parsed
        print(f"DNS query qname={qname} qtype={qtype} from {peer}", flush=True)
        if qtype == T_A and qname in table:
            sock.sendto(answer(ident, qname, table[qname]), peer)
        else:
            # Every other query (AAAA included — glibc resolves A and AAAA
            # in parallel) gets NOERROR with zero answers, never silence.
            sock.sendto(nodata(ident, qname, qtype), peer)


if __name__ == "__main__":
    main()
