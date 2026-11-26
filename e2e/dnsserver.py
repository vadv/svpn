"""File-backed DNS A-record server for the sticky and DNS-exit suites.

Records live in /dns/records, one per line, reloaded when the file's mtime
changes, so the suites rewrite answers without any signalling:

    name ip            for every asker
    name ip@address    only when the query comes from `address`
    name -             no answer at all: a resolver with nothing to say

A name may have both: the asker's own line wins over the line for everyone.
Every query is appended to /dns/queries as `<asker> <name> <qtype>`.
NODATA answers as NOERROR with zero records: the resolver treats
that as a successful refresh with an empty set, which is what lets stale pins
purge.
"""

import pathlib
import socket
import struct

RECORDS = pathlib.Path("/dns/records")
QUERIES = pathlib.Path("/dns/queries")
TTL = 5
T_A = 1
CLASS_IN = 1
SILENT = "-"


def load():
    """name → [(asker address or None, answer)], in file order."""
    table = {}
    try:
        text = RECORDS.read_text()
    except OSError:
        return table
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, _, value = line.partition(" ")
        name = name.strip().rstrip(".").lower()
        answer, _, asker = value.strip().partition("@")
        if name and answer:
            table.setdefault(name, []).append((asker or None, answer))
    return table


def lookup(table, qname, asker):
    """The answer `qname` gives `asker`: its own line, else the line for everyone."""
    records = table.get(qname, ())
    for who, answer in records:
        if who == asker:
            return answer
    for who, answer in records:
        if who is None:
            return answer
    return None


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
        with QUERIES.open("a") as log:
            log.write(f"{peer[0]} {qname} {qtype}\n")
        print(f"DNS query qname={qname} qtype={qtype} from {peer}", flush=True)
        found = lookup(table, qname, peer[0])
        if found == SILENT:
            continue
        if qtype == T_A and found is not None:
            sock.sendto(answer(ident, qname, found), peer)
        else:
            # Every other query (AAAA included — glibc resolves A and AAAA
            # in parallel) gets NOERROR with zero answers, never silence.
            sock.sendto(nodata(ident, qname, qtype), peer)


if __name__ == "__main__":
    main()
