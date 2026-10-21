"""Inject a checksummed, out-of-window RST into the isolated test connection."""

import socket
import struct
import sys


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


source = socket.inet_aton("10.77.0.1")
destination = socket.inet_aton("10.77.0.2")
tcp = struct.pack("!HHIIBBHHH", 9000, int(sys.argv[1]), 0, 0, 0x50, 4, 0, 0, 0)
pseudo = source + destination + struct.pack("!BBH", 0, socket.IPPROTO_TCP, len(tcp))
tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp)) + tcp[18:]
ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 0, 0, 64, socket.IPPROTO_TCP, 0, source, destination)
ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
assert checksum(ip) == 0 and checksum(pseudo + tcp) == 0
with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as sock:
    sock.sendto(ip + tcp, ("10.77.0.2", 0))
