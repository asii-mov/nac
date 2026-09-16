import errno
import ipaddress
import json
import os
import socket
import sys


def start_time(pid):
    with open(f"/proc/{pid}/stat", "r", encoding="ascii") as stream:
        return int(stream.read().rsplit(") ", 1)[1].split()[19])


def has_route(address):
    target = ipaddress.ip_address(address)
    if target.version == 4:
        with open("/proc/net/route", "r", encoding="ascii") as stream:
            for line in stream.read().splitlines()[1:]:
                fields = line.split()
                if len(fields) < 8 or not int(fields[3], 16) & 1:
                    continue
                network = ipaddress.IPv4Address(
                    int(fields[1], 16).to_bytes(4, "little")
                )
                mask = ipaddress.IPv4Address(
                    int(fields[7], 16).to_bytes(4, "little")
                )
                if target in ipaddress.IPv4Network(
                    (str(network), str(mask)), strict=False
                ):
                    return True
        return False
    with open("/proc/net/ipv6_route", "r", encoding="ascii") as stream:
        for line in stream:
            fields = line.split()
            if len(fields) < 10 or int(fields[8], 16) & 0x200:
                continue
            network = ipaddress.IPv6Network(
                (int(fields[0], 16), int(fields[1], 16)), strict=False
            )
            if target in network:
                return True
    return False


def denied_connection(address):
    assert not has_route(address)
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as connection:
            connection.settimeout(1)
            connection.connect((address, 9))
    except OSError as error:
        assert error.errno in {
            errno.EADDRNOTAVAIL,
            errno.ENETDOWN,
            errno.ENETUNREACH,
            errno.EHOSTUNREACH,
        }
        return
    raise AssertionError("network connection unexpectedly succeeded")


def main():
    request = json.loads(sys.stdin.buffer.read(32769))
    pid = request["pid"]
    assert isinstance(pid, int) and pid > 1
    assert start_time(pid) == request["start_time"]
    descriptor = os.open(f"/proc/{pid}/ns/net", os.O_RDONLY)
    assert start_time(pid) == request["start_time"]
    os.setns(descriptor, 0)
    os.close(descriptor)
    os.setgroups([])
    os.setgid(65534)
    os.setuid(65534)
    assert os.getuid() == 65534 and os.geteuid() == 65534
    for address in request["addresses"]:
        denied_connection(address)
    try:
        socket.getaddrinfo("example.com", 9)
    except OSError:
        pass
    else:
        raise AssertionError("external DNS unexpectedly succeeded")
    sys.stdout.write("adapter-network-denied")


try:
    main()
except Exception:
    sys.exit(2)
