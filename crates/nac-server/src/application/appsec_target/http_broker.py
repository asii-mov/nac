import json
import os
import socket
import sys


def start_time(pid):
    with open(f"/proc/{pid}/stat", "r", encoding="ascii") as stream:
        return int(stream.read().rsplit(") ", 1)[1].split()[19])


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
    method = request["method"]
    path = request["path"]
    assert method in ("GET", "POST")
    assert path.startswith("/") and not path.startswith("//")
    assert len(path) <= 1024 and all(c not in path for c in "\r\n\0\\#")
    body = request["body"].encode("utf-8")
    actor = request["actor"]
    assert len(body) <= 8192 and len(actor) <= 128
    assert all(c.isascii() and (c.isalnum() or c == "-") for c in actor)
    cap = request["cap"]
    assert isinstance(cap, int) and 1 <= cap <= 16777216
    wire_cap = min(cap * 16, 16777216)
    wire = (f"{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n"
            f"Authorization: Bearer {actor}\r\nConnection: close\r\n"
            f"Content-Length: {len(body)}\r\n\r\n").encode("ascii") + body
    with socket.create_connection(("127.0.0.1", 8080), timeout=2) as connection:
        connection.settimeout(2)
        connection.sendall(wire)
        received = 0
        while received <= wire_cap:
            chunk = connection.recv(min(8192, wire_cap + 1 - received))
            if not chunk:
                break
            sys.stdout.buffer.write(chunk)
            received += len(chunk)


try:
    main()
except Exception:
    sys.exit(2)
