"""Network helpers that tolerate container hosts without an IPv6 route."""

from __future__ import annotations

import socket


def create_connection(host: str, port: int, timeout: float) -> socket.socket:
    """Connect using IPv4 first, then other resolved families as fallback."""
    addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    addresses.sort(key=lambda item: 0 if item[0] == socket.AF_INET else 1)
    failures: list[str] = []
    for family, socktype, proto, _canonical, address in addresses:
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(timeout)
        try:
            sock.connect(address)
            return sock
        except OSError as exc:
            failures.append(f"{address[0]}: {exc}")
            sock.close()
    detail = "; ".join(failures[-4:]) or "no address returned"
    raise OSError(f"cannot connect to {host}:{port}: {detail}")
