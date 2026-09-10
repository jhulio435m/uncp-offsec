import socket

from mailsec.network import create_connection


class _FakeSocket:
    def __init__(self, family, attempts):
        self.family = family
        self.attempts = attempts

    def settimeout(self, timeout):
        self.timeout = timeout

    def connect(self, address):
        self.attempts.append((self.family, address))
        if self.family == socket.AF_INET6:
            raise OSError("IPv6 unavailable")

    def close(self):
        pass


def test_connection_prefers_ipv4_when_ipv6_has_no_route(monkeypatch):
    addresses = [
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::1", 25, 0, 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 25)),
    ]
    attempts = []
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: addresses)
    monkeypatch.setattr(socket, "socket", lambda family, *a: _FakeSocket(family, attempts))

    connected = create_connection("mx.example", 25, 5)

    assert connected.family == socket.AF_INET
    assert attempts == [(socket.AF_INET, ("192.0.2.1", 25))]
