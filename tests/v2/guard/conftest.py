"""Default tests never contact a network, regardless of shell credentials."""

import socket

import pytest


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    original_connect = socket.socket.connect
    def denied(*args, **kwargs):
        raise AssertionError("Network is disabled in offline Guard tests")
    def local_event_loop_only(sock, address):
        # Windows asyncio's socketpair implementation needs a loopback socket.
        if isinstance(address, tuple) and address[0] in ("127.0.0.1", "::1"):
            return original_connect(sock, address)
        return denied()
    monkeypatch.setattr(socket, "create_connection", denied)
    monkeypatch.setattr(socket.socket, "connect", local_event_loop_only)
