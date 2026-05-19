from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import urllib.parse
from typing import Any


HTTP_SCHEMES = {"http", "https"}
PRIVATE_NETWORK_MESSAGE = "private, loopback, reserved, and link-local hosts require --allow-private-network"

_SIX_TO_FOUR_NET = ipaddress.IPv6Network("2002::/16")
_TEREDO_NET = ipaddress.IPv6Network("2001::/32")


class UrlPolicyError(Exception):
    """Raised when a URL is rejected by the network policy."""


def is_restricted_ip(address: str) -> bool:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    if isinstance(parsed, ipaddress.IPv6Address):
        if parsed.ipv4_mapped is not None:
            parsed = parsed.ipv4_mapped
        elif parsed in _SIX_TO_FOUR_NET or parsed in _TEREDO_NET:
            return True
    return parsed.is_private or parsed.is_loopback or parsed.is_link_local or parsed.is_reserved or parsed.is_multicast or parsed.is_unspecified


def _resolve_addresses(hostname: str, port: int) -> list[tuple[int, str]]:
    try:
        infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as error:
        raise UrlPolicyError("hostname could not be resolved") from error
    return [(info[0], info[4][0]) for info in infos]


def _parse_and_validate(url: str, allow_private_network: bool) -> tuple[urllib.parse.ParseResult, str, int, list[tuple[int, str]]]:
    try:
        parsed = urllib.parse.urlparse(url)
    except ValueError as error:
        raise UrlPolicyError("URL is malformed") from error
    if parsed.scheme not in HTTP_SCHEMES or not parsed.netloc:
        raise UrlPolicyError("URL must use http or https")
    try:
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as error:
        raise UrlPolicyError("URL is malformed") from error
    if not hostname:
        raise UrlPolicyError("URL must include a hostname")
    if not allow_private_network and (hostname.lower() == "localhost" or hostname.lower().endswith(".localhost")):
        raise UrlPolicyError(PRIVATE_NETWORK_MESSAGE)
    addresses = _resolve_addresses(hostname, port)
    if not allow_private_network:
        if any(is_restricted_ip(address) for _family, address in addresses):
            raise UrlPolicyError(PRIVATE_NETWORK_MESSAGE)
    return parsed, hostname, port, addresses


def validate_http_url(url: str, allow_private_network: bool = False) -> str | None:
    try:
        _parse_and_validate(url, allow_private_network)
    except UrlPolicyError as error:
        return str(error)
    return None


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, *, pinned_ip: str, timeout: float):
        super().__init__(host, port, timeout=timeout)
        self._pinned_ip = pinned_ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self._pinned_ip, self.port), timeout=self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, *, pinned_ip: str, timeout: float, context: ssl.SSLContext):
        super().__init__(host, port, timeout=timeout, context=context)
        self._pinned_ip = pinned_ip

    def connect(self) -> None:
        sock = socket.create_connection((self._pinned_ip, self.port), timeout=self.timeout)
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()
            sock = self.sock
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def open_url(
    url: str,
    *,
    allow_private_network: bool = False,
    timeout: float = 10.0,
    method: str = "GET",
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> http.client.HTTPResponse:
    """Open an HTTP(S) URL with a pinned, pre-validated IP to defeat DNS rebinding.

    The caller is responsible for closing the returned response (or its connection).
    """
    parsed, hostname, port, addresses = _parse_and_validate(url, allow_private_network)
    _, pinned_ip = addresses[0]

    request_headers: dict[str, str] = {}
    if headers:
        for key, value in headers.items():
            if key.lower() == "host":
                continue
            request_headers[key] = value
    if data is not None and not any(key.lower() == "content-length" for key in request_headers):
        request_headers["Content-Length"] = str(len(data))

    selector = parsed.path or "/"
    if parsed.query:
        selector = f"{selector}?{parsed.query}"

    if parsed.scheme == "https":
        connection: http.client.HTTPConnection = _PinnedHTTPSConnection(
            hostname,
            port,
            pinned_ip=pinned_ip,
            timeout=timeout,
            context=ssl.create_default_context(),
        )
    else:
        connection = _PinnedHTTPConnection(hostname, port, pinned_ip=pinned_ip, timeout=timeout)

    try:
        connection.request(method.upper(), selector, body=data, headers=request_headers)
        return connection.getresponse()
    except Exception:
        connection.close()
        raise


def http_get_json(url: str, *, allow_private_network: bool, timeout: float, user_agent: str) -> Any:
    import json as _json

    response = open_url(url, allow_private_network=allow_private_network, timeout=timeout, headers={"User-Agent": user_agent})
    try:
        body = response.read(10_000_000)
    finally:
        response.close()
    return _json.loads(body.decode("utf-8"))


def http_post_json(url: str, payload: Any, *, allow_private_network: bool, timeout: float, user_agent: str) -> Any:
    import json as _json

    data = _json.dumps(payload).encode("utf-8")
    response = open_url(
        url,
        allow_private_network=allow_private_network,
        timeout=timeout,
        method="POST",
        data=data,
        headers={"User-Agent": user_agent, "Content-Type": "application/json"},
    )
    try:
        body = response.read(10_000_000)
    finally:
        response.close()
    return _json.loads(body.decode("utf-8"))
