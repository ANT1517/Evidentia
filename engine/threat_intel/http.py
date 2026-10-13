"""HTTP layer: injectable transport plus an origin-guarded client.

Guarantees, enforced here rather than trusted to each provider:
  * only https URLs whose origin is in the configured allow-list are ever requested
  * redirects are never followed (a 3xx is surfaced and refused)
  * TLS certificates and host names are verified (default SSL context)
  * response bodies are size-capped
Nothing from a message can name a host: providers build URLs from configured origins and
put indicator values only in the path/body, after validation.
"""
from __future__ import annotations

import http.client
import socket
import ssl
from dataclasses import dataclass, field
from typing import Mapping, Optional, Protocol
from urllib.parse import urlsplit


@dataclass(frozen=True)
class HttpRequest:
    method: str
    url: str
    headers: Mapping[str, str] = field(default_factory=dict, repr=False)   # may hold API keys
    body: Optional[bytes] = field(default=None, repr=False)                  # may hold indicators


@dataclass(frozen=True)
class HttpResponse:
    status: int
    body: bytes = b""
    headers: Mapping[str, str] = field(default_factory=dict)
    truncated: bool = False


class TransportError(Exception):
    """kind: 'timeout' or 'network'. The message never includes URLs or headers."""

    def __init__(self, kind: str, detail: str = "") -> None:
        super().__init__(f"{kind}: {detail}")
        self.kind = kind


class OriginNotAllowed(Exception):
    pass


class Transport(Protocol):
    def request(self, req: HttpRequest, *, timeout: float, max_bytes: int) -> HttpResponse: ...


class StdlibTransport:
    """Blocking transport on http.client. Never follows redirects; verifies TLS."""

    def request(self, req: HttpRequest, *, timeout: float, max_bytes: int) -> HttpResponse:
        parts = urlsplit(req.url)
        if parts.scheme != "https" or not parts.hostname:
            raise TransportError("network", "only https is supported")
        ctx = ssl.create_default_context()          # CERT_REQUIRED + check_hostname
        conn = http.client.HTTPSConnection(
            parts.hostname, parts.port or 443, timeout=timeout, context=ctx
        )
        try:
            target = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
            conn.request(req.method, target, body=req.body, headers=dict(req.headers))
            resp = conn.getresponse()
            data = resp.read(max_bytes + 1)
            return HttpResponse(
                status=resp.status,
                body=data[:max_bytes],
                headers={k.lower(): v for k, v in resp.getheaders()},
                truncated=len(data) > max_bytes,
            )
        except (socket.timeout, TimeoutError) as e:
            raise TransportError("timeout", type(e).__name__) from None
        except (OSError, http.client.HTTPException) as e:   # includes ssl.SSLError
            raise TransportError("network", type(e).__name__) from None
        finally:
            conn.close()


class GuardedClient:
    """Wraps a Transport and refuses anything outside the configured provider origins."""

    def __init__(self, transport: Transport, allowed_origins: frozenset, max_bytes: int) -> None:
        self._transport = transport
        self._allowed = frozenset(o.rstrip("/").lower() for o in allowed_origins)
        self._max_bytes = max_bytes

    def send(self, req: HttpRequest, timeout: float) -> HttpResponse:
        parts = urlsplit(req.url)
        origin = f"{parts.scheme}://{parts.netloc}".lower()
        if parts.scheme != "https" or "@" in parts.netloc or origin not in self._allowed:
            raise OriginNotAllowed("request target is not a configured provider origin")
        return self._transport.request(req, timeout=timeout, max_bytes=self._max_bytes)
