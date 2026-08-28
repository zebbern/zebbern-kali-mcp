import json
import logging
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from mcp_tools._client import KaliToolsClient


@contextmanager
def running_http_server(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_configured_api_token_is_sent_to_the_real_http_boundary():
    received = {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            received["api_token"] = self.headers.get("X-API-Key")
            body = json.dumps({"success": True}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            return

    with running_http_server(Handler) as server:
        client = KaliToolsClient(
            f"http://127.0.0.1:{server.server_port}",
            timeout=2,
            api_token="client-token",
        )

        result = client.safe_get("probe")

    assert result == {"success": True}
    assert received == {"api_token": "client-token"}


@pytest.mark.parametrize("operation", ["get", "post", "delete", "stream"])
def test_api_token_is_not_forwarded_across_origins(operation):
    received = {"source": [], "target": []}

    class TargetHandler(BaseHTTPRequestHandler):
        def _respond(self):
            received["target"].append(
                {"method": self.command, "api_token": self.headers.get("X-API-Key")}
            )
            body = json.dumps({"success": True}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = _respond
        do_POST = _respond
        do_DELETE = _respond

        def log_message(self, *_args):
            return

    with running_http_server(TargetHandler) as target_server:
        target_url = f"http://127.0.0.1:{target_server.server_port}/finish"

        class RedirectHandler(BaseHTTPRequestHandler):
            def _redirect(self):
                content_length = int(self.headers.get("Content-Length", "0"))
                if content_length:
                    self.rfile.read(content_length)
                received["source"].append(
                    {"method": self.command, "api_token": self.headers.get("X-API-Key")}
                )
                self.send_response(302)
                self.send_header("Location", target_url)
                self.send_header("Content-Length", "0")
                self.end_headers()

            do_GET = _redirect
            do_POST = _redirect
            do_DELETE = _redirect

            def log_message(self, *_args):
                return

        with running_http_server(RedirectHandler) as source_server:
            client = KaliToolsClient(
                f"http://127.0.0.1:{source_server.server_port}",
                timeout=2,
                api_token="client-token",
            )

            if operation == "get":
                result = client.safe_get("start")
            elif operation == "post":
                result = client.safe_post("start", {"value": "test"})
            elif operation == "delete":
                result = client.safe_delete("start")
            else:
                response = client.request(
                    "POST", "start", json={"value": "test"}, stream=True
                )
                try:
                    response.raise_for_status()
                    result = response.json()
                finally:
                    response.close()

    assert result == {"success": True}
    assert received["source"] == [
        {
            "method": operation.upper() if operation != "stream" else "POST",
            "api_token": "client-token",
        }
    ]
    assert received["target"] == [{"method": "GET", "api_token": None}]


def test_api_token_is_preserved_for_same_origin_redirects():
    received = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            received.append((self.path, self.headers.get("X-API-Key")))
            if self.path == "/start":
                self.send_response(302)
                self.send_header("Location", "/finish")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

            body = json.dumps({"success": True}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            return

    with running_http_server(Handler) as server:
        client = KaliToolsClient(
            f"http://127.0.0.1:{server.server_port}",
            timeout=2,
            api_token="client-token",
        )

        result = client.safe_get("start")

    assert result == {"success": True}
    assert received == [("/start", "client-token"), ("/finish", "client-token")]


def test_cross_origin_redirect_cannot_forward_post_body():
    received_bodies = []

    class TargetHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            received_bodies.append(self.rfile.read(length))
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_args):
            return

    with running_http_server(TargetHandler) as target_server:
        target_url = f"http://127.0.0.1:{target_server.server_port}/finish"

        class RedirectHandler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                self.rfile.read(length)
                self.send_response(307)
                self.send_header("Location", target_url)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *_args):
                return

        with running_http_server(RedirectHandler) as source_server:
            client = KaliToolsClient(
                f"http://127.0.0.1:{source_server.server_port}",
                timeout=2,
                api_token="client-token",
            )
            result = client.safe_post("start", {"password": "body-secret"})

    assert result["success"] is False
    assert received_bodies == []


def test_debug_logs_exclude_query_values_and_json_bodies(caplog):
    class Handler(BaseHTTPRequestHandler):
        def _respond(self):
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length:
                self.rfile.read(content_length)
            body = json.dumps({"success": True}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = _respond
        do_POST = _respond

        def log_message(self, *_args):
            return

    with running_http_server(Handler) as server:
        client = KaliToolsClient(
            f"http://127.0.0.1:{server.server_port}", timeout=2
        )
        with caplog.at_level(logging.DEBUG, logger="mcp_tools._client"):
            assert client.safe_get("probe", {"api_key": "query-secret"}) == {
                "success": True
            }
            assert client.safe_post("probe", {"password": "body-secret"}) == {
                "success": True
            }

    messages = "\n".join(record.getMessage() for record in caplog.records)
    assert "query-secret" not in messages
    assert "body-secret" not in messages
    assert "GET /probe -> 200" in messages
    assert "POST /probe -> 200" in messages


def test_http_error_logs_exclude_query_values(caplog):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(500)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_args):
            return

    with running_http_server(Handler) as server:
        client = KaliToolsClient(
            f"http://127.0.0.1:{server.server_port}", timeout=2
        )
        with caplog.at_level(logging.ERROR, logger="mcp_tools._client"):
            result = client.safe_get("probe", {"api_key": "error-secret"})

    assert result["success"] is False
    assert "error-secret" not in caplog.text


def test_stream_response_remains_readable_after_request_returns():
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = b'data: {"type":"complete"}\n\n'
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            return

    with running_http_server(Handler) as server:
        client = KaliToolsClient(
            f"http://127.0.0.1:{server.server_port}", timeout=2
        )
        response = client.request("POST", "stream", stream=True)
        try:
            lines = list(response.iter_lines(decode_unicode=True))
        finally:
            response.close()

    assert lines == ['data: {"type":"complete"}', ""]
