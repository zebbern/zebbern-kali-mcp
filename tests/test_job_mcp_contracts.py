from mcp_tools import command_exec


class RecordingMCP:
    def __init__(self):
        self.tools = {}

    def tool(self):
        def register(function):
            self.tools[function.__name__] = function
            return function

        return register


class RecordingClient:
    server_url = "http://127.0.0.1:5000"

    def __init__(self):
        self.calls = []

    def safe_get(self, endpoint, params=None):
        call = {"method": "GET", "endpoint": endpoint, "params": params or {}}
        self.calls.append(call)
        return call

    def safe_post(self, endpoint, json_data):
        call = {"method": "POST", "endpoint": endpoint, "json": json_data}
        self.calls.append(call)
        return call

    def request(self, method, endpoint, **kwargs):
        call = {"method": method, "endpoint": endpoint, **kwargs}
        self.calls.append(call)

        class Response:
            headers = {"Content-Type": "text/event-stream"}

            @staticmethod
            def raise_for_status():
                return None

            @staticmethod
            def iter_lines(decode_unicode=False):
                assert decode_unicode is True
                yield 'data: {"type":"result","success":true,"return_code":0}'
                yield 'data: {"type":"complete"}'

        return Response()

    def request_headers(self, additional=None):
        return additional or {}

    def check_health(self):
        return {"status": "healthy"}


def registered_tools():
    mcp = RecordingMCP()
    client = RecordingClient()
    command_exec.register(mcp, client)
    return mcp.tools, client


def test_job_management_tools_use_job_endpoints():
    tools, _client = registered_tools()

    assert tools["job_status"]("job-1") == {
        "method": "GET",
        "endpoint": "api/jobs/job-1",
        "params": {},
    }
    assert tools["job_output"]("job-1", timeout=3, lines=25) == {
        "method": "GET",
        "endpoint": "api/jobs/job-1/output",
        "params": {"timeout": 3, "lines": 25},
    }
    assert tools["job_cancel"]("job-1") == {
        "method": "POST",
        "endpoint": "api/jobs/job-1/cancel",
        "json": {},
    }


def test_legacy_interactive_tools_target_the_trackable_job_service():
    tools, _client = registered_tools()

    assert tools["send_input"]("job-1", "whoami\n") == {
        "method": "POST",
        "endpoint": "api/jobs/job-1/input",
        "json": {"input": "whoami\n", "type": "auto"},
    }
    assert tools["read_output"]("job-1", timeout=2, lines=12) == {
        "method": "GET",
        "endpoint": "api/jobs/job-1/output",
        "params": {"timeout": 2, "lines": 12},
    }


def test_streaming_exec_uses_the_redirect_safe_client_request():
    tools, client = registered_tools()

    result = tools["exec_stream"]("nmap target", timeout=45)

    assert result == {
        "success": True,
        "output": "",
        "return_code": 0,
        "timed_out": False,
        "streamed": True,
    }
    assert client.calls == [{
        "method": "POST",
        "endpoint": "api/command",
        "json": {
            "command": "nmap target",
            "streaming": True,
            "timeout": 45,
        },
        "headers": {"Accept": "text/event-stream"},
        "stream": True,
        "timeout": (10, 45),
    }]
