"""Shared helpers for API route blueprints."""

import json as _json
import queue
import threading
from flask import Response, stream_with_context


def sse_response(generator):
    """Proper SSE content type + disable buffering so events flush immediately."""
    return Response(
        stream_with_context(generator),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


def streaming_tool_response(run_func, params):
    """Generic streaming SSE response for tool endpoints (gobuster, nikto, etc).

    Deduplicates the identical streaming boilerplate used by multiple tools.
    """
    output_queue = queue.Queue()

    def generate_output():
        def handle_output(source, line):
            escaped = _json.dumps(line)[1:-1]
            output_queue.put(
                f'data: {{"type": "output", "source": "{source}", "line": "{escaped}"}}\n\n'
            )

        result_container = {}

        def execute_in_thread():
            try:
                result = run_func(params, on_output=handle_output)
                result_container["result"] = result
            except Exception as e:
                result_container["error"] = str(e)
            finally:
                output_queue.put("DONE")

        thread = threading.Thread(target=execute_in_thread)
        thread.start()

        while True:
            try:
                item = output_queue.get(timeout=1)
                if item == "DONE":
                    break
                yield item
            except queue.Empty:
                yield 'data: {"type": "heartbeat"}\n\n'
                continue

        thread.join()

        if "result" in result_container:
            r = result_container["result"]
            yield (
                f'data: {{"type": "result", "success": {str(r["success"]).lower()}, '
                f'"return_code": {r.get("return_code", 0)}}}\n\n'
            )
        elif "error" in result_container:
            yield (
                f'data: {{"type": "error", "message": '
                f'"Server error: {result_container["error"]}"}}\n\n'
            )

        yield 'data: {"type": "complete"}\n\n'

    return Response(
        stream_with_context(generate_output()),
        content_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
