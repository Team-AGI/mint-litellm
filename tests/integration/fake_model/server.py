"""도구 호출을 요구하는 가짜 모델 서버(OpenAI Responses 형식).

첫 요청에는 ``leak`` 도구를 부르라는 ``function_call``을 돌려주고(인자는 사용자 입력의 JSON),
도구 결과(``function_call_output``)가 들어 있는 두 번째 요청에는 그 결과를 그대로 싣은 메시지를
돌려준다. LiteLLM이 응답 API로 MCP 도구를 자동 실행하는 경로를 시험하는 데만 쓴다.
"""

import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def envelope(output: list[dict]) -> dict:
    return {
        "id": "resp_fake",
        "object": "response",
        "created_at": int(time.time()),
        "status": "completed",
        "model": "fake-model",
        "output": output,
        "parallel_tool_calls": True,
        "tool_choice": "auto",
        "tools": [],
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        "error": None,
        "incomplete_details": None,
    }


def answer(body: dict) -> dict:
    raw = body.get("input")
    items = raw if isinstance(raw, list) else [{"role": "user", "content": raw}]
    outputs = [i.get("output", "") for i in items if i.get("type") == "function_call_output"]
    if outputs:
        text = "tool output: " + " | ".join(str(o) for o in outputs)
        return envelope(
            [
                {
                    "type": "message",
                    "id": "msg_fake",
                    "status": "completed",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": text, "annotations": []}],
                }
            ]
        )
    name = next(
        (t["name"] for t in body.get("tools") or [] if str(t.get("name", "")).endswith("leak")),
        "leak",
    )
    user = next((i.get("content") for i in items if i.get("role") == "user"), "{}")
    return envelope(
        [
            {
                "type": "function_call",
                "id": "fc_fake",
                "call_id": "call_fake",
                "name": name,
                "arguments": user if isinstance(user, str) else json.dumps(user),
                "status": "completed",
            }
        ]
    )


class Handler(BaseHTTPRequestHandler):
    def _send(self, status: int, payload: dict) -> None:
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        self._send(200, {"ok": True})

    def do_POST(self) -> None:
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        if self.path.rstrip("/").endswith("/responses"):
            self._send(200, answer(body))
        else:
            self._send(404, {"error": "unsupported"})

    def log_message(self, *args) -> None:
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("", 9100), Handler).serve_forever()
