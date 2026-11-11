import asyncio
import json

from mint_litellm.plugin.policy.opa_client import OPAClient
from mint_litellm.types.reason_codes import Reason

HASH = "a" * 64


def output(version="active", digest=HASH):
    return {
        "decision": "Allow",
        "policy_ids": [],
        "policy_version_id": version,
        "bundle_sha256": digest,
        "obligations": [],
        "observable": False,
        "missing_inputs": [],
    }


async def run_server(replies, *, timeout=1):
    calls = []

    async def handler(reader, writer):
        try:
            headers = await reader.readuntil(b"\r\n\r\n")
            length = next(
                int(line.split(b":", 1)[1])
                for line in headers.split(b"\r\n")
                if line.lower().startswith(b"content-length:")
            )
            calls.append(json.loads(await reader.readexactly(length)))
            reply = replies[min(len(calls) - 1, len(replies) - 1)]
            if reply is None:
                await asyncio.sleep(timeout * 2)
                return
            body = json.dumps({"result": reply}).encode()
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                + str(len(body)).encode()
                + b"\r\nConnection: close\r\n\r\n"
                + body
            )
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(handler, "localhost", 0, family=2)
    host, port = server.sockets[0].getsockname()[:2]
    try:
        client = OPAClient(f"http://{host}:{port}", timeout)
        result = await client.evaluate(
            {"tool": {"name": "example"}}, policy_version_id="active", bundle_sha256=HASH
        )
        return result, calls
    finally:
        server.close()
        await server.wait_closed()


def test_matching_version_returns_result():
    result, calls = asyncio.run(run_server([output()]))
    assert result.output.decision == "Allow"
    assert calls == [{"input": {"tool": {"name": "example"}}}]


def test_version_mismatch_retries_once_and_accepts_matching_result():
    result, calls = asyncio.run(run_server([output("old"), output()]))
    assert result.output.policy_version_id == "active"
    assert len(calls) == 2


def test_hash_mismatch_after_retry_stops():
    result, calls = asyncio.run(run_server([output(digest="b" * 64)]))
    assert result.failure.reason_code == Reason.POLICY_VERSION_MISMATCH
    assert len(calls) == 2


def test_missing_input_stops():
    result, _ = asyncio.run(run_server([{**output(), "missing_inputs": ["tool"]}]))
    assert result.failure.reason_code == Reason.SCHEMA_ERROR


def test_invalid_output_stops():
    result, _ = asyncio.run(run_server([{**output(), "observable": "true"}]))
    assert result.failure.reason_code == Reason.SCHEMA_ERROR


def test_unknown_decision_stops():
    result, _ = asyncio.run(run_server([{**output(), "decision": "Unknown"}]))
    assert result.failure.reason_code == Reason.SCHEMA_ERROR


def test_raw_arguments_are_rejected_before_request():
    async def run():
        return await OPAClient("http://localhost:1", 1).evaluate(
            {"arguments": {"keys": [], "sizes": {}, "values": {"secret": "text"}}},
            policy_version_id="active",
            bundle_sha256=HASH,
        )

    assert asyncio.run(run()).failure.reason_code == Reason.SCHEMA_ERROR


def test_timeout_stops_as_dependency_failure():
    result, _ = asyncio.run(run_server([None], timeout=0.2))
    assert result.failure.reason_code == Reason.DEPENDENCY_FAILURE


def test_connection_failure_stops_as_dependency_failure():
    async def run():
        server = await asyncio.start_server(lambda r, w: None, "localhost", 0, family=2)
        host, port = server.sockets[0].getsockname()[:2]
        server.close()
        await server.wait_closed()
        return await OPAClient(f"http://{host}:{port}", 1).evaluate(
            {}, policy_version_id="active", bundle_sha256=HASH
        )

    assert asyncio.run(run()).failure.reason_code == Reason.DEPENDENCY_FAILURE


def test_the_request_is_compact_utf8_json():
    seen = []

    async def go():
        async def handler(reader, writer):
            headers = await reader.readuntil(b"\r\n\r\n")
            length = next(
                int(line.split(b":", 1)[1])
                for line in headers.split(b"\r\n")
                if line.lower().startswith(b"content-length:")
            )
            seen.append((headers.lower(), await reader.readexactly(length)))
            body = json.dumps({"result": output()}).encode()
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Length: "
                + str(len(body)).encode()
                + b"\r\nConnection: close\r\n\r\n"
                + body
            )
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(handler, "localhost", 0, family=2)
        host, port = server.sockets[0].getsockname()[:2]
        client = OPAClient(f"http://{host}:{port}", 1)
        try:
            await client.evaluate(
                {"tool": {"name": "한글"}}, policy_version_id="active", bundle_sha256=HASH
            )
        finally:
            await client.aclose()
            server.close()
            await server.wait_closed()

    asyncio.run(go())
    ((headers, body),) = seen
    assert b"content-type: application/json" in headers
    assert body == '{"input":{"tool":{"name":"한글"}}}'.encode()
