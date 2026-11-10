"""데이터베이스 접속이 끊겼다 돌아온 직후, 풀에 남은 끊긴 연결이 판정을 막지 않는다."""

import asyncio
import os
import socket

import pytest

psycopg = pytest.importorskip("psycopg")
pytest.importorskip("psycopg_pool")

from psycopg.conninfo import conninfo_to_dict, make_conninfo  # noqa: E402

from mint_litellm.plugin.snapshot import PluginDatabase  # noqa: E402

ADMIN_URL = os.environ.get("MINT_TEST_DATABASE_URL")
LOOPBACK = socket.gethostbyname("localhost")


class Relay:
    """접속을 끊고 다시 여는 TCP 중계. 끊을 때 열려 있던 연결을 모두 닫는다."""

    def __init__(self, host, port):
        self.target = (host, port)
        self.server = None
        self.writers = set()

    async def start(self, port=0):
        self.server = await asyncio.start_server(self.handle, LOOPBACK, port)
        return self.server.sockets[0].getsockname()[1]

    async def handle(self, reader, writer):
        try:
            upstream_reader, upstream_writer = await asyncio.open_connection(*self.target)
        except OSError:
            writer.close()
            return
        self.writers |= {writer, upstream_writer}

        async def pipe(source, sink):
            try:
                while data := await source.read(65536):
                    sink.write(data)
                    await sink.drain()
            except OSError:
                pass
            finally:
                sink.close()

        await asyncio.gather(pipe(reader, upstream_writer), pipe(upstream_reader, writer))

    async def cut(self):
        self.server.close()
        for writer in list(self.writers):
            writer.close()
        self.writers.clear()
        await asyncio.sleep(0.05)


async def probe(db):
    async def work(conn):
        return (await (await conn.execute("SELECT 1")).fetchone())[0]

    try:
        return await db._run(work)
    except Exception as exc:
        return type(exc).__name__


def test_calls_right_after_the_database_returns_are_not_blocked_by_dead_pool_connections():
    if not ADMIN_URL:
        pytest.skip("MINT_TEST_DATABASE_URL is not set")
    params = conninfo_to_dict(ADMIN_URL)
    relay = Relay(params.get("host", LOOPBACK), int(params.get("port", 5432)))

    async def go():
        port = await relay.start()
        dsn = make_conninfo(**{**params, "host": LOOPBACK, "port": port})
        db = PluginDatabase(dsn, acquire_timeout=1.0)
        try:
            assert await asyncio.gather(*(probe(db) for _ in range(8))) == [1] * 8
            await relay.cut()
            assert await probe(db) != 1
            await relay.start(port)
            return await asyncio.gather(*(probe(db) for _ in range(8)))
        finally:
            await db.close()
            await relay.cut()

    assert asyncio.run(go(), loop_factory=asyncio.SelectorEventLoop) == [1] * 8
