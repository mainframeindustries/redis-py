import asyncio
import socket
import types
from unittest.mock import patch

import pytest

import redis
from redis.asyncio.connection import (
    Connection,
    PythonParser,
    UnixDomainSocketConnection,
)
from redis.asyncio.retry import Retry
from redis.backoff import NoBackoff
from redis.exceptions import ConnectionError, InvalidResponse, TimeoutError
from tests.conftest import skip_if_server_version_lt

from .compat import mock


@pytest.mark.onlynoncluster
async def test_invalid_response(create_redis):
    r = await create_redis(single_connection_client=True)

    raw = b"x"

    parser: "PythonParser" = r.connection._parser
    if not isinstance(parser, PythonParser):
        pytest.skip("PythonParser only")
    stream_mock = mock.Mock(parser._stream)
    stream_mock.readline.return_value = raw + b"\r\n"
    with mock.patch.object(parser, "_stream", stream_mock):
        with pytest.raises(InvalidResponse) as cm:
            await parser.read_response()
    assert str(cm.value) == f"Protocol Error: {raw!r}"


@skip_if_server_version_lt("4.0.0")
@pytest.mark.redismod
@pytest.mark.onlynoncluster
async def test_loading_external_modules(modclient):
    def inner():
        pass

    modclient.load_external_module("myfuncname", inner)
    assert getattr(modclient, "myfuncname") == inner
    assert isinstance(getattr(modclient, "myfuncname"), types.FunctionType)

    # and call it
    from redis.commands import RedisModuleCommands

    j = RedisModuleCommands.json
    modclient.load_external_module("sometestfuncname", j)

    # d = {'hello': 'world!'}
    # mod = j(modclient)
    # mod.set("fookey", ".", d)
    # assert mod.get('fookey') == d


async def test_socket_param_regression(r):
    """A regression test for issue #1060"""
    conn = UnixDomainSocketConnection()
    _ = await conn.disconnect() is True


async def test_can_run_concurrent_commands(r):
    if getattr(r, "connection", None) is not None:
        # Concurrent commands are only supported on pooled or cluster connections
        # since there is no synchronization on a single connection.
        pytest.skip("pool only")
    assert await r.ping() is True
    assert all(await asyncio.gather(*(r.ping() for _ in range(10))))


async def test_connect_retry_on_timeout_error():
    """Test that the _connect function is retried in case of a timeout"""
    conn = Connection(retry_on_timeout=True, retry=Retry(NoBackoff(), 3))
    origin_connect = conn._connect
    conn._connect = mock.AsyncMock()

    async def mock_connect():
        # connect only on the last retry
        if conn._connect.call_count <= 2:
            raise socket.timeout
        else:
            return await origin_connect()

    conn._connect.side_effect = mock_connect
    await conn.connect()
    assert conn._connect.call_count == 3


async def test_connect_without_retry_on_os_error():
    """Test that the _connect function is not being retried in case of a OSError"""
    with patch.object(Connection, "_connect") as _connect:
        _connect.side_effect = OSError("")
        conn = Connection(retry_on_timeout=True, retry=Retry(NoBackoff(), 2))
        with pytest.raises(ConnectionError):
            await conn.connect()
        assert _connect.call_count == 1


async def test_connect_timeout_error_without_retry():
    """Test that the _connect function is not being retried if retry_on_timeout is
    set to False"""
    conn = Connection(retry_on_timeout=False)
    conn._connect = mock.AsyncMock()
    conn._connect.side_effect = socket.timeout

    with pytest.raises(TimeoutError) as e:
        await conn.connect()
    assert conn._connect.call_count == 1
    assert str(e.value) == "Timeout connecting to server"


class TestError(BaseException):
    pass


class InterruptingReader:
    """
    A class simulating an asyncio input buffer, but raising a
    special exception every other read.
    """

    def __init__(self, data):
        self.data = data
        self.counter = 0
        self.pos = 0

    def tick(self):
        self.counter += 1
        # return
        if (self.counter % 2) == 0:
            raise TestError()

    async def read(self, want):
        self.tick()
        want = 5
        result = self.data[self.pos : self.pos + want]
        self.pos += len(result)
        return result

    async def readline(self):
        self.tick()
        find = self.data.find(b"\n", self.pos)
        if find >= 0:
            result = self.data[self.pos : find + 1]
        else:
            result = self.data[self.pos :]
        self.pos += len(result)
        return result

    async def readexactly(self, length):
        self.tick()
        result = self.data[self.pos : self.pos + length]
        if len(result) < length:
            raise asyncio.IncompleteReadError(result, None)
        self.pos += len(result)
        return result


@pytest.mark.onlynoncluster
async def test_connection_parse_response_resume(r: redis.Redis):
    """
    This test verifies that the Connection parser,
    be that PythonParser or HiredisParser,
    can be interrupted at IO time and then resume parsing.
    """
    conn = Connection(**r.connection_pool.connection_kwargs)
    await conn.connect()
    message = (
        b"*3\r\n$7\r\nmessage\r\n$8\r\nchannel1\r\n"
        b"$25\r\nhi\r\nthere\r\n+how\r\nare\r\nyou\r\n"
    )

    conn._parser._stream = InterruptingReader(message)
    for i in range(100):
        try:
            response = await conn.read_response()
            break
        except TestError:
            pass

    else:
        pytest.fail("didn't receive a response")
    assert response
    assert i > 0
