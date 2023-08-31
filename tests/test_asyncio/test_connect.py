import asyncio
import itertools
import logging
import re
import socket
import ssl

import pytest
from redis.asyncio import ResponseError
from redis.asyncio.connection import (
    Connection,
    SSLConnection,
    UnixDomainSocketConnection,
)

from ..ssl_utils import get_ssl_filename

_logger = logging.getLogger(__name__)


_CLIENT_NAME = "test-suite-client"
_CMD_SEP = b"\r\n"
_SUCCESS_RESP = b"+OK" + _CMD_SEP
_ERROR_RESP = b"-ERR" + _CMD_SEP
_SUPPORTED_CMDS = {f"CLIENT SETNAME {_CLIENT_NAME}": _SUCCESS_RESP}


# Emulate initial handshake, AUTH and HELLO commands
server_ver = 5
got_auth = []


def handle_auth(parts, hello=False):
    global got_auth
    assert parts[0] == "AUTH"
    auth = parts[1:]
    got_auth = auth
    expect = 2 if hello or server_ver >= 6 else 1
    if len(auth) != expect:
        return b"-ERR wrong number of arguments for 'auth' command" + _CMD_SEP
    return _SUCCESS_RESP


def handle_setname(parts):
    assert parts[0] == "SETNAME"
    assert len(parts) == 2
    return _SUCCESS_RESP


def handle_hello(parts):
    global got_protocol
    assert parts.pop(0) == "HELLO"
    if server_ver < 6:
        return _ERROR_RESP
    try:
        got_protocol = int(parts[0])
        del parts[0]
    except ValueError:
        got_protocol = None
    if parts and parts[0] == "AUTH":
        res = handle_auth(parts[:3], True)
        del parts[:3]
        if res != _SUCCESS_RESP:
            return res
    if parts and parts[0] == "SETNAME":
        res = handle_setname(parts[:2])
        del parts[:3]

    proto = got_protocol if got_protocol is not None else 2
    proto = min(proto, 3)
    result = {"server": "redistester", "version": "0.0.1", "proto": proto}
    response = resp_encode(result, proto)
    return response.encode("ascii")


def resp_encode(data, ver):
    if isinstance(data, dict):
        if ver == 3:
            result = f"%{len(data)}\r\n"
            for key, val in data.items():
                result += resp_encode(key, ver) + resp_encode(val, ver)
            return result
        else:
            mylist = list(itertools.chain(*((key, val) for (key, val) in data.items())))
            return resp_encode(mylist, ver)
    elif isinstance(data, list):
        result = f"*{len(data)}\r\n"
        for val in data:
            result += resp_encode(val, ver)
        return result
    elif isinstance(data, str):
        return f"+{data}\r\n"
    elif isinstance(data, int):
        return f":{data}\r\n"
    else:
        raise NotImplementedError


_SUPPORTED_CMDS_X = {
    "HELLO": handle_hello,
    "AUTH": handle_auth,
}


@pytest.fixture
def tcp_address():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()


@pytest.fixture
def uds_address(tmpdir):
    return tmpdir / "uds.sock"


async def test_tcp_connect(tcp_address):
    host, port = tcp_address
    conn = Connection(host=host, port=port, client_name=_CLIENT_NAME, socket_timeout=10)
    await _assert_connect(conn, tcp_address)


async def test_uds_connect(uds_address):
    path = str(uds_address)
    conn = UnixDomainSocketConnection(
        path=path, client_name=_CLIENT_NAME, socket_timeout=10
    )
    await _assert_connect(conn, path)


@pytest.mark.parametrize(
    ("use_server_ver", "use_protocol", "use_auth", "use_client_name"),
    [
        (5, 2, False, True),
        (5, 2, True, True),
        (5, 3, True, True),
        (6, 2, False, True),
        (6, 2, True, True),
        (6, 3, False, False),
        (6, 3, True, False),
        (6, 3, False, True),
        (6, 3, True, True),
    ],
)
# @pytest.mark.parametrize("use_protocol", [2, 3])
# @pytest.mark.parametrize("use_auth", [False, True])
async def test_tcp_auth(
    tcp_address, use_protocol, use_auth, use_server_ver, use_client_name
):
    """
    Test that various initial handshake cases are handled correctly by the client
    """
    global server_ver
    global got_protocol
    global got_auth
    host, port = tcp_address
    server_ver = use_server_ver

    if use_auth:
        auth_args = {"username": "myuser", "password": "mypassword"}
    else:
        auth_args = {}
    got_auth = None
    got_protocol = None
    conn = Connection(
        host=host,
        port=port,
        client_name=_CLIENT_NAME if use_client_name else None,
        socket_timeout=10,
        protocol=use_protocol,
        **auth_args,
    )
    try:
        if use_server_ver < 6 and use_protocol > 2:
            with pytest.raises(ResponseError):
                await _assert_connect(conn, tcp_address)
            return

        await _assert_connect(conn, tcp_address)
        if use_protocol == 3:
            assert got_protocol == use_protocol
        if use_auth:
            if use_server_ver < 6:
                assert got_auth == ["mypassword"]
            else:
                assert got_auth == ["myuser", "mypassword"]
    finally:
        await conn.disconnect()


@pytest.mark.ssl
async def test_tcp_ssl_connect(tcp_address):
    host, port = tcp_address
    certfile = get_ssl_filename("server-cert.pem")
    keyfile = get_ssl_filename("server-key.pem")
    conn = SSLConnection(
        host=host,
        port=port,
        client_name=_CLIENT_NAME,
        ssl_ca_certs=certfile,
        socket_timeout=10,
    )
    await _assert_connect(conn, tcp_address, certfile=certfile, keyfile=keyfile)
    await conn.disconnect()


async def _assert_connect(conn, server_address, certfile=None, keyfile=None):
    stop_event = asyncio.Event()
    finished = asyncio.Event()

    async def _handler(reader, writer):
        try:
            return await _redis_request_handler(reader, writer, stop_event)
        finally:
            finished.set()

    if isinstance(server_address, str):
        server = await asyncio.start_unix_server(_handler, path=server_address)
    elif certfile:
        host, port = server_address
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certfile=certfile, keyfile=keyfile)
        server = await asyncio.start_server(_handler, host=host, port=port, ssl=context)
    else:
        host, port = server_address
        server = await asyncio.start_server(_handler, host=host, port=port)

    async with server as aserver:
        await aserver.start_serving()
        try:
            await conn.connect()
            await conn.disconnect()
        finally:
            stop_event.set()
            aserver.close()
            await aserver.wait_closed()
            await finished.wait()


async def _redis_request_handler(reader, writer, stop_event):
    buffer = b""
    command = None
    command_ptr = None
    fragment_length = None
    while not stop_event.is_set() or buffer:
        _logger.info(str(stop_event.is_set()))
        try:
            buffer += await asyncio.wait_for(reader.read(1024), timeout=0.5)
        except TimeoutError:
            continue
        if not buffer:
            continue
        parts = re.split(_CMD_SEP, buffer)
        buffer = parts[-1]
        for fragment in parts[:-1]:
            fragment = fragment.decode()
            _logger.info("Command fragment: %s", fragment)

            if fragment.startswith("*") and command is None:
                command = [None for _ in range(int(fragment[1:]))]
                command_ptr = 0
                fragment_length = None
                continue

            if fragment.startswith("$") and command[command_ptr] is None:
                fragment_length = int(fragment[1:])
                continue

            assert len(fragment) == fragment_length
            command[command_ptr] = fragment
            command_ptr += 1

            if command_ptr < len(command):
                continue

            command = " ".join(command)
            _logger.info("Command %s", command)
            parts = command.split()
            if parts[0] in _SUPPORTED_CMDS_X:
                resp = _SUPPORTED_CMDS_X[parts[0]](parts)
            else:
                resp = _SUPPORTED_CMDS.get(command, _ERROR_RESP)
            _logger.info("Response from %s", resp)
            writer.write(resp)
            await writer.drain()
            command = None
    _logger.info("Exit handler")
