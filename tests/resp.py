import itertools
from contextlib import closing
from types import NoneType
from typing import Any, Generator, List, Optional, Tuple, Union

CRNL = b"\r\n"


class VerbatimStr(str):
    """
    A string that is encoded as a resp3 verbatim string
    """

    def __new__(cls, value: str, hint: str) -> "VerbatimStr":
        return str.__new__(cls, value)

    def __init__(self, value: str, hint: str) -> None:
        self.hint = hint

    def __repr__(self) -> str:
        return f"VerbatimStr({super().__repr__()}, {self.hint!r})"


class ErrorStr(str):
    """
    A string to be encoded as a resp3 error
    """

    def __new__(cls, code: str, value: str) -> "ErrorStr":
        return str.__new__(cls, value)

    def __init__(self, code: str, value: str) -> None:
        self.code = code.upper()

    def __repr__(self) -> str:
        return f"ErrorString({self.code!r}, {super().__repr__()})"

    def __str__(self):
        return f"{self.code} {super().__str__()}"


class PushData(list):
    """
    A special type of list indicating data from a push response
    """

    def __repr__(self) -> str:
        return f"PushData({super().__repr__()})"


class Attribute(dict):
    """
    A special type of map indicating data from a attribute response
    """

    def __repr__(self) -> str:
        return f"Attribute({super().__repr__()})"


class RespEncoder:
    """
    A class for simple RESP protocol encoder for unit tests
    """

    def __init__(
        self, protocol: int = 2, encoding: str = "utf-8", errorhander="strict"
    ) -> None:
        self.protocol = protocol
        self.encoding = encoding
        self.errorhandler = errorhander

    def apply_encoding(self, value: str) -> bytes:
        return value.encode(self.encoding, errors=self.errorhandler)

    def has_crnl(self, value: bytes) -> bool:
        """check if either cr or nl is in the value"""
        return b"\r" in value or b"\n" in value

    def escape_crln(self, value: bytes) -> bytes:
        """remove any cr or nl from the value"""
        return value.replace(b"\r", b"\\r").replace(b"\n", b"\\n")

    def encode(self, data: Any, hint: Optional[str] = None) -> bytes:
        if isinstance(data, dict):
            if self.protocol > 2:
                code = "|" if isinstance(data, Attribute) else "%"
                result = f"{code}{len(data)}\r\n".encode()
                for key, val in data.items():
                    result += self.encode(key) + self.encode(val)
                return result
            else:
                # Automatically encode dicts as flattened key, value arrays
                mylist = list(
                    itertools.chain(*((key, val) for (key, val) in data.items()))
                )
                return self.encode(mylist)

        elif isinstance(data, list):
            code = ">" if isinstance(data, PushData) and self.protocol > 2 else "*"
            result = f"{code}{len(data)}\r\n".encode()
            for val in data:
                result += self.encode(val)
            return result

        elif isinstance(data, set):
            if self.protocol > 2:
                result = f"~{len(data)}\r\n".encode()
                for val in data:
                    result += self.encode(val)
                return result
            else:
                return self.encode(list(data))

        elif isinstance(data, ErrorStr):
            enc = self.apply_encoding(str(data))
            if self.protocol > 2:
                if len(enc) > 80 or self.has_crnl(enc):
                    return f"!{len(enc)}\r\n".encode() + enc + b"\r\n"
            return b"-" + self.escape_crln(enc) + b"\r\n"

        elif isinstance(data, str):
            enc = self.apply_encoding(data)
            # long strings or strings with control characters must be encoded as bulk
            # strings
            if hint or len(enc) > 80 or self.has_crnl(enc):
                return self.encode_bulkstr(enc, hint)
            return b"+" + enc + b"\r\n"

        elif isinstance(data, bytes):
            return self.encode_bulkstr(data, hint)

        elif isinstance(data, bool):
            if self.protocol == 2:
                return b":1\r\n" if data else b":0\r\n"
            return b"t\r\n" if data else b"f\r\n"

        elif isinstance(data, int):
            if (data > 2**63 - 1) or (data < -(2**63)):
                if self.protocol > 2:
                    return f"({data}\r\n".encode()  # resp3 big int
                return f"+{data}\r\n".encode()  # force to simple string
            return f":{data}\r\n".encode()
        elif isinstance(data, float):
            if self.protocol > 2:
                return f",{data}\r\n".encode()  # resp3 double
            return f"+{data}\r\n".encode()  # simple string

        elif isinstance(data, NoneType):
            if self.protocol > 2:
                return b"_\r\n"  # resp3 null
            return b"$-1\r\n"  # Null bulk string
            # some commands return null array: b"*-1\r\n"

        else:
            raise NotImplementedError(f"encode not implemented for {type(data)}")

    def encode_bulkstr(self, bstr: bytes, hint: Optional[str]) -> bytes:
        if self.protocol > 2 and hint is not None:
            # a resp3 verbatim string
            return f"={len(bstr)}\r\n{hint}:".encode() + bstr + b"\r\n"
        # regular bulk string
        return f"${len(bstr)}\r\n".encode() + bstr + b"\r\n"


def encode(value: Any, protocol: int = 2, hint: Optional[str] = None) -> bytes:
    """
    Encode a value using the RESP protocol
    """
    return RespEncoder(protocol).encode(value, hint)


# a stateful RESP parser implemented via a generator
def resp_parse(
    buffer: bytes,
) -> Generator[Optional[Tuple[Any, bytes]], Union[None, bytes], None]:
    """
    A stateful, generator based, RESP parser.
    Returns a generator producing at most a single top-level primitive.
    Yields tuple of (data_item, unparsed), or None if more data is needed.
    It is fed more data with generator.send()
    """
    # Read the first line of resp or yield to get more data
    while CRNL not in buffer:
        incoming = yield None
        assert incoming is not None
        buffer += incoming
    cmd, rest = buffer.split(CRNL, 1)

    code, arg = cmd[:1], cmd[1:]

    if code == b":" or code == b"(":  # integer, resp3 large int
        yield int(arg), rest

    elif code == b"t":  # resp3 true
        yield True, rest

    elif code == b"f":  # resp3 false
        yield False, rest

    elif code == b"_":  # resp3 null
        yield None, rest

    elif code == b",":  # resp3 double
        yield float(arg), rest

    elif code == b"+":  # simple string
        # we decode them automatically
        yield arg.decode(errors="surrogateescape"), rest

    elif code == b"$":  # bulk string
        count = int(arg)
        expect = count + 2  # +2 for the trailing CRNL
        while len(rest) < expect:
            incoming = yield (None)
            assert incoming is not None
            rest += incoming
        bulkstr = rest[:count]
        # we decode them automatically.  Can be encoded
        # back to binary if necessary with "surrogatescape"
        yield bulkstr.decode(errors="surrogateescape"), rest[expect:]

    elif code == b"=":  # verbatim strings
        count = int(arg)
        expect = count + 4 + 2  # 4 type and colon +2 for the trailing CRNL
        while len(rest) < expect:
            incoming = yield (None)
            assert incoming is not None
            rest += incoming
        hint = rest[:3]
        result = rest[4: (count + 4)]
        yield VerbatimStr(result.decode(errors="surrogateescape"),
                          hint.decode()), rest[expect:]

    elif code in b"*>":  # array or push data
        count = int(arg)
        result_array = []
        for _ in range(count):
            # recursively parse the next array item
            with closing(resp_parse(rest)) as parser:
                parsed = parser.send(None)
                while parsed is None:
                    incoming = yield None
                    parsed = parser.send(incoming)
            value, rest = parsed
            result_array.append(value)
        if code == b">":
            yield PushData(result_array), rest
        else:
            yield result_array, rest

    elif code == b"~":  # set
        count = int(arg)
        result_set = set()
        for _ in range(count):
            # recursively parse the next set item
            with closing(resp_parse(rest)) as parser:
                parsed = parser.send(None)
                while parsed is None:
                    incoming = yield None
                    parsed = parser.send(incoming)
            value, rest = parsed
            result_set.add(value)
        yield result_set, rest

    elif code in b"%|":  # map or attribute
        count = int(arg)
        result_map = {}
        for _ in range(count):
            # recursively parse the next key, and value
            with closing(resp_parse(rest)) as parser:
                parsed = parser.send(None)
                while parsed is None:
                    incoming = yield None
                    parsed = parser.send(incoming)
            key, rest = parsed
            with closing(resp_parse(rest)) as parser:
                parsed = parser.send(None)
                while parsed is None:
                    incoming = yield None
                    parsed = parser.send(incoming)
            value, rest = parsed
            result_map[key] = value
        if code == b"|":
            yield Attribute(result_map), rest
        yield result_map, rest

    elif code == b"-":  # error
        # we decode them automatically
        decoded = arg.decode(errors="surrogateescape")
        code, value = decoded.split(" ", 1)
        yield ErrorStr(code, value), rest

    elif code == b"!":  # resp3 error
        count = int(arg)
        expect = count + 2  # +2 for the trailing CRNL
        while len(rest) < expect:
            incoming = yield (None)
            assert incoming is not None
            rest += incoming
        bulkstr = rest[:count]
        decoded = bulkstr.decode(errors="surrogateescape")
        code, value = decoded.split(" ", 1)
        yield ErrorStr(code, value), rest[expect:]

    else:
        raise ValueError(f"Unknown opcode '{code.decode()}'")


class NeedMoreData(RuntimeError):
    """
    Raised when more data is needed to complete a parse
    """


class RespParser:
    """
    A class for simple RESP protocol decoding for unit tests
    """

    def __init__(self) -> None:
        self.parser: Optional[
            Generator[Optional[Tuple[Any, bytes]], Union[None, bytes], None]
        ] = None
        # which has not resulted in a parsed value
        self.consumed: List[bytes] = []

    def parse(self, buffer: bytes) -> Optional[Any]:
        """
        Parse a buffer of data, return a tuple of a single top-level primitive and the
        remaining buffer or raise NeedMoreData if more data is needed
        """
        if self.parser is None:
            # create a new parser generator, initializing it with
            # any unparsed data from previous calls
            buffer = b"".join(self.consumed) + buffer
            del self.consumed[:]
            self.parser = resp_parse(buffer)
            parsed = self.parser.send(None)
        else:
            # sen more data to the parser
            parsed = self.parser.send(buffer)

        if parsed is None:
            self.consumed.append(buffer)
            raise NeedMoreData()

        # got a value, close the parser, store the remaining buffer
        self.parser.close()
        self.parser = None
        value, remaining = parsed
        self.consumed = [remaining]
        return value

    def get_unparsed(self) -> bytes:
        return b"".join(self.consumed)

    def close(self) -> None:
        if self.parser is not None:
            self.parser.close()
            self.parser = None
        del self.consumed[:]


def parse_all(buffer: bytes) -> Tuple[List[Any], bytes]:
    """
    Parse all the data in the buffer, returning the list of top-level objects and the
    remaining buffer
    """
    with closing(RespParser()) as parser:
        result: List[Any] = []
        while True:
            try:
                result.append(parser.parse(buffer))
                buffer = b""
            except NeedMoreData:
                return result, parser.get_unparsed()


def parse_chunks(buffers: List[bytes]) -> Tuple[List[Any], bytes]:
    """
    Parse all the data in the buffers, returning the list of top-level objects and the
    remaining buffer.
    Used primarily for testing, since it will parse the data in chunks
    """
    result: List[Any] = []
    with closing(RespParser()) as parser:
        for buffer in buffers:
            while True:
                try:
                    result.append(parser.parse(buffer))
                    buffer = b""
                except NeedMoreData:
                    break
        return result, parser.get_unparsed()
