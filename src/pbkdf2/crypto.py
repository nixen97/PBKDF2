from typing import Union
from math import ceil
from base64 import b64encode, b64decode

from pbkdf2.exceptions import KeyTooLongException

string = Union[str, bytes]

def byte_xor(a, b):
    return bytes([_a ^ _b for _a, _b in zip(a, b)])


class PBKDF2:
    PSEUDO_RANDOM_OUT = 4
    MAX_KEYSIZE = (2**32 - 1) * PSEUDO_RANDOM_OUT # (2^32 - 1) * hLen

    def __init__(
        self,
        password : string,
        salt : string = None,
        iterations : int = None,
        outlength : int = 128
    ):
        if isinstance(password, str):
            password = password.encode()

        if isinstance(salt, str):
            salt = salt.encode()

        if outlength > self.MAX_KEYSIZE:
            raise KeyTooLongException

        self.num_blocks = ceil(outlength / self.PSEUDO_RANDOM_OUT)

        self.digest = b""

        for i in range(1, self.num_blocks + 1):
            self.digest +=  self.F(
                password,
                salt,
                iterations,
                i
            )

        assert len(self.digest) >= outlength

        self.digest = self.digest[:outlength]

        self.digest = b64encode(self.digest)

    def GetBytes(self):
        return self.digest

    @staticmethod
    def F(P : bytes, S : bytes, c : int, i : int) -> bytes:
        assert i <= PBKDF2.MAX_KEYSIZE
        out = PBKDF2.PRF(P, S + i.to_bytes(4, "big"))

        for j in range(1, c+1):
            out = byte_xor(
                PBKDF2.PRF(P, out),
                out
            )

        return out

    @staticmethod
    def PRF(P : bytes, K : bytes) -> bytes:
        return b"test"

    @staticmethod
    def HMAC() -> bytes:
        # RFC 2104
        pass

    @staticmethod
    def H(msg : bytes) -> bytes:
        return msg
