from typing import Union
from math import ceil
from base64 import b64encode, b64decode
import hashlib
from secrets import randbelow, token_bytes

from pbkdf2.exceptions import KeyTooLongException

string = Union[str, bytes]

def byte_xor(a, b):
    return bytes([_a ^ _b for _a, _b in zip(a, b)])


class PBKDF2:
    # RFC 2898
    PSEUDO_RANDOM_OUT = 32
    MAX_KEYSIZE = (2**32 - 1) * PSEUDO_RANDOM_OUT # (2^32 - 1) * hLen

    def __init__(
        self,
        password : string,
        salt : string = None,
        iterations : int = None,
        outlength : int = 64
    ):
        if salt is None:
            salt = token_bytes(16)

        if iterations is None:
            iterations = 29000 + randbelow(1000)

        if isinstance(password, str):
            password = password.encode()

        if isinstance(salt, str):
            salt = salt.encode()

        self.salt = salt
        self.iterations = iterations

        if outlength > self.MAX_KEYSIZE:
            raise KeyTooLongException

        self.num_blocks = ceil(outlength / self.PSEUDO_RANDOM_OUT)

        self.digest = b""

        for i in range(1, self.num_blocks + 1):
            self.digest += self.F(
                password,
                self.salt,
                self.iterations,
                i
            )

        assert len(self.digest) >= outlength

        self.digest = self.digest[:outlength]

    def Hash(self):
        return "PBKDF2_SHA256$" + str(self.iterations) + "$" + b64encode(self.salt).decode() + "$" + self.GetB64().decode()

    def GetBytes(self):
        return self.digest

    def GetB64(self):
        return b64encode(self.digest)

    def GetHex(self):
        return self.digest.hex()

    @classmethod
    def F(cls, P : bytes, S : bytes, c : int, i : int) -> bytes:
        assert i <= cls.MAX_KEYSIZE

        out = cls.PRF(P, S + i.to_bytes(4, "big"))

        for j in range(1, c+1):
            out = byte_xor(
                PBKDF2.PRF(P, out),
                out
            )

        return out

    @classmethod
    def PRF(cls, P : bytes, K : bytes) -> bytes:
        # RFC 2104
        ipad = b"\x36"*cls.PSEUDO_RANDOM_OUT
        opad = b"\x5C"*cls.PSEUDO_RANDOM_OUT

        if len(K) < cls.PSEUDO_RANDOM_OUT:
            K = K + b"\x00"*(cls.PSEUDO_RANDOM_OUT - len(K))

        if len(K) > cls.PSEUDO_RANDOM_OUT:
            K = cls.H(K)

        return cls.H(
            byte_xor(K, opad) + cls.H(
                byte_xor(K, ipad) + P
            )
        )

    @classmethod
    def H(cls, msg : bytes) -> bytes:
        h = hashlib.sha256()
        h.update(msg)
        return h.digest()
