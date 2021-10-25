import codecs
from collections import Generator

MOD = 256


def ksa(key: list[int]):
    key_length = len(key)
    s = list(range(MOD))
    j = 0
    for i in range(MOD):
        j = (j + s[i] + key[i % key_length]) % MOD
        s[i], s[j] = s[j], s[i]
    return s


def prga(S) -> Generator[int]:
    i = 0
    j = 0
    while True:
        i = (i + 1) % MOD
        j = (j + S[i]) % MOD
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % MOD]
        yield K


class Rc4Cipher:
    def __init__(self, key: str):
        self.key = [ord(c) for c in key]

    def _key_stream_generator(self) -> Generator[int]:
        s = ksa([c for c in self.key])
        return prga(s)

    def _encryption(self, encryption_data):
        res = []
        key_stream_gen = self._key_stream_generator()
        for c in encryption_data:
            val = ("%02X" % (c ^ next(key_stream_gen)))  # XOR and taking hex
            res.append(val)
        return ''.join(res)

    def encode(self, text_to_encode: str):
        return self._encryption([ord(ch) for ch in text_to_encode])

    def decode(self, text_to_decode: str):
        return codecs.decode(self._encryption(codecs.decode(text_to_decode, 'hex_codec')), 'hex_codec').decode('utf-8')
