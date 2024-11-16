from Constants import *

def ROTR(word: int, rotate: int = 0, size: int = 32) -> int:
    return (word >> rotate) | (word << (size - rotate))

def ROTL(word: int, rotate: int = 0, size: int = 32) -> int:
    return (word << rotate) | (word >> (size - rotate))

def Ch(x: int, y: int, z: int) -> int:
    return (x & y) ^ (~x & z)

def Maj(x: int, y: int, z: int) -> int:
    return (x & y) ^ (x & z) ^ (y & z)

def Parity(x: int, y: int, z: int) -> int:
    return x ^ y ^ z

def padding(message: bytearray, bits=512) -> bytearray:
    length = len(message) * 8
    message.append(0x80)
    while (len(message) * 8 + (bits//8)) % bits != 0:
        message.append(0x00)
    return message + length.to_bytes((bits//64), 'big')

def to_bytearray(message: str) -> bytearray:
    if isinstance(message, str): return bytearray(message, 'ascii')
    elif isinstance(message, bytes): return bytearray(message)
    else: raise TypeError


def sha1(message: str) -> hex:
    message: bytearray = padding(to_bytearray(message), bits=512)
    blocks: list[bytearray] = [message[i:i + 64] for i in range(0, len(message), 64)]

    H0, H1, H2, H3, H4 = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0

    for block in blocks:
        message_schedule: list[bytes] = []

        for t in range(80):
            
            if t <= 15: 
                message_schedule.append(int.from_bytes(block[t*4:(t*4)+4]))
            else:
                A: bytes = message_schedule[t-3]
                B: bytes = message_schedule[t-8]
                C: bytes = message_schedule[t-14]
                D: bytes = message_schedule[t-16]
                message_schedule.append(ROTL((A ^ B ^ C ^ D) , rotate=1) % 2**32)

        a, b, c, d, e = H0, H1, H2, H3, H4

        for t in range(80):

            if t <= 19: func, n = Ch(b, c, d), 0
            elif t <= 39: func, n = Parity(b, c, d), 1
            elif t <= 59: func, n = Maj(b, c, d), 2
            else: func, n = Parity(b, c, d), 3

            T = (ROTL(a, 5) + func + e + K1[n] + message_schedule[t]) % 2**32
            e, d, c, b, a = d, c, ROTL(b, 30), a, T

        H0, H1, H2, H3, H4 = (H0 + a) % 2**32, (H1 + b) % 2**32, (H2 + c) % 2**32, (H3 + d) % 2**32, (H4 + e) % 2**32

    return b''.join(H.to_bytes(4, 'big') for H in (H0, H1, H2, H3, H4)).hex()


def sha256(message: str) -> hex:

    def Sigma0(word: int) -> int:
        return (ROTR(word, 7) ^ ROTR(word, 18) ^ (word >> 3))

    def Sigma1(word: int) -> int:
        return (ROTR(word, 17) ^ ROTR(word, 19) ^ (word >> 10))

    def uSigma0(word: int) -> int:
        return (ROTR(word, 2) ^ ROTR(word, 13) ^ ROTR(word, 22))

    def uSigma1(word: int) -> int:
        return (ROTR(word, 6) ^ ROTR(word, 11) ^ ROTR(word, 25))

    message: bytearray = padding(to_bytearray(message), bits=512)
    blocks: list[bytearray] = [message[i:i + 64] for i in range(0, len(message), 64)]

    H0, H1, H2, H3 = 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
    H4, H5, H6, H7 = 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19

    for block in blocks:
        message_schedule: list[bytes] = []
        for t in range(64):

            if t <= 15:
                message_schedule.append(int.from_bytes(block[t*4:(t*4)+4], 'big'))
            else:
                A: bytes = Sigma1(message_schedule[t-2])
                B: bytes = message_schedule[t-7]
                C: bytes = Sigma0(message_schedule[t-15])
                D: bytes = message_schedule[t-16]
                message_schedule.append((A + B + C + D) % 2**32)

        a, b, c, d, e, f, g, h = H0, H1, H2, H3, H4, H5, H6, H7

        for t in range(64):

            T1 = (h + uSigma1(e) + Ch(e, f, g) + K256[t] + message_schedule[t]) % 2**32
            T2 = (uSigma0(a) + Maj(a, b, c)) % 2**32

            h, g, f = g, f, e
            e = (d + T1) % 2**32
            d, c, b = c, b, a
            a = (T1 + T2) % 2**32

        H0, H1, H2, H3 = (H0 + a) % 2**32, (H1 + b) % 2**32, (H2 + c) % 2**32, (H3 + d) % 2**32
        H4, H5, H6, H7 = (H4 + e) % 2**32, (H5 + f) % 2**32, (H6 + g) % 2**32, (H7 + h) % 2**32

    return b''.join(H.to_bytes(4, 'big') for H in (H0, H1, H2, H3, H4, H5, H6, H7)).hex()


def sha512base(message: str, sha: int = 512) -> tuple:

    def Sigma0(word: int) -> int:
        return (ROTR(word, 1, size=64) ^ ROTR(word, 8, size=64) ^ (word >> 7))

    def Sigma1(word: int) -> int:
        return (ROTR(word, 19, size=64) ^ ROTR(word, 61, size=64) ^ (word >> 6))

    def uSigma0(word: int) -> int:
        return (ROTR(word, 28, size=64) ^ ROTR(word, 34, size=64) ^ ROTR(word, 39, size=64))

    def uSigma1(word: int) -> int:
        return (ROTR(word, 14, size=64) ^ ROTR(word, 18, size=64) ^ ROTR(word, 41, size=64))

    message: bytearray = padding(to_bytearray(message), bits=1024)
    blocks: list[bytearray] = [message[i:i + 128] for i in range(0, len(message), 128)]

    if sha == 512:
        H0, H1, H2, H3 = 0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1
        H4, H5, H6, H7 = 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179

    elif sha == 384:
        H0, H1, H2, H3 = 0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939
        H4, H5, H6, H7 = 0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4

    for block in blocks:
        message_schedule: list[bytes] = []
        for t in range(80):

            if t <= 15:
                message_schedule.append(int.from_bytes(block[t*8:(t*8)+8], 'big'))
            else:
                A: bytes = Sigma1(message_schedule[t-2])
                B: bytes = message_schedule[t-7]
                C: bytes = Sigma0(message_schedule[t-15])
                D: bytes = message_schedule[t-16]

                schedule = ((A + B + C + D) % 2**64)
                message_schedule.append(schedule)

        a, b, c, d, e, f, g, h = H0, H1, H2, H3, H4, H5, H6, H7

        for t in range(80):

            T1 = (h + uSigma1(e) + Ch(e, f, g) + K512[t] + message_schedule[t]) % 2**64
            T2 = (uSigma0(a) + Maj(a, b, c)) % 2**64

            h, g, f = g, f, e
            e = (d + T1) % 2**64
            d, c, b = c, b, a
            a = (T1 + T2) % 2**64

        H0, H1, H2, H3 = (H0 + a) % 2**64, (H1 + b) % 2**64, (H2 + c) % 2**64, (H3 + d) % 2**64
        H4, H5, H6, H7 = (H4 + e) % 2**64, (H5 + f) % 2**64, (H6 + g) % 2**64, (H7 + h) % 2**64

    return H0, H1, H2, H3, H4, H5, H6, H7


def sha512(message: str) -> hex:
    H0, H1, H2, H3, H4, H5, H6, H7 = sha512base(message, sha=512)
    return b''.join(H.to_bytes(8, 'big') for H in (H0, H1, H2, H3, H4, H5, H6, H7)).hex()


def sha384(message: str) -> hex:
    H0, H1, H2, H3, H4, H5, H6, H7 = sha512base(message, sha=384)
    return b''.join(H.to_bytes(8, 'big') for H in (H0, H1, H2, H3, H4, H5)).hex()
