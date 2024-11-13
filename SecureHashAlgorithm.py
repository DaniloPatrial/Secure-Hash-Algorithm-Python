import os
os.system("cls")

SHA1_K = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6]

SHA256_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

SHA384_512_K = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
    0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
    0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
    0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
    0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
    0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
    0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
]


class Operations:

    @staticmethod
    def SHR(word: int, shift: int = 0) -> int:
        return word >> shift

    @staticmethod
    def ROTR(word: int, rotate: int = 0, size: int = 32) -> int:
        return (word >> rotate) | (word << (size - rotate))

    @staticmethod
    def ROTL(word: int, rotate: int = 0, size: int = 32) -> int:
        return (word << rotate) | (word >> (size - rotate))

op = Operations()


class Functions:

    @staticmethod #check type
    def Ch(x: int, y: int, z: int) -> int:
        return (x & y) ^ (~x & z)

    @staticmethod
    def Maj(x: int, y: int, z: int) -> int:
        return (x & y) ^ (x & z) ^ (y & z)

    @staticmethod
    def Parity(x: int, y: int, z: int) -> int:
        return x ^ y ^ z

    @staticmethod
    def SHA256_uSigma0(word: int) -> int:
        return (op.ROTR(word, 2) ^ op.ROTR(word, 13) ^ op.ROTR(word, 22))

    @staticmethod
    def SHA256_uSigma1(word: int) -> int:
        return (op.ROTR(word, 6) ^ op.ROTR(word, 11) ^ op.ROTR(word, 25))

    @staticmethod
    def SHA256_Sigma0(word: int) -> int:
        return (op.ROTR(word, 7) ^ op.ROTR(word, 18) ^ op.SHR(word, 3))

    @staticmethod
    def SHA256_Sigma1(word: int) -> int:
        return (op.ROTR(word, 17) ^ op.ROTR(word, 19) ^ op.SHR(word, 10))

    @staticmethod
    def uSigma0(word: int) -> int:
        return (op.ROTR(word, 28, size=64) ^ op.ROTR(word, 34, size=64) ^ op.ROTR(word, 39, size=64))

    @staticmethod
    def uSigma1(word: int) -> int:
        return (op.ROTR(word, 14, size=64) ^ op.ROTR(word, 18, size=64) ^ op.ROTR(word, 41, size=64))

    @staticmethod
    def Sigma0(word: int) -> int:
        return (op.ROTR(word, 1, size=64) ^ op.ROTR(word, 8, size=64) ^ op.SHR(word, 7))

    @staticmethod
    def Sigma1(word: int) -> int:
        return (op.ROTR(word, 19, size=64) ^ op.ROTR(word, 61, size=64) ^ op.SHR(word, 6))

fc = Functions()


class Padding:

    def __init__(self, message: str = None, *, bits: int = 512) -> None:
        if isinstance(message, str): message = bytearray(message, 'ascii')
        elif isinstance(message, bytes): message = bytearray(message)
        else: raise TypeError(f"raised from '{__class__.__name__}'")

        if bits == 512: self.message = self.padding512(message)
        elif bits == 1024: self.message = self.padding1024(message)
        else: raise ValueError(f"raised from '{__class__.__name__}'")

    def padding512(self, message: bytearray) -> bytearray:
        length = len(message) * 8
        message.append(0x80)
        while (len(message) * 8 + 64) % 512 != 0: message.append(0x00)

        message += length.to_bytes(8, 'big')
        return message

    def padding1024(self, message: bytearray) -> bytearray:
        length = len(message) * 8
        message.append(0x80)
        while (len(message) * 8 + 128) % 1024 != 0: message.append(0x00)

        message += length.to_bytes(16, 'big')
        return message

    def __bytearray__(self) -> bytearray:
        return self.message


class Parsing:

    def __init__(self, message: bytearray, *, bits: int = 512) -> None:
        if bits == 512: self.blocks = self.parsing512(message)
        elif bits == 1024: self.blocks = self.parsing1024(message)
        else: raise ValueError(f"raised from '{__class__.__name__}'")

    def parsing512(self, message: bytearray) -> list[bytearray]:
        blocks: list[bytearray] = [message[i:i + 64] for i in range(0, len(message), 64)]
        return blocks

    def parsing1024(self, message: bytearray) -> list[bytearray]:
        blocks: list[bytearray] = [message[i:i + 128] for i in range(0, len(message), 128)]
        return blocks

    def __list__(self) -> list[bytearray]:
        return self.blocks


class SHA1_HashComputation:

    def __init__(self, message: str) -> None:
        padded_message: bytearray = Padding(message, bits=512).__bytearray__()
        parsed_message: list[bytearray] = Parsing(padded_message, bits=512).__list__()
        self.blocks: list[bytearray] = parsed_message

    def HashComputation(self) -> bytes:
        H0, H1, H2, H3, H4 = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0

        for block in self.blocks:
            message_schedule: list[bytes] = []
            for t in range(80):
                if t <= 15: message_schedule.append(bytes(block[t*4:(t*4)+4]))
                else:
                    A = int.from_bytes(message_schedule[t-3], 'big')
                    B = int.from_bytes(message_schedule[t-8], 'big')
                    C = int.from_bytes(message_schedule[t-14], 'big')
                    D = int.from_bytes(message_schedule[t-16], 'big')

                    schedule = (op.ROTL((A ^ B ^ C ^ D), rotate=1)) & 0xffffffff
                    message_schedule.append(schedule.to_bytes(4, 'big'))

            a, b, c, d, e = H0, H1, H2, H3, H4

            for t in range(80):
                if t <= 19:
                    T = (op.ROTL(a, 5) + fc.Ch(b, c, d) + e + SHA1_K[0] + 
                         int.from_bytes(message_schedule[t], 'big')) % 2**32

                elif t <= 39:
                    T = (op.ROTL(a, 5) + fc.Parity(b, c, d) + e + SHA1_K[1] + 
                         int.from_bytes(message_schedule[t], 'big')) % 2**32

                elif t <= 59:
                    T = (op.ROTL(a, 5) + fc.Maj(b, c, d) + e + SHA1_K[2] + 
                         int.from_bytes(message_schedule[t], 'big')) % 2**32

                else:
                    T = (op.ROTL(a, 5) + fc.Parity(b, c, d) + e + SHA1_K[3] + 
                         int.from_bytes(message_schedule[t], 'big')) % 2**32

                e, d, c, b, a = d, c, op.ROTL(b, 30), a, T

            H0, H1, H2, H3, H4 = (H0 + a) % 2**32, (H1 + b) % 2**32, (H2 + c) % 2**32, (H3 + d) % 2**32, (H4 + e) % 2**32

        return ((H0).to_bytes(4, 'big') + (H1).to_bytes(4, 'big') +
                (H2).to_bytes(4, 'big') + (H3).to_bytes(4, 'big') +
                (H4).to_bytes(4, 'big')).hex()


class SHA256_HashComputation:

    def __init__(self, message: str) -> None:
        padded_message: bytearray = Padding(message, bits=512).__bytearray__()
        parsed_message: list[bytearray] = Parsing(padded_message, bits=512).__list__()
        self.blocks: list[bytearray] = parsed_message

    def HashComputation(self) -> bytes:

        H0, H1, H2, H3 = 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
        H4, H5, H6, H7 = 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19

        for block in self.blocks:
            message_schedule: list[bytes] = []
            for t in range(64):
                if t <= 15: message_schedule.append(bytes(block[t*4:(t*4)+4]))
                else:
                    A = fc.SHA256_Sigma1(int.from_bytes(message_schedule[t-2], 'big'))
                    B = int.from_bytes(message_schedule[t-7], 'big')
                    C = fc.SHA256_Sigma0(int.from_bytes(message_schedule[t-15], 'big'))
                    D = int.from_bytes(message_schedule[t-16], 'big')

                    schedule = ((A + B + C + D) % 2**32).to_bytes(4, 'big')
                    message_schedule.append(schedule)

            a, b, c, d, e, f, g, h = H0, H1, H2, H3, H4, H5, H6, H7

            for t in range(64):
                T1 = ((h + fc.SHA256_uSigma1(e) + fc.Ch(e, f, g) + SHA256_K[t] + 
                       int.from_bytes(message_schedule[t], 'big')) % 2**32)

                T2 = (fc.SHA256_uSigma0(a) + fc.Maj(a, b, c)) % 2**32

                h, g, f = g, f, e
                e = (d + T1) % 2**32
                d, c, b = c, b, a
                a = (T1 + T2) % 2**32

            H0, H1, H2, H3 = (H0 + a) % 2**32, (H1 + b) % 2**32, (H2 + c) % 2**32, (H3 + d) % 2**32
            H4, H5, H6, H7 = (H4 + e) % 2**32, (H5 + f) % 2**32, (H6 + g) % 2**32, (H7 + h) % 2**32

        return ((H0).to_bytes(4, 'big') + (H1).to_bytes(4, 'big') +
                (H2).to_bytes(4, 'big') + (H3).to_bytes(4, 'big') +
                (H4).to_bytes(4, 'big') + (H5).to_bytes(4, 'big') +
                (H6).to_bytes(4, 'big') + (H7).to_bytes(4, 'big')).hex()


class SHA512_HashComputation:
    def __init__(self, message: str) -> None:
        padded_message: bytearray = Padding(message, bits=1024).__bytearray__()
        parsed_message: list[bytearray] = Parsing(padded_message, bits=1024).__list__()
        self.blocks: list[bytearray] = parsed_message

    def HashComputation(self) -> bytes:
        H0, H1, H2, H3 = 0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1
        H4, H5, H6, H7 = 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179

        for block in self.blocks:
            message_schedule: list[bytes] = []
            for t in range(80):
                if t <= 15: message_schedule.append(int.from_bytes(block[t*8:(t*8)+8], 'big'))
                else:
                    A = fc.Sigma1(message_schedule[t-2])
                    B = message_schedule[t-7]
                    C = fc.Sigma0(message_schedule[t-15])
                    D = message_schedule[t-16]

                    schedule = ((A + B + C + D) % 2**64)
                    message_schedule.append(schedule)

            a, b, c, d, e, f, g, h = H0, H1, H2, H3, H4, H5, H6, H7

            for t in range(80):
                T1 = ((h + fc.uSigma1(e) + fc.Ch(e, f, g) + SHA384_512_K[t] + message_schedule[t]) % 2**64)

                T2 = (fc.uSigma0(a) + fc.Maj(a, b, c)) % 2**64

                h, g, f = g, f, e
                e = (d + T1) % 2**64
                d, c, b = c, b, a
                a = (T1 + T2) % 2**64

            H0, H1, H2, H3 = (H0 + a) % 2**64, (H1 + b) % 2**64, (H2 + c) % 2**64, (H3 + d) % 2**64
            H4, H5, H6, H7 = (H4 + e) % 2**64, (H5 + f) % 2**64, (H6 + g) % 2**64, (H7 + h) % 2**64

        return ((H0).to_bytes(8, 'big') + (H1).to_bytes(8, 'big') +
                (H2).to_bytes(8, 'big') + (H3).to_bytes(8, 'big') +
                (H4).to_bytes(8, 'big') + (H5).to_bytes(8, 'big') +
                (H6).to_bytes(8, 'big') + (H7).to_bytes(8, 'big')).hex()


class SHA384_HashComputation:
    def __init__(self, message: str) -> None:
        padded_message: bytearray = Padding(message, bits=1024).__bytearray__()
        parsed_message: list[bytearray] = Parsing(padded_message, bits=1024).__list__()
        self.blocks: list[bytearray] = parsed_message

    def HashComputation(self) -> bytes:
        H0, H1, H2, H3 = 0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939
        H4, H5, H6, H7 = 0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4

        for block in self.blocks:
            message_schedule: list[bytes] = []
            for t in range(80):
                if t <= 15: message_schedule.append(int.from_bytes(block[t*8:(t*8)+8], 'big'))
                else:
                    A = fc.Sigma1(message_schedule[t-2])
                    B = message_schedule[t-7]
                    C = fc.Sigma0(message_schedule[t-15])
                    D = message_schedule[t-16]

                    schedule = ((A + B + C + D) % 2**64)
                    message_schedule.append(schedule)

            a, b, c, d, e, f, g, h = H0, H1, H2, H3, H4, H5, H6, H7

            for t in range(80):
                T1 = ((h + fc.uSigma1(e) + fc.Ch(e, f, g) + SHA384_512_K[t] + message_schedule[t]) % 2**64)

                T2 = (fc.uSigma0(a) + fc.Maj(a, b, c)) % 2**64

                h, g, f = g, f, e
                e = (d + T1) % 2**64
                d, c, b = c, b, a
                a = (T1 + T2) % 2**64

            H0, H1, H2, H3 = (H0 + a) % 2**64, (H1 + b) % 2**64, (H2 + c) % 2**64, (H3 + d) % 2**64
            H4, H5, H6, H7 = (H4 + e) % 2**64, (H5 + f) % 2**64, (H6 + g) % 2**64, (H7 + h) % 2**64

        return ((H0).to_bytes(8, 'big') + (H1).to_bytes(8, 'big') +
                (H2).to_bytes(8, 'big') + (H3).to_bytes(8, 'big') +
                (H4).to_bytes(8, 'big') + (H5).to_bytes(8, 'big')).hex()


def sha1(message: str) -> hex:
        return SHA1_HashComputation(message).HashComputation()

def sha256(message: str) -> hex:
        return SHA256_HashComputation(message).HashComputation()

def sha384(message: str) -> hex:
        return SHA384_HashComputation(message).HashComputation()

def sha512(message: str) -> hex:
        return SHA512_HashComputation(message).HashComputation()

if __name__ == "__main__":
    sha1()
    sha256()
    sha384()
    sha512()