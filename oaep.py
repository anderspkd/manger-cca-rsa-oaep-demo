from Crypto.Util import number
from Crypto.PublicKey import RSA
from hashlib import sha1
from os import urandom as rand


# Somewhat thin wrapper around pycrypt's RSA implementation
class RSA_key:
    def __init__(self, size=1024):
        self._key = RSA.generate(size)

    # Unlike pycrypto's insanely named `size' function (which returns
    # the max size a key can encrypt), this function returns the size
    # of the key (i.e., the modulus).
    def size(self, bytes=True):
        bits = number.size(self._key.n)
        if bytes:
            return number.ceil_div(bits, 8)
        return bits

    def b2i(self, x):
        return int.from_bytes(x, 'big')

    # textbook RSA encryption and decryption
    def encrypt(self, m):
        if type(m) == bytes:
            m = self.b2i(m)
        return pow(m, self._key.e, self._key.n)

    def decrypt(self, c):
        if type(c) == bytes:
            c = self.b2i(c)
        return pow(c, self._key.d, self._key.n)


# MGF1 and I2OSP curtsy of wikipedia
# (https://en.wikipedia.org/wiki/Mask_generation_function#Example_Code)
def I2OSP(i, size=4):
    return bytes([(i >> (8 * i)) & 0xFF for i in range(size - 1, -1, -1)])


def MGF1(i, l, H=sha1):
    counter = 0
    output = b''
    while len(output) < l:
        c = I2OSP(counter, 4)
        output += H(i + c).digest()
        counter += 1
    return output[:l]


# XOR to byte strings.
def xor(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])


# OAEP encrypt. See RFC 3447 7.1.1 (no support for label)
def oaep_enc(pk, m, H=sha1):
    hlen = H().digest_size
    mlen = len(m)
    k = pk.size()

    if mlen > k - 2*hlen - 2:
        raise ValueError('message too long')

    # Encoding
    lhash = H(b'').digest()
    ps = bytes([0x00] * (k - mlen - 2*hlen - 2))
    db = lhash + ps + b'\x01' + m
    seed = rand(hlen)
    dbmask = MGF1(seed, k - hlen - 1)
    maskeddb = xor(db, dbmask)
    seedmask = MGF1(maskeddb, hlen)
    maskedseed = xor(seed, seedmask)
    em = b'\x00' + maskedseed + maskeddb

    # encryption
    c = pk.encrypt(em)

    return c


# OAEP decrypt. See RFC 3447 7.1.2
def oaep_dec(sk, c, H=sha1, debug=False):
    k = sk.size()
    hlen = H().digest_size
    lhash = sha1(b'').digest()

    # if c is not None and number.ceil_div(number.size(c), 8) != k:
    #     raise ValueError('decryption error (1)')

    # if k < 2 * hlen + 2:
    #     raise ValueError('decryption error (2)')

    # decryption
    m = sk.decrypt(c)

    em = m.to_bytes(k, byteorder='big')

    y = em[0]
    maskedseed = em[1:1+hlen]
    maskeddb = em[1+hlen:]

    # Sanity check
    assert len(maskeddb) == k-hlen-1, 'WTF?'

    seedmask = MGF1(maskeddb, hlen)
    seed = xor(maskedseed, seedmask)
    dbmask = MGF1(seed, k - hlen - 1)
    db = xor(maskeddb, dbmask)

    if debug:
        print(seed)
        print(db)

    # padding oracle
    if y != 0:
        raise ValueError('em[0] != 0x00')

    _lhash = db[:hlen]

    if _lhash != lhash:
        raise ValueError("lhash' != lhash")

    try:
        i = db.index(0x01)
    except ValueError:
        raise ValueError('no 0x01 byte found')
    else:
        # ps = db[:i]  # not needed
        m = db[i+1:]
        return m
