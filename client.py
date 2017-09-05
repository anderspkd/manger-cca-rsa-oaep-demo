from requests import get as _get
from hashlib import sha1
import json
from math import log, floor
from oaep import MGF1, xor
from Crypto.Util import number
from decimal import Decimal, getcontext, ROUND_CEILING, ROUND_FLOOR

base_url = 'http://127.0.0.1:5000'


def get(url):
    return _get(base_url + url).content


# True  => (c^d mod n) >= B
# False => (c^d mod n) < B
def query_oracle(f):
    h = pow(f, e, n)
    w = (h * ciphertext) % n
    r = get('/decrypt?' + hex(w))

    return r == b'em[0] != 0x00'


def step1(c):
    f1 = 1
    while not query_oracle(f1):
        f1 = 2 * f1
    return f1


def step2(c, f1):
    f2 = int(floor((n + B) / B) * (f1 / 2))
    while query_oracle(f2):
        f2 = int(f2 + (f1 / 2))
    return f2


def step3(c, t2):

    # Helper
    def Dec(thing, rounding):
        if rounding == 'up':
            return Decimal(thing).to_integral_value(rounding=ROUND_CEILING)
        else:
            return Decimal(thing).to_integral_value(rounding=ROUND_FLOOR)
    getcontext().prec = 500

    m_min = Dec(n / t2, 'up')
    m_max = Dec((n + B) / t2, 'down')
    t_tmp = Dec((2 * B) / (m_max - m_min), 'down')
    i = Dec((t_tmp * m_min) / n, 'up')
    f3 = Dec((i * n) / m_min, 'up')

    while True:
        if not query_oracle(int(f3)):
            m_max = Dec((i*n + B) / f3, 'down')
        else:
            m_min = Dec((i*n + B) / f3, 'up')
        diff = Decimal(m_max - m_min)
        print(f'm_max - m_min: {diff}')
        if diff == 0:
            break
        t_tmp = Dec((2 * B) / (m_max - m_min), 'down')
        i = Dec((t_tmp * m_min) / n, 'up')
        f3 = Dec((i * n) / m_min, 'up')

    print(f'f3 - B: {f3 - B}')
    return m_min


if __name__ == '__main__':
    pubkey = json.loads(get('/publickey'))
    e = pubkey['e']
    n = pubkey['n']

    k = Decimal(str(log(n, 256))).to_integral_value(rounding=ROUND_CEILING)
    B = getcontext().power(Decimal(2), Decimal(8*(k-1)))

    assert 2*B < n, "Shouldn't happen"

    ciphertext = int(get('/encrypted_flag'))

    # (t1 / 2)*m \in [B/2, B)
    t1 = step1(ciphertext)

    # t2*m \in [n, n + B)
    t2 = step2(ciphertext, t1)

    m = int(step3(ciphertext, t2))

    # OAEP decoding
    k = number.size(n)
    k = number.ceil_div(k, 8)
    hlen = 20
    lhash = sha1(b'').digest()

    em = m.to_bytes(k, byteorder='big')

    y = em[0]
    maskedseed = em[1:1+hlen]
    maskeddb = em[1+hlen:]

    seedmask = MGF1(maskeddb, hlen)
    seed = xor(maskedseed, seedmask)
    dbmask = MGF1(seed, k - hlen - 1)
    db = xor(maskeddb, dbmask)

    _lhash = db[:hlen]

    assert _lhash == lhash, 'lhash should match _lhash'

    i = db.index(0x01)

    m = db[i+1:]

    print(f'Found message:\n{m}')

    print('Server says:')
    print(get(f'/test_flag?{str(m, "ascii")}'))
