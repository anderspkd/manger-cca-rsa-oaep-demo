from oaep import RSA_key, oaep_enc, oaep_dec
from flask import Flask, request, jsonify
from os import urandom as rand

app = Flask(__name__)

flag = b'flag{' + bytes(rand(32).hex(), 'ascii') + b'}'
key = RSA_key()  # create a 1024-bit key

print(f'Flag: {flag}')


@app.route('/encrypted_flag')
def get_encrypted_flag():
    c = oaep_enc(key, flag)
    oaep_dec(key, c, debug=True)
    return str(c) + '\n'


@app.route('/publickey')
def get_publickey():
    return jsonify(e=key._key.e, n=key._key.n)


@app.route('/decrypt')
def decrypt():
    c = 0
    try:
        c = next(request.args.keys())
    except:
        return 'No ciphertext given'
    else:
        c = int(c, 16)

    try:
        oaep_dec(key, c)
    except ValueError as e:
        return str(e)
    else:
        return 'OK\n'


@app.route('/test_flag')
def test_flag():
    flag_cand = ''
    try:
        flag_cand = next(request.args.keys())
    except:
        return 'No flag\n'
    else:
        return 'Yay\n' if bytes(flag_cand, 'ascii') == flag else 'Boo\n'


if __name__ == '__main__':
    app.run()
