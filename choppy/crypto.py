#! usr/bin/env/ python3

import base64
import hashlib
import os
import secrets

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ------------------------------------------------------------------------------
def hash_str(s):
    return hashlib.md5(bytes(s, 'utf-8')).digest().hex()


def md5_hash(fp):
    chunk = 2**12
    f_hash = hashlib.md5()
    with open(fp, 'rb') as file_:
        data = file_.read(chunk)
        while data:
            f_hash.update(data)
            data = file_.read(chunk)

    return f_hash.hexdigest()


# ------------------------------------------------------------------------------
def load_key(password, salt, length=32, iterations=100000):

    if isinstance(password, str):
        password = bytes(password, 'utf-8')

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
        )

    return base64.urlsafe_b64encode(kdf.derive(password))


def generate_salt(length=32):
    with open('salt.txt', 'xb') as outfile:
        outfile.write(os.urandom(length))


def generate_password(length=32):
    with open('password.txt', 'xw') as outfile:
        outfile.write(secrets.token_urlsafe(length))

    print('Storing passwords in plain text is not a good idea.')


def encrypt(key, fn, fnout):
    algo = Fernet(key)
    with open(fnout, 'wb') as outfile:
        with open(fn, 'rb') as infile:
            outfile.write(algo.encrypt(infile.read()))


def decrypt(key, fn, fnout):
    algo = Fernet(key)
    with open(fnout, 'wb') as outfile:
        with open(fn, 'rb') as infile:
            outfile.write(algo.decrypt(infile.read()))


def xxcrypt(crypt_algo, fp_out, fp_in):
    with open(fp_out, 'wb') as outfile:
        with open(fp_in, 'rb') as infile:
            outfile.write(crypt_algo(infile.read()))


def batch_encrypt(key, paths, outdir):
    fp_out = lambda fp: os.path.join(outdir, os.path.basename(fp))
    fernet = Fernet(key)
    crypt_algo = fernet.encrypt
    for fp in paths:
        xxcrypt(crypt_algo, fp_out(fp), fp)



# def crypto_test(key, fp):
#     filename, ext = os.path.splitext(fp)
#     encrypted = filename + '_enc' + ext
#     decrypted = filename + '_dec' + ext
#
#     passphrase = b"password"
#     salt = os.urandom(16)
#     key = load_key(passphrase, salt)
#
#     crypt_algo = Fernet(key)
#
#     s1 = perf_counter()
#     run_crypto(crypt_algo.encrypt, fp, encrypted)
#
#     s2 = perf_counter()
#     run_crypto(crypt_algo.decrypt, encrypted, decrypted)
#
#     s3 = perf_counter()
#
#     fp_size = os.path.getsize(fp)
#
#     print('-> enc: {:.4f} sec, -> dec: {:.4f} sec'.format(s2-s1, s3-s2))
#     print('Filesize: {:,} kb'.format(fp_size // 1000))
#     print('Encrypted filesize ratio: {:.2%}'.format(os.path.getsize(encrypted) / fp_size))
#
#     status = md5_hash(fp) == md5_hash(decrypted)
#     print('Status:', status)
