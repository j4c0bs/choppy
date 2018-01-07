#! usr/bin/env/ python3

# from concurrent import futures

import base64
import hashlib
import os
import secrets

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ------------------------------------------------------------------------------
def generate_salt(length=32):
    with open('salt.txt', 'xb') as outfile:
        outfile.write(os.urandom(length))


def generate_password(length=32):
    with open('password.txt', 'xt') as outfile:
        outfile.write(secrets.token_urlsafe(length))

    print('Storing passwords in plain text is not a good idea.')


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


def get_io_paths(paths, outdir):
    get_path_pair = lambda fp: os.path.join(outdir, os.path.basename(fp))
    return tuple(zip(paths, map(get_path_pair, paths)))


# ------------------------------------------------------------------------------
def batch_decrypt(key, paths, outdir):
    io_paths = get_io_paths(paths, outdir)

    fernet = Fernet(key)
    outpaths = []

    def apply_crypto(fps):
        fp_in, fp_out = fps
        with open(fp_out, 'wb') as outfile:
            with open(fp_in, 'rb') as infile:
                try:
                    token = fernet.decrypt(infile.read())
                    outfile.write(token)
                except InvalidToken:
                    fp_out = ''

        return fp_out

    for fps in io_paths:
        fp_decrypted = apply_crypto(fps)
        if fp_decrypted:
            outpaths.append(fp_decrypted)

    return outpaths


def batch_encrypt(key, paths, outdir):
    io_paths = get_io_paths(paths, outdir)

    fernet = Fernet(key)
    outpaths = []

    def apply_crypto(fps):
        fp_in, fp_out = fps
        with open(fp_out, 'wb') as outfile:
            with open(fp_in, 'rb') as infile:
                outfile.write(fernet.encrypt(infile.read()))

        return fp_out

    for fps in io_paths:
        outpaths.append(apply_crypto(fps))

    return outpaths
