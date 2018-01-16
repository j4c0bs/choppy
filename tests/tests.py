#! usr/bin/env/ python3

import os
from os.path import abspath, dirname, getsize
import sys
parent_dir = dirname(abspath(dirname('__file__')))
sys.path.insert(0, parent_dir)

from random import randint
import tempfile
from secrets import token_urlsafe
from time import perf_counter

from cryptography.fernet import Fernet

from choppy.choppy import read_password_file, read_bytes_file
from choppy.chop import chop, chop_encrypt
from choppy.merge import merge, decrypt_merge
from choppy import crypto
from choppy.util import *

# ------------------------------------------------------------------------------
def test_utils():

    def test_fmt_hex(t=1000):
        for _ in range(t):
            n = randint(1, 2**32)
            n_hex = fmt_hex(n)
            assert not len(n_hex) % 2
            assert n == int(n_hex, 16)
        return True

    assert cat(map(str, (i for i in range(5)))) == '01234'
    assert test_fmt_hex()
    assert len(hex_16bit(2)) == 4

    test_digits = 10
    digits_10 = [randint(1, 2**16 - 1) for _ in range(test_digits)]
    digits_hex_str = cat(map(hex_16bit, digits_10))
    assert hex_byte_read_len(digits_hex_str) == hex_16bit(test_digits * 2)

    test_word = 'TEST word !@#$% _-,. 1234567890'
    assert decode_hex_str(encode_str_hex(test_word)) == test_word


# ------------------------------------------------------------------------------
def rand_fn(outdir):
    return os.path.join(outdir, '{}.txt'.format(token_urlsafe(4)))

def make_file(tmpdir, filesize=1024):
    fp = rand_fn(tmpdir)
    with open(fp, 'xb') as outfile:
        outfile.write(os.urandom(filesize))

    return fp


def get_key():
    return Fernet.generate_key()

def get_pw_salt():
    return token_urlsafe(16), os.urandom(32)

# ------------------------------------------------------------------------------
def gen_dir_files(dir_):
    for fn in os.listdir(dir_):
        yield os.path.join(dir_, fn)


def test_chop_merge(nfiles=1, nparts=10, wobble=0):

    key = get_key()

    with tempfile.TemporaryDirectory() as tmpdir:

        paths = [make_file(tmpdir) for _ in range(nfiles)]

        encrypted_paths = chop_encrypt(paths, tmpdir, key, nparts, wobble=wobble)
        outdir = os.path.join(tmpdir, 'MRG')
        os.mkdir(outdir)
        status = decrypt_merge(encrypted_paths, outdir, key, quiet=True)

        assert all(status)
        assert len(status) == nfiles

    print('passed: test_chop_merge, nfiles={}'.format(nfiles))


# ------------------------------------------------------------------------------
if __name__ == '__main__':
    start = perf_counter()

    test_utils()
    print('passed: test_utils')

    test_chop_merge()
    test_chop_merge(nfiles=10, nparts=10, wobble=50)

    print('\n>>> {:.3f}s'.format(perf_counter() - start))
