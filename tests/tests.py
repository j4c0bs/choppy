#! usr/bin/env/ python3

import os
from os.path import abspath, dirname, getsize
import sys
parent_dir = dirname(abspath(dirname('__file__')))
sys.path.insert(0, parent_dir)
test_files = os.path.join(parent_dir, 'test_files')

from random import randint
from time import perf_counter

from choppy.choppy import chop, merge, decrypt_and_merge, read_password_file, read_salt_file
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
def test_dir(fp):
    return os.path.join(test_files, fp)


def gen_dir_files(dir_):
    for fn in os.listdir(dir_):
        yield os.path.join(dir_, fn)


def test_chop_no_encryption():
    tfs = ('pcs_mrg.pdf', '20MB.mp3')
    fps = list(map(test_dir, tfs))
    tmpdir = test_dir('chunks')
    chopped = chop(fps, tmpdir, 10, wobble=50, numfn=False, enc=False)
    merge(chopped, tmpdir)


def test_chop_encrypt():
    pw_fp = test_dir('password.txt')
    salt_fp = test_dir('salt.txt')

    pw = read_password_file(pw_fp)
    salt = read_salt_file(salt_fp)

    key = crypto.load_key(pw, salt)

    tfs = ('pcs_mrg.pdf', '20MB.mp3')
    fps = list(map(test_dir, tfs))
    tmpdir = test_dir('chunks')

    chopped = chop(fps, tmpdir, 10, numfn=False, key=key, enc=True)
    merge(chopped, tmpdir)


def test_chop_encrypt_decrypt_merge():
    pw_fp = test_dir('password.txt')
    salt_fp = test_dir('salt.txt')

    pw = read_password_file(pw_fp)
    salt = read_salt_file(salt_fp)

    key = crypto.load_key(pw, salt)

    # p=100 >>> 1.067s
    # p=10 >>> 0.883s
    tfs = ('pcs_mrg.pdf', '20MB.mp3')

    # real	0m43.293s
    # tfs = ('The.Stand.S01E04.mp4',)

    fps = list(map(test_dir, tfs))
    tmpdir = test_dir('chunks')

    paths = chop(fps, tmpdir, 10, numfn=False, key=key, enc=True)
    decrypt_and_merge(paths, tmpdir, key)



# ------------------------------------------------------------------------------
if __name__ == '__main__':
    start = perf_counter()

    # test_chop_no_encryption()
    # test_chop_encrypt()
    test_chop_encrypt_decrypt_merge()

    print('\n>>> {:.3f}s'.format(perf_counter() - start))
