#! usr/bin/env/ python3

import os
from os.path import abspath, dirname, getsize
import sys
parent_dir = dirname(abspath(dirname('__file__')))
sys.path.insert(0, parent_dir)
test_files = os.path.join(parent_dir, 'test_files')

from random import randint


from choppy.choppy import chop, recombine
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
    # test_fp = test_dir('20MB.mp3')
    # test_fp = test_dir('pcs_mrg.pdf')
    tmpdir = test_dir('chunks')
    # fps = [test_fp]
    chopped = chop(fps, tmpdir, 10, numfn=False, enc=False)

    recombine(chopped, tmpdir)



# ------------------------------------------------------------------------------
if __name__ == '__main__':
    # print(sys.path)
    test_chop_no_encryption()
