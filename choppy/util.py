#! usr/bin/env/ python3


# ------------------------------------------------------------------------------
cat = ''.join


def fmt_hex(n):
    hx = '{:x}'.format(n)
    if len(hx) % 2:
        hx = hx.zfill(len(hx) + 1)
    return hx


def hex_16bit(n):
    return '{:0>4x}'.format(n)


def hex_byte_read_len(hx):
    return hex_16bit(len(hx) // 2)


def encode_str_hex(word):
    hex_vals = []
    for char in word:
        hex_vals.append(fmt_hex(ord(char)))
    return cat(hex_vals)


def decode_hex_str(hx):
    hex_str = []
    for chars in map(cat, zip(hx[::2], hx[1::2])):
        hex_str.append(chr(int(chars, 16)))
    return cat(hex_str)


# ------------------------------------------------------------------------------

def test_utils():
    from random import randint


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
