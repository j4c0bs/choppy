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


HEX_FP = encode_str_hex('ch0ppyFP')


# ------------------------------------------------------------------------------
