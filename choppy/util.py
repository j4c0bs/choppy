#! usr/bin/env/ python3

from itertools import chain
import struct
from sys import byteorder

from choppy.crypto import hash_str

# ------------------------------------------------------------------------------
cat = ''.join


def bcat(*args):
    bx = chain.from_iterable(args)
    return bytearray(bx)


def fmt_hex(n):
    hx = '{:x}'.format(n)
    if len(hx) % 2:
        hx = hx.zfill(len(hx) + 1)
    return hx


_CFP_HEX = '6368307070794650'
CFP = hash_str(_CFP_HEX)


# ------------------------------------------------------------------------------
X16 = struct.Struct('>H')
X64 = struct.Struct('>Q')


def encode_uint16(n):
    return X16.pack(n)


def decode_uint16(b):
    return X16.unpack(b)[0]


def encode_uint64(n):
    return X64.pack(n)


def decode_uint64(b):
    return X64.unpack(b)[0]


def encode_uint(n):
    hx = fmt_hex(n)
    if byteorder == 'big':
        hx = hx[::-1]
    return bytearray.fromhex(hx)


def decode_uint(b):
    if len(b) == 2:
        return decode_uint16(b)
    elif len(b) == 8:
        return decode_uint64(b)
    else:
        bx = b.hex()
        if byteorder == 'big':
            bx = bx[::-1]
        return int(bx, 16)


def byte_len(b):
    return encode_uint16(len(b))
