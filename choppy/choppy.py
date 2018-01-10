#! usr/bin/env/ python3

import sys

from choppy import crypto
from choppy.chop import chop_encrypt
from choppy.merge import decrypt_merge
from choppy.user_options import parse_arguments

# ------------------------------------------------------------------------------
def read_password_file(fp):
    with open(fp, 'r') as infile:
        pw = infile.read().strip()
    return pw


def read_bytes_file(fp):
    with open(fp, 'rb') as infile:
        data = infile.read()
    return data


# ------------------------------------------------------------------------------
def main():
    args = parse_arguments()

    print('\n')
    print('-'*80)
    for k, v in vars(args).items():
        print(k, ':', v)
    print('-'*80)
    print('\n')

    outdir = args.outdir
    cmd = args.command

    if cmd == 'util':
        if args.genkey:
            crypto.generate_keyfile(outdir=outdir)
        if args.genpw:
            crypto.generate_password(length=args.genpw, outdir=outdir)
        if args.gensalt:
            crypto.generate_salt(length=args.gensalt, outdir=outdir)

    else:
        if args.use_key:
            if args.keyfile:
                key = read_bytes_file(args.keyfile.name)
            else:
                key = args.kw
        else:
            if args.passwordfile:
                password = read_password_file(args.passwordfile.name)
            else:
                password = args.pw

            salt = read_bytes_file(args.salt)
            key = crypto.load_key(password, salt, args.iterations)

        get_paths = lambda arg_in: tuple(infile.name for infile in arg_in)

        if cmd == 'derive':
            crypto.generate_keyfile(key=key, outdir=outdir)

        elif cmd == 'chop':
            paths = get_paths(args.input)
            chop_encrypt(paths, outdir, key, args.partitions, args.wobble, args.randfn)

        elif cmd == 'merge':
            paths = get_paths(args.input)
            decrypt_merge(paths, outdir, key)


# ------------------------------------------------------------------------------
if __name__ == '__main__':
    print('test code moved to choppy/tests/')
