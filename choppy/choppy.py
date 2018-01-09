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
    for k, v in vars(args).items():
        print(k, ':', v)
    print('\n')

    outdir = args.outdir

    if args.genkey:
        crypto.generate_keyfile(outdir=outdir)
    if args.genpw:
        crypto.generate_password(length=args.genpw, outdir=outdir)
    if args.gensalt:
        crypto.generate_salt(length=args.gensalt, outdir=outdir)

    if any((args.chop, args.merge, args.derkey)):
        valid_pw = (args.pw or args.passwordfile) and args.salt
        valid_kw = args.kw or args.keyfile

        if not (valid_kw or valid_pw):
            print('Missing key or password / salt')
            sys.exit(0)

        else:
            if valid_kw:
                if args.keyfile:
                    key = read_bytes_file(args.keyfile.name)
                else:
                    key = args.kw
            else:
                if args.passwordfile:
                    password = read_password_file(args.passwordfile.name)
                else:
                    password = args.pw

                salt = read_bytes_file(args.salt.name)
                key = crypto.load_key(password, salt, args.iterations)

        if args.derkey:
            if valid_pw:
                crypto.generate_keyfile(key, outdir)
            else:
                print('Unable to derive key: missing password or salt')
                sys.exit(0)


        get_paths = lambda arg_cmd: tuple(infile.name for infile in arg_cmd)

        if args.chop:
            paths = get_paths(args.chop)
            chop_encrypt(paths, outdir, key, args.partitions, args.wobble, args.randfn)

        if args.merge:
            paths = get_paths(args.merge)
            decrypt_merge(paths, outdir, key)



# ------------------------------------------------------------------------------
if __name__ == '__main__':
    print('test code moved to choppy/tests/')
