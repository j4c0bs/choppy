#! usr/bin/env/ python3

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


def path_tuple(arg_infiles):
    return tuple(infile.name for infile in arg_infiles)


# ------------------------------------------------------------------------------
def main():
    """Entry point for CLI"""

    args = parse_arguments()

    outdir = args.outdir
    cmd = args.command

    if cmd == 'generate':
        for _ in range(args.repeat):
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

        if cmd == 'derive':
            crypto.generate_keyfile(key=key, outdir=outdir)

        elif cmd == 'chop':
            paths = path_tuple(args.input)
            chop_encrypt(paths, outdir, key, args.partitions, args.wobble, args.randfn)

        elif cmd == 'merge':
            paths = path_tuple(args.input)
            decrypt_merge(paths, outdir, key)


# ------------------------------------------------------------------------------
if __name__ == '__main__':
    print('test code moved to choppy/tests/')
