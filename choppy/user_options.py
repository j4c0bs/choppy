#! usr/bin/env/ python3

import argparse
import getpass
import os
import sys

from choppy.version import VERSION

# ------------------------------------------------------------------------------
def confirm_directory(subdir):
    if os.path.exists(subdir):
        if not os.path.isdir(subdir):
            return False
    else:
        os.mkdir(subdir)
    return True


def validate_directory(user_dir):
    user_input = user_dir[:]
    user_dir = os.path.abspath(user_dir)
    status = confirm_directory(user_dir)
    if status:
        return user_dir
    else:
        msg = 'Unable to validate output directory: {}'.format(user_input)
        raise argparse.ArgumentTypeError(msg)


def show_tips():
    return """
---- choppy quick start ----

1. Generate random key file (key.txt):
    choppy util --gen-key

2. Chop file into 13 parts and encrypt:
    choppy chop -i file.txt -n 13 --use-key -k key.txt

3. Store or securely transfer chopped files and key.txt. File name, extension
have no effect on the merge process and can be modified as needed.

4. Decrypt merge files into original:
    choppy merge -i [infiles] --use-key -k key.txt

note: The md5 hash of the original input file is stored within the plaintext
chopped files. After merging, the output file is verified by comparing its md5
hash to the original. If verified, any encrypted file used in the merge will be
automatically removed.

"""


def load_pw_options(subcmd):

    pwgrp = subcmd.add_argument_group('Password Input')

    pwgrp.add_argument(
        '-p', '--pw-file', type=argparse.FileType('rb'),
        dest='passwordfile', metavar='infile',
        help='File containing password for key derivation.')

    pwgrp.add_argument(
        '-s', '--salt', type=argparse.FileType('rb'), metavar='infile',
        help='File containing salt for key derivation - required for use with password.')

    pwgrp.add_argument(
        '-t', '--iterations', type=int, default=10**5, metavar='n',
        help='Perform n iterations in key derivation. Defaults to 100,000.')


def load_keypass_options(subcmd, pfx):
    keypass_grp = subcmd.add_argument_group('Key / Password Select')

    kpg = keypass_grp.add_mutually_exclusive_group(required=True)

    kpg.add_argument(
        '--use-key', action='store_true', dest='use_key',
        help='Enables usage of key for {}cryption. Enter in secure prompt or specify file with -k.'.format(pfx))

    kpg.add_argument(
        '--use-pw', action='store_true', dest='use_pw',
        help='Enables usage of password, salt, iterations for {}cryption. Enter in secure prompt or specify file with -p.'.format(pfx))

    key_opt = subcmd.add_argument_group('Key Input')

    key_opt.add_argument(
        '-k', '--key-file', type=argparse.FileType('rb'),
        dest='keyfile', metavar='infile',
        help='File containing base64 encoded 32 byte key.')

    load_pw_options(subcmd)


def parse_arguments():
    """Parse command line arguments."""

    parser = argparse.ArgumentParser(
        prog='choppy', description='chop -> encrypt -> (?) -> decrypt -> merge',
        allow_abbrev=False)

    parser.set_defaults(kw='', pw='')
    parser.set_defaults(passwordfile=None, keyfile=None)
    parser.set_defaults(use_pw=False, use_key=False)

    subparsers = parser.add_subparsers(
        dest='command', metavar='[chop | merge | derive | util]',
        help='see docs/usage for more information')

    chp = subparsers.add_parser('chop')
    mrg = subparsers.add_parser('merge')
    derkey = subparsers.add_parser('derive')
    util = subparsers.add_parser('util')

    # --------------------------------------------------------------------------
    chop_grp = chp.add_argument_group('Chop')

    chop_grp.add_argument(
        '-i', '--input', nargs='+', type=argparse.FileType('rb'), metavar='infile',
        help='Input file(s) to chop and encrypt.')

    chop_grp.add_argument(
        '-n', type=int, default=10, dest='partitions', metavar='n',
        help='Create n partitions from each input file(s).')

    chop_grp.add_argument(
        '-w', '--wobble', type=int, default=0, metavar='n', choices=range(1, 100),
        help='Randomize partition size (1-99).')

    chop_grp.add_argument(
        '-r', '--randfn', action='store_true',
        help='Use random file names for partitions instead of numeric.')

    load_keypass_options(chp, pfx='en')

    # --------------------------------------------------------------------------
    mrg_grp = mrg.add_argument_group('Merge')

    mrg_grp.add_argument(
        '-i', '--input', nargs='+', type=argparse.FileType('rb'), metavar='infile',
        help='Input files to decrypt and merge.')

    load_keypass_options(mrg, pfx='de')

    # --------------------------------------------------------------------------
    load_pw_options(derkey)

    # --------------------------------------------------------------------------
    gen_grp = util.add_argument_group('Utilities')

    gen_grp.add_argument(
        '-k', '--gen-key', action='store_true', dest='genkey',
        help='Write file containing a randomly generated password of n characters.')

    gen_grp.add_argument(
        '-p', '--gen-pw', type=int, default=0, metavar='n', dest='genpw',
        help='Write file containing randomly generated password of n characters.')

    gen_grp.add_argument(
        '-s', '--gen-salt', type=int, default=0, metavar='n', dest='gensalt',
        help='Write file containing randomly generated salt of n bytes. Standard: 32')

    gen_grp.add_argument(
        '-r', '--repeat', type=int, default=1, metavar='n',
        help='Generate n files per command.')

    # --------------------------------------------------------------------------
    for grp in (chp, mrg, derkey, util):
        grp.add_argument(
            '-o', '--outdir', type=validate_directory, default=os.getcwd(),
            help='Output directory.')

    parser.add_argument('-v', '--version', action='version', version=VERSION)
    parser.add_argument('-q', action='store_true', help='show quick start and exit')

    args = parser.parse_args()

    if args.q:
        print(show_tips())
        sys.exit(0)

    if args.command != 'util':

        if args.use_key and not args.keyfile:
            args.kw = getpass.getpass(prompt='Key: ')

        if args.use_pw or args.command == 'derive':
            args.use_pw = True

            if not args.salt:
                print('salt file required for password use.')
                sys.exit(0)

            if not args.passwordfile:
                args.pw = getpass.getpass(prompt='Password: ')

    return args


# ------------------------------------------------------------------------------
if __name__ =='__main__':
    args = parse_arguments()
    print('\n')
    for k, v in vars(args).items():
        print(k, ':', v)
    print('\n')
