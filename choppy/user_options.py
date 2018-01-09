#! usr/bin/env/ python3

import argparse
import getpass
import os

# from choppy.version import VERSION
VERSION = '0.0.1'
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


def parse_arguments():
    """Parse command line arguments."""

    parser = argparse.ArgumentParser(
        prog='choppy', description='chop -> encrypt -> ? -> decrypt -> merge',
        allow_abbrev=False)

    parser.set_defaults(kw='', pw='')
    parser.set_defaults(kw_prompt=False, pw_prompt=False)
    parser.set_defaults(passwordfile=None, keyfile=None)

    subparsers = parser.add_subparsers(dest='command')
    key_grp = subparsers.add_parser('key')
    pw_grp = subparsers.add_parser('password')

    # --------------------------------------------------------------------------
    chop_grp = parser.add_argument_group('Chop')

    chop_grp.add_argument(
        '-c', '--chop', nargs='+', type=argparse.FileType('rb'), metavar='infile',
        help='Input file(s) to chop and encrypt.')

    chop_grp.add_argument(
        '-n', type=int, default=10, dest='partitions', metavar='n',
        help='Create n partitions from each input file(s).')

    chop_grp.add_argument(
        '-w', '--wobble', type=int, default=0, metavar='1-99', choices=range(1, 100),
        help='Randomize partition size (1-99).')

    chop_grp.add_argument(
        '-r', '--randfn', action='store_true',
        help='Generate random file names for partitions.')

    # --------------------------------------------------------------------------
    mrg_grp = parser.add_argument_group('Merge')

    mrg_grp.add_argument(
        '-m', '--merge', nargs='+', type=argparse.FileType('rb'), metavar='infile',
        help='Input files to decrypt and merge.')

    # --------------------------------------------------------------------------
    gen_grp = parser.add_argument_group('Utilities')

    k_opts = gen_grp.add_mutually_exclusive_group()

    k_opts.add_argument(
        '--gen-key', action='store_true', dest='genkey',
        help='Write file containing a randomly generated password of n characters.')

    k_opts.add_argument(
        '--der-key', action='store_true', dest='derkey',
        help='Derive key from salt, password and write to file.')

    gen_grp.add_argument(
        '--gen-pw', type=int, default=0, metavar='n', dest='genpw',
        help='Write file containing randomly generated password of n characters.')

    gen_grp.add_argument(
        '--gen-salt', type=int, default=0, metavar='n', dest='gensalt',
        help='Write file containing randomly generated salt of n bytes.')

    # --------------------------------------------------------------------------
    k_pf = key_grp.add_mutually_exclusive_group()

    k_pf.add_argument(
        '-k', '--key-file', type=argparse.FileType('rb'), dest='keyfile',
        metavar='infile', help='File containing base64 encoded 32 byte key.')

    k_pf.add_argument(
        '--key-prompt', action='store_true', dest='kw_prompt',
        help='Secure prompt to enter key as text.')

    pw_pf = pw_grp.add_mutually_exclusive_group()

    pw_pf.add_argument(
        '-p', '--pw-file', type=argparse.FileType('rb'), dest='passwordfile',
        metavar='infile', help='File containing password for key derivation.')

    pw_pf.add_argument(
        '--pw-prompt', action='store_true', dest='pw_prompt',
        help='Secure prompt to enter password as text.')

    pw_grp.add_argument(
        '-s', '--salt', type=argparse.FileType('rb'), metavar='infile',
        help='File containing salt for key derivation.')

    pw_grp.add_argument(
        '-t', '--iterations', type=int, default=10**5, metavar='n',
        help='Perform n iterations in key derivation. Defaults to 100,000.')

    # --------------------------------------------------------------------------
    parser.add_argument(
        '-o', '--outdir', type=validate_directory, default=os.getcwd(),
        help='Output directory.')

    parser.add_argument('-v', '--version', action='version', version=VERSION)

    args = parser.parse_args()


    if args.kw_prompt:
        args.kw = getpass.getpass(prompt='Key: ')

    if args.pw_prompt:
        args.pw = getpass.getpass(prompt='Password: ')


    return args


# ------------------------------------------------------------------------------
if __name__ =='__main__':
    args = parse_arguments()
    print('\n')
    for k, v in vars(args).items():
        print(k, ':', v)
    print('\n')
