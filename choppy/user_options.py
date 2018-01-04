#! usr/bin/env/ python3

import argparse
import getpass
import os
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
        prog='choppy', description='chop -> encrypt -> ? -> decrypt -> merge')

    parser.add_argument(
        '--input', '-i', nargs='+', type=argparse.FileType('rb'), required=True,
        help='Input file(s) to chop or merge.')

    parser.add_argument(
        '--outdir', '-o', type=validate_directory, default=os.getcwd(),
        help='Output directory.')

    parser.add_argument(
        '--salt', '-s', type=argparse.FileType('rb'), required=True,
        help='File containing salt for key derivation.')

    parser.add_argument(
        '--password', '-p', type=argparse.FileType('rb'),
        help='Optional - file containing password for key.')


    # cmds = parser.add_mutually_exclusive_group()

    chop = parser.add_argument_group('Chop')

    chop.add_argument(
        '--chop', '-c', action='store_true', help='Chop and encrypt input file(s).')

    chop.add_argument(
        '-n', type=int, default=10, help='Create n partitions from each input file(s).')

    chop.add_argument(
        '--wobble', '-w', type=int, default=0,
        help='Randomize partition size (1-99).')

    mrg = parser.add_argument_group('Merge')

    mrg.add_argument(
        '--merge', '-m', action='store_true', help='Decrypt and merge input files.')


    # parser.add_argument('-v', '--version', action='version', version=VERSION)

    args = parser.parse_args()

    if not args.password:
        args.password = getpass.getpass(prompt='Password: ')

    return args


# ------------------------------------------------------------------------------
if __name__ =='__main__':
    args = parse_arguments()
    for k, v in vars(args).items():
        print(k, ':', v)
