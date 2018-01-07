#! usr/bin/env/ python3

from collections import defaultdict
from itertools import chain, count, groupby
from operator import itemgetter
import os
from random import randint
import secrets
import shutil
import tempfile

import choppy.partition as partition
from choppy.crypto import batch_decrypt, batch_encrypt, md5_hash, hash_str
from choppy.util import cat, fmt_hex, hex_16bit, hex_byte_read_len, encode_str_hex, decode_hex_str

# ------------------------------------------------------------------------------
HEX_FP = encode_str_hex('ch0ppyFP')


def read_password_file(fp):
    with open(fp, 'r') as infile:
        pw = infile.read().strip()
    return pw


def read_salt_file(fp):
    with open(fp, 'rb') as infile:
        salt = infile.read()
    return salt


def convert_filename(fp):
    fn_hex = encode_str_hex(os.path.basename(fp))
    return hex_byte_read_len(fn_hex), fn_hex


def convert_hash(fp, hash_func=md5_hash):
    fn_hash = hash_func(fp)
    return hex_byte_read_len(fn_hash), fn_hash


def convert_nbytes(n):
    nhex = fmt_hex(n)
    return hex_byte_read_len(nhex), nhex


# ------------------------------------------------------------------------------
def chop_file(fp, fp_gen, partitions, wobble=0):

    byte_reads = partition.byte_lengths(os.path.getsize(fp), partitions)

    if wobble:
        byte_reads = partition.wobbler(byte_reads, wobble)

    id_tot = hex_16bit(partitions)
    fmap_end = cat(chain(convert_filename(fp), convert_hash(fp)))
    group_id = hash_str(cat(map(str, byte_reads)))


    def metabytes(idx, nbytes):
        ix = hex_16bit(idx)
        nb_rd, nb_hex = convert_nbytes(nbytes)
        metahex = cat((HEX_FP, group_id, ix, id_tot, nb_rd, nb_hex, fmap_end))
        return bytes.fromhex(metahex)


    with open(fp, 'rb') as file_:
        for ix, (nbytes, fp_out) in enumerate(zip(byte_reads, fp_gen)):
            with open(fp_out, 'wb') as file_ix:
                file_ix.write(metabytes(ix, nbytes))
                file_ix.write(file_.read(nbytes))
                yield file_ix.name


# ------------------------------------------------------------------------------
def read_int(file_, r=2):
    try:
        n = int(file_.read(r).hex(), 16)
    except ValueError:
        n = 0
    return n


def load_paths(paths):

    metadata = defaultdict(list)

    for fp in paths:
        with open(fp, 'rb') as file_ix:

            fingerprint = file_ix.read(8).hex()
            if fingerprint != HEX_FP:
                continue

            group_id = file_ix.read(16).hex()

            ix = read_int(file_ix)
            tot = read_int(file_ix)
            seek = 28

            read_next = read_int(file_ix)
            nbytes = int(file_ix.read(read_next).hex(), 16)
            seek += read_next + 2

            read_next = read_int(file_ix)
            filename = file_ix.read(read_next).hex()
            seek += read_next + 2

            read_next = read_int(file_ix)
            if read_next % 16:
                continue

            filehash = file_ix.read(read_next).hex()
            seek += read_next + 2

            metadata[(tot, group_id, filename, filehash)].append((ix, seek, nbytes, fp))

    return metadata


def find_valid_path_groups(paths):
    get_ix = itemgetter(0)
    metadata = load_paths(paths)

    valid_keys = (k for k, v in metadata.items() if len(v) >= k[0])

    for key in valid_keys:
        tot, group_id, filename, filehash = key
        metapaths = metadata[key]
        if sorted(set(map(get_ix, metapaths))) == [i for i in range(tot)]:
            metapaths.sort(key=get_ix)
            filename = decode_hex_str(filename)

            if len(metapaths) == tot:
                yield filename, filehash, metapaths

            else:
                filtered_paths = []
                for _, group in groupby(metapaths, get_ix):
                    fpaths = tuple(group)
                    filtered_paths.append(fpaths[0])

                yield filename, filehash, filtered_paths


def merge_partitions(meta_paths, fn):
    with open(fn, 'wb') as outfile:
        for _, seek, nbytes, fp in meta_paths:
            with open(fp, 'rb') as file_ix:
                file_ix.seek(seek)
                outfile.write(file_ix.read(nbytes))

            yield fp


def merge(filepaths, outdir):

    valid_groups = tuple(find_valid_path_groups(filepaths))

    trash_files = []

    if not valid_groups:
        print('>>> No partitions to merge from {} files'.format(len(filepaths)))

    else:
        for filename, filehash, valid_paths in valid_groups:
            filepath = os.path.join(outdir, filename)

            used_files = tuple(merge_partitions(valid_paths, filepath))
            status = md5_hash(filepath) == filehash

            if status:
                print('File contents verified for:\n\t', filepath)
                trash_files.extend(used_files)
            else:
                print('File contents unverified:\n\t', filepath, filehash)

    return trash_files


def cleanup_used_files(used_files, filepaths):
    basename = os.path.basename
    used_fn_set = set(basename(fp) for fp in used_files)
    trash_files = (fp for fp in filepaths if basename(fp) in used_fn_set)
    used_files.extend(trash_files)

    for fp in used_files:
        try:
            os.remove(fp)
        except OSError as e:
            print('Unable to remove file: {}'.format(fp))


def decrypt_and_merge(filepaths, outdir, key):
    with tempfile.TemporaryDirectory() as tmpdir:
        paths = batch_decrypt(key, filepaths, tmpdir)
        print('>>> Decrypted files:', len(paths))
        used_files = merge(paths, outdir)
        cleanup_used_files(used_files, filepaths)


# ------------------------------------------------------------------------------
def generate_filename(outdir, sfx=0, numfn=True):
    seen = set()

    for i in count(0):
        fn = i if numfn else secrets.token_urlsafe(randint(8, 16))
        fp_out = os.path.join(outdir, '{}.chp.{}'.format(fn, sfx))
        if fp_out not in seen:
            seen.add(fp_out)
            yield fp_out


def chop(filepaths, outdir, partitions, wobble=0, numfn=True, key=None, enc=True):

    chopped_paths = []

    with tempfile.TemporaryDirectory() as tmpdir:
        paths = []
        for ix, fp in enumerate(filepaths):
            fp_gen = generate_filename(tmpdir, sfx=ix, numfn=numfn)
            paths.extend(chop_file(fp, fp_gen, partitions, wobble))

        print('> Files chopped: {}'.format(len(paths) // partitions))

        if enc:
            if key:
                print('Encrypting chopped files.')
                chopped_paths.extend(batch_encrypt(key, paths, outdir))
            else:
                print('Key not loaded. No file partitions saved.')
        else:
            outpath = lambda fp_in: os.path.join(outdir, os.path.basename(fp_in))
            for fp in paths:
                chopped_paths.append(shutil.move(fp, outpath(fp)))

    return chopped_paths


# ------------------------------------------------------------------------------
if __name__ == '__main__':
    print('test code moved to choppy/tests/')
