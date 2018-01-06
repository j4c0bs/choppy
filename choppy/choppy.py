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
from choppy.crypto import batch_encrypt, md5_hash, hash_str
from choppy.util import cat, fmt_hex, hex_16bit, hex_byte_read_len, encode_str_hex, decode_hex_str

# ------------------------------------------------------------------------------
HEX_FP = encode_str_hex('ch0ppyFP')


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


def merge_file(meta_paths, fn):
    with open(fn, 'wb') as outfile:
        for _, seek, nbytes, fp in meta_paths:
            with open(fp, 'rb') as file_ix:
                file_ix.seek(seek)
                outfile.write(file_ix.read(nbytes))


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



# def find_valid_path_groups(paths):
#     get_ix = itemgetter(0)
#     metadata = load_paths(paths)
#
#     valid_keys = (k for k, v in metadata.items() if k[0] == len(v))
#
#     for key in valid_keys:
#         tot, filename, filehash = key
#         vals = metadata[key]
#         if sorted(map(get_ix, vals)) == [i for i in range(tot)]:
#             vals.sort(key=get_ix)
#             filename = decode_hex_str(filename)
#             yield filename, filehash, vals
#
#
def recombine(paths, outdir):

    results = []

    valid_groups = tuple(find_valid_path_groups(paths))
    if not valid_groups:
        print('>>> No partitions to merge from {} files'.format(len(paths)))
        results.append(False)
    else:

        for filename, filehash, valid_paths in valid_groups:
            filepath = os.path.join(outdir, filename)
            merge_file(valid_paths, filepath)

            status = md5_hash(filepath) == filehash

            if status:
                print('File contents verified for:', filepath)
            else:
                print('File contents unverified:', filepath, filehash)

            results.append(status)

    return results


# ------------------------------------------------------------------------------
def generate_filename(outdir, sfx=0, numfn=True):
    for i in count(0):
        fn = i if numfn else secrets.token_urlsafe(randint(8, 16))
        yield os.path.join(outdir, '{}.chp.{}'.format(fn, sfx))


def chop(filepaths, outdir, partitions, wobble=0, key=None, numfn=True, enc=True):

    chopped_paths = []

    with tempfile.TemporaryDirectory() as tmpdir:
        paths = []
        for ix, fp in enumerate(filepaths):
            fp_gen = generate_filename(tmpdir, sfx=ix, numfn=numfn)
            paths.extend(chop_file(fp, fp_gen, partitions, wobble))

        print('> Files chopped: {}'.format(len(paths) // partitions))

        if enc:
            if key:
                batch_encrypt(key, paths, outdir)
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
