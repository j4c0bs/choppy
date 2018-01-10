#! usr/bin/env/ python3

from collections import defaultdict
from itertools import groupby
from operator import itemgetter
import os
import tempfile

from choppy.crypto import batch_decrypt, md5_hash
from choppy.util import decode_hex_str, HEX_FP

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

    mrg_status = []
    trash_files = []

    if not valid_groups:
        print('>>> No partitions to merge from {} files'.format(len(filepaths)))

    else:
        for filename, filehash, valid_paths in valid_groups:
            filepath = os.path.join(outdir, filename)

            used_files = tuple(merge_partitions(valid_paths, filepath))
            status = md5_hash(filepath) == filehash
            mrg_status.append(status)

            if status:
                trash_files.extend(used_files)
            else:
                print('>>> File contents unverified:\n\t', os.path.relpath(filepath), filehash)

    return mrg_status, trash_files


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


def decrypt_merge(filepaths, outdir, key):

    status = False
    n_files = 0

    with tempfile.TemporaryDirectory() as tmpdir:
        paths = batch_decrypt(key, filepaths, tmpdir)
        mrg_status, used_files = merge(paths, outdir)
        cleanup_used_files(used_files, filepaths)
        status = all(mrg_status)
        n_files += len(mrg_status)

    if status:
        print('>>> Merge complete and verified for {} file(s)'.format(n_files))

    return status
