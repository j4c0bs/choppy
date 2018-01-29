#! usr/bin/env/ python3

from collections import defaultdict
from itertools import groupby
from operator import itemgetter
import os
import tempfile

from choppy.crypto import batch_decrypt, md5_hash
from choppy import util

# ------------------------------------------------------------------------------
def load_paths(paths):
    """Loads files and checks for valid metadata block.

    Chopped partition files start with a 16 byte fingerprint.
    Metadata format:
        [fingerprint][group id hash][index total] ||
        [read next][encoded filename][read next][file hash] ||
        [index][read next][byte len of partition]

        [16][16][2]
        [2][read value][2][read value]
        [2][2][read value]

    Arg:
        paths: iterable of filepaths
    Returns:
        dict of filepaths grouped by matching metadata blocks
    """

    metadata = defaultdict(list)

    for fp in paths:
        with open(fp, 'rb') as file_ix:

            seek = 0

            fingerprint = file_ix.read(16)
            seek += 16
            if fingerprint != util.CFP:
                continue

            group_id = file_ix.read(16)
            seek += 16

            ix_tot = util.decode_uint16(file_ix.read(2))
            seek += 2

            read_next = util.decode_uint16(file_ix.read(2))
            seek += 2
            filename = file_ix.read(read_next).decode('utf-8')
            seek += read_next

            read_next = util.decode_uint16(file_ix.read(2))
            seek += 2
            if read_next % 16:
                continue
            filehash = file_ix.read(read_next)
            seek += read_next

            ix = util.decode_uint16(file_ix.read(2))
            seek += 2

            read_next = util.decode_uint16(file_ix.read(2))
            seek += 2
            nbytes = util.decode_uint(file_ix.read(read_next))
            seek += read_next

            group_key = (ix_tot, group_id, filename, filehash)
            metadata[group_key].append((ix, seek, nbytes, fp))

    return metadata


def find_valid_path_groups(paths):
    """Inspects and validates path groups by metadata.

    Arg:
        paths: iterable of filepaths with candidate partitions

    Yields:
        tuple (str filename, input file hash, iterable of partition filepaths)
    """

    get_ix = itemgetter(0)
    metadata = load_paths(paths)

    valid_keys = (k for k, v in metadata.items() if len(v) >= k[0])

    for key in valid_keys:
        tot, group_id, filename, filehash = key
        metapaths = metadata[key]
        if sorted(set(map(get_ix, metapaths))) == [i for i in range(tot)]:
            metapaths.sort(key=get_ix)

            if len(metapaths) == tot:
                yield filename, filehash, metapaths

            else:
                filtered_paths = []
                for _, group in groupby(metapaths, get_ix):
                    fpaths = tuple(group)
                    filtered_paths.append(fpaths[0])

                yield filename, filehash, filtered_paths


def merge_partitions(meta_paths, fn):
    """Recreates original input file from decrypted file partitions.

    Arg:
        meta_paths: dict of sorted iterable of partition file paths
        fn: str filepath out

    Yields:
        str filepath for merged file
    """

    with open(fn, 'wb') as outfile:
        for _, seek, nbytes, fp in meta_paths:
            with open(fp, 'rb') as file_ix:
                file_ix.seek(seek)
                outfile.write(file_ix.read(nbytes))

            yield fp


def merge(filepaths, outdir):
    """Merges groups of valid partitions and confirms reassembled file is
        identical to original input file.

    Args:
        filepaths: iterable of str filepaths to merge
        outdir: directory output path

    Returns:
        tuple (bool, iterable of filepaths to remove)
    """

    valid_groups = tuple(find_valid_path_groups(filepaths))

    status = []
    used_files = []

    if not valid_groups:
        print('> No partitions to merge from {} files'.format(len(filepaths)))

    else:
        for filename, filehash, valid_paths in valid_groups:
            filepath = os.path.join(outdir, filename)

            partition_files = tuple(merge_partitions(valid_paths, filepath))
            merge_status = md5_hash(filepath) == filehash

            status.append(merge_status)

            if merge_status:
                used_files.extend(partition_files)
            elif not merge_status:
                print('> File contents unverified:\n\t', os.path.relpath(filepath), filehash)

    return status, used_files


def remove(filepaths):
    """Removes files.

    Args:
        filepaths: iterable of filepaths to remove

    Raises:
        OSError if file cannot be removed
    """

    for fp in filepaths:
        try:
            os.remove(fp)
        except OSError as e:
            print('> Unable to remove file: {}'.format(fp))


def decrypt_merge(filepaths, outdir, key):
    """Decrypts, merges valid files, and removes used partition files.

    Arg:
        filepaths: iterable of str filepaths to merge
        outdir: directory output path
        key: cryptographic key for decrypting input files

    Returns:
        iterable of bool
    """

    status = []

    with tempfile.TemporaryDirectory() as tmpdir:
        decrypted_paths = batch_decrypt(key, filepaths, tmpdir)
        candidates = [fp for fp in decrypted_paths if fp]

        status, used_part_files = merge(candidates, outdir)
        trash_files = []

        for enc_fp, dec_fp in zip(filepaths, decrypted_paths):
            if dec_fp in used_part_files:
                trash_files.append(enc_fp)

        remove(trash_files)


    verified_mrg = sum(status)
    failed_mrg = len(status) - verified_mrg

    print('>>> Merge complete and verified for {} file(s)'.format(verified_mrg))

    if failed_mrg:
        print('>>> Unable to verify merge for {} file(s)'.format(failed_mrg))

    return status
