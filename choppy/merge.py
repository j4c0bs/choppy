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
    """Loads files and checks for valid metadata block.

    Chopped partition files start with an 8 byte hex fingerprint.
    Metadata format:
        [fingerprint][group id hash][index][index total]
        [read next][byte len of partition]
        [read next][encoded filename]
        [read next][file hash]

    Arg:
        paths: iterable of filepaths
    Returns:
        dict of filepaths grouped by matching metadata blocks
    """

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


def merge(filepaths, outdir, quiet=False):
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

    if not valid_groups and not quiet:
        print('> No partitions to merge from {} files'.format(len(filepaths)))

    else:
        for filename, filehash, valid_paths in valid_groups:
            filepath = os.path.join(outdir, filename)

            partition_files = tuple(merge_partitions(valid_paths, filepath))
            merge_status = md5_hash(filepath) == filehash

            status.append(merge_status)

            if merge_status:
                used_files.extend(partition_files)
            elif not merge_status and not quiet:
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


def decrypt_merge(filepaths, outdir, key, quiet=False):
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

        status, used_part_files = merge(candidates, outdir, quiet)
        trash_files = []

        for enc_fp, dec_fp in zip(filepaths, decrypted_paths):
            if dec_fp in used_part_files:
                trash_files.append(enc_fp)

        remove(trash_files)

    # if not quiet:
    #     print('>>> Merge complete and verified for {} file(s)'.format(len(status)))

    return status
