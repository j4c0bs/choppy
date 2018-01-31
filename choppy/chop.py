#! usr/bin/env/ python3

"""
Functions for file partioning and batch encrypting.
"""

from itertools import count
import os
from random import randint
from secrets import token_urlsafe
import tempfile

import choppy.partition as partition
from choppy.crypto import batch_encrypt, hash_str, md5_hash
from choppy import util

# ------------------------------------------------------------------------------
def convert_filename(fp):
    """Converts str filename into metadata [byte-read][bytes] format.

    Arg:
        fp: str filepath

    Returns:
        tuple (int, bytes)
        int: byte length
    """

    fn_b = bytes(os.path.basename(fp), 'utf-8')
    return util.byte_len(fn_b), fn_b


def convert_hash(fp, hash_func=md5_hash):
    """ into metadata [byte-read][bytes] format.

    Args:
        fp: str filepath
        hash_func: function for calculating hash of file

    Returns:
        tuple (int, hash)
        int: the byte length of the hash
    """

    fn_hash = hash_func(fp)
    return util.byte_len(fn_hash), fn_hash


def convert_nbytes(n):
    """Converts integer into metadata [byte-read][bytes] format.

    Args:
        n: int

    Returns:
        tuple (int, bytes)
        int: the byte length of the hash
    """

    if n.bit_length() <= 64:
        nbx = util.encode_uint64(n)
    else:
        nbx = util.encode_uint(n)

    return util.byte_len(nbx), nbx


def partition_file(fp, outpaths, nparts, wobble=0):
    """Creates file partitions and embeds metadata for reassembly.

    Args:
        fp: str filepath
        outpaths: iterable (or generator) of filepaths for partitions
        nparts: int number of partitions to create
        wobble: int (1-99) percent to randomize partition size

    Yields:
        partition filepath
    """

    byte_reads = partition.byte_lengths(os.path.getsize(fp), nparts)

    if wobble:
        byte_reads = partition.wobbler(byte_reads, wobble)

    fingerprint = util.CFP[:]
    group_id = hash_str(''.join(map(str, byte_reads)))
    id_tot = util.encode_uint16(nparts)

    group_block = util.bcat(fingerprint, group_id, id_tot)
    group_block.extend(util.bcat(*convert_filename(fp), *convert_hash(fp)))


    def metabytes(idx, nbytes):
        ix = util.encode_uint16(idx)
        cnb = convert_nbytes(nbytes)
        part_block = util.bcat(ix, *cnb)
        meta_block = b''.join((group_block, part_block))
        return meta_block


    with open(fp, 'rb') as file_:
        for ix, (nbytes, fp_out) in enumerate(zip(byte_reads, outpaths)):
            with open(fp_out, 'wb') as file_ix:
                file_ix.write(metabytes(ix, nbytes))
                file_ix.write(file_.read(nbytes))
                yield file_ix.name


def generate_filepath(outdir, sfx=0, randfn=False):
    """Filepath generator.

    Args:
        outdir: str directory path
        sfx: int numerical file extension suffix to differentiate groups of partitions
        randfn: bool enabling random filenames instead of sequential numeric

    Yields:
        str filepath
    """

    seen = set()

    for i in count(0):
        fn = token_urlsafe(randint(8, 16)) if randfn else i
        fp_out = os.path.join(outdir, '{}.chp.{}'.format(fn, sfx))
        if fp_out not in seen:
            seen.add(fp_out)
            yield fp_out


def chop(filepaths, outdir, nparts, wobble, randfn):
    """Batch process function to manage partitioning multiple files.

    Args:
        filepaths: iterable of filepaths to partition
        outdir: str directory path
        nparts: int number of partitions to create
        wobble: int (1-99) percent to randomize partition size
        randfn: bool enabling random filenames instead of sequential numeric

    Returns:
        iterable of partition filepaths
    """

    chopped_paths = []
    for ix, fp in enumerate(filepaths):
        outpath_gen = generate_filepath(outdir, ix, randfn)
        chopped_paths.extend(partition_file(fp, outpath_gen, nparts, wobble))

    n_parts = len(chopped_paths)
    n_files = n_parts // nparts

    print('>>> Files chopped: {}, Partitions generated: {}'.format(n_files, n_parts))
    return chopped_paths


def chop_encrypt(filepaths, outdir, key, nparts, wobble=0, randfn=False):
    """Batch process function to partition files then encrypt partitions.

    Args:
        filepaths: iterable of filepaths to partition
        outdir: str directory path
        key: str or bytes - encryption key
        nparts: int number of partitions to create
        wobble: int (1-99) percent to randomize partition size
        randfn: bool enabling random filenames instead of sequential numeric

    Returns:
        iterable of filepaths for encrypted partitions
    """

    with tempfile.TemporaryDirectory() as tmpdir:
        chopped_paths = chop(filepaths, tmpdir, nparts, wobble, randfn)
        encrypted_paths = batch_encrypt(key, chopped_paths, outdir)

    return encrypted_paths
