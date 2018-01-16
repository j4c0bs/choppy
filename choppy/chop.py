#! usr/bin/env/ python3

from itertools import chain, count
import os
from random import randint
from secrets import token_urlsafe
import tempfile

import choppy.partition as partition
from choppy.crypto import batch_encrypt, hash_str, md5_hash
from choppy.util import cat, fmt_hex, hex_16bit, hex_byte_read_len, encode_str_hex, HEX_FP

# ------------------------------------------------------------------------------
def convert_filename(fp):
    """Converts str filename into metadata hex format.

    Arg:
        fp: str filepath

    Returns:
        tuple (int, hex str)
        int is the byte length of the hex str
    """

    fn_hex = encode_str_hex(os.path.basename(fp))
    return hex_byte_read_len(fn_hex), fn_hex


def convert_hash(fp, hash_func=md5_hash):
    """ into metadata hex format.

    Args:
        fp: str filepath
        hash_func: function for calculating hash of file

    Returns:
        tuple (int, hash str)
        int is the byte length of the hash str
    """

    fn_hash = hash_func(fp)
    return hex_byte_read_len(fn_hash), fn_hash


def convert_nbytes(n):
    """Converts integer into metadata hex format.

    Args:
        n: int

    Returns:
        tuple (int, str hex)
        int is the byte length of the hash str
    """

    nhex = fmt_hex(n)
    return hex_byte_read_len(nhex), nhex


def partition_file(fp, outpaths, partitions, wobble=0):
    """Creates file partitions and embeds metadata for reassembly.

    Args:
        fp: str filepath
        outpaths: iterable (or generator) of filepaths for partitions
        partitions: int number of partitions to create
        wobble: int (1-99) percent to randomize partition size

    Yields:
        partition filepath
    """

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


def chop(filepaths, outdir, partitions, wobble, randfn):
    """Batch process function to manage partitioning multiple files.

    Args:
        filepaths: iterable of filepaths to partition
        outdir: str directory path
        partitions: int number of partitions to create
        wobble: int (1-99) percent to randomize partition size
        randfn: bool enabling random filenames instead of sequential numeric

    Returns:
        iterable of partition filepaths
    """

    chopped_paths = []
    for ix, fp in enumerate(filepaths):
        outpath_gen = generate_filepath(outdir, ix, randfn)
        chopped_paths.extend(partition_file(fp, outpath_gen, partitions, wobble))

    n_parts = len(chopped_paths)
    n_files = n_parts // partitions
    # print('>>> Files chopped: {}, Partitions generated: {}'.format(n_files, n_parts))
    return chopped_paths


def chop_encrypt(filepaths, outdir, key, partitions, wobble=0, randfn=False):
    """Batch process function to partition files then encrypt partitions.

    Args:
        filepaths: iterable of filepaths to partition
        outdir: str directory path
        key: str or bytes - encryption key
        partitions: int number of partitions to create
        wobble: int (1-99) percent to randomize partition size
        randfn: bool enabling random filenames instead of sequential numeric

    Returns:
        iterable of filepaths for encrypted partitions
    """

    with tempfile.TemporaryDirectory() as tmpdir:
        chopped_paths = chop(filepaths, tmpdir, partitions, wobble, randfn)
        encrypted_paths = batch_encrypt(key, chopped_paths, outdir)

    return encrypted_paths
