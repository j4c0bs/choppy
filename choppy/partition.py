#! usr/bin/env/ python3

"""
Functions for calculating and randomizing partition sizes.
"""

from itertools import compress
from random import choice as rand_choice
from random import randint, shuffle
# ------------------------------------------------------------------------------


def byte_lengths(n_bytes, n_partitions):
    """Calculates evenly distributed byte reads for given file size.

    Args:
        n_bytes: int - total file size in bytes
        n_partitions: int - number of file partitions

    Returns:
        iterable of ints
    """

    chunk_size = n_bytes // n_partitions
    byte_reads = [chunk_size] * n_partitions
    for ix in range(n_bytes % n_partitions):
        byte_reads[ix] += 1
    return tuple(byte_reads)


def wobbler(byte_reads, percent):
    """Randomizes byte read amounts.

    Args:
        byte_reads: iterable of ints
        percent: int or float < 1

    Returns:
        iterable of ints with sum == sum of byte_reads
    """

    rdlist = list(byte_reads)

    if percent > 1:
        percent /= 100

    ave = sum(rdlist) // len(rdlist)
    delta = int(ave * percent)
    min_v, max_v = (ave - delta, ave + delta)
    in_bounds = lambda x: min_v <= x <= max_v

    def random_offset():
        return randint(1, delta) * rand_choice((-1, 1))

    indices = [i for i in range(len(rdlist))]

    def randomize_ix():
        shuffle(indices)

    for ix, n in enumerate(rdlist):
        offset = random_offset()

        if in_bounds(n + offset):
            rdlist[ix] += offset

            randomize_ix()
            mask = (in_bounds(rdlist[rx] - offset) for rx in indices)
            rand_ix = tuple(compress(indices, mask))

            if len(rand_ix) > 1:
                for rx in rand_ix:
                    if rx != ix:
                        break
            else:
                rx = ix

            rdlist[rx] -= offset

    if sum(rdlist) == sum(byte_reads):
        return tuple(rdlist)
    else:
        return byte_reads
