#! usr/bin/env/ python3

# import tempfile
#
#
# # ------------------------------------------------------------------------------
# def test_chop(fn, fnout, n=10):
#     start = perf_counter()
#
#     tmpdir = tempfile.TemporaryDirectory()
#
#     paths = tuple(partition_file(fn, tmpdir, n))
#     print('File partitioned:', len(paths))
#
#     merge_file(paths, fnout)
#     print('Files merged')
#
#     check = file_info(fn) == file_info(fnout)
#     print('Status:', check)
#
#     tmpdir.cleanup()
#
#     print('{:.4f} sec'.format(perf_counter() - start))
#
#
# # ------------------------------------------------------------------------------
