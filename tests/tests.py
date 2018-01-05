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
#     paths = tuple(partition_file(fn, tmpdir.name, n))
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



# def test_wobbler(t=1000):
#     errors = []
#     parts = [3 * i for i in range(1, 5)]
#
#     for _ in range(t):
#         n_bytes = randint(1000, 10**9)
#         for p in parts:
#             br = calculate_byte_lengths(n_bytes, p)
#             w = wobbler(br, 99)
#             if sum(br) != sum(w):
#                 errors.append(n_bytes, p, br, w)
#             else:
#                 continue
#
#     if not errors:
#         print('No errors')
#
#     return errors
