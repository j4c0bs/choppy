#! usr/bin/env/ python3

import os

from os.path import abspath, dirname
import sys
parent_dir = dirname(abspath(dirname('__file__')))
sys.path.insert(0, parent_dir)

import unittest
import tempfile

from cryptography.fernet import Fernet

from choppy.chop import chop_encrypt
from choppy.merge import decrypt_merge
from choppy.crypto import md5_hash

# ------------------------------------------------------------------------------
def make_file(tmpdir, filesize=1024):
    fp = os.path.join(tmpdir, 'test_file.txt')
    with open(fp, 'xb') as outfile:
        outfile.write(os.urandom(filesize))
    return fp


class TestChopMerge(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()

        self.tmp_chop = os.path.join(self.tmpdir.name, 'chop')
        os.mkdir(self.tmp_chop)

        self.tmp_merge = os.path.join(self.tmpdir.name, 'merge')
        os.mkdir(self.tmp_merge)

        self.input_file = make_file(self.tmp_chop)
        self.input_file_hash = md5_hash(self.input_file)

        self.key = Fernet.generate_key()


    def test_chop_merge(self):
        _paths = [self.input_file]
        n_parts = 10
        encrypted_paths = chop_encrypt(_paths, self.tmp_chop, self.key, n_parts)
        self.assertEqual(n_parts, len(encrypted_paths))

        status, decrypted_paths = decrypt_merge(encrypted_paths, self.tmp_merge, self.key)
        self.assertTrue(all(status))

        decrypted_file = decrypted_paths[0]
        decrypted_file_hash = md5_hash(decrypted_file)
        self.assertEqual(self.input_file_hash, decrypted_file_hash)


    def tearDown(self):
        self.tmpdir.cleanup()


# ------------------------------------------------------------------------------
if __name__ == '__main__':
    unittest.main()
