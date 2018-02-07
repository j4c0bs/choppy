# -*- coding: utf-8 -*-

"""
Choppy public functions
-----------------------
chop, chop_encrypt, merge, decrypt_merge

Choppy public module
--------------------
crypto


copyright: (c) Jeremy Jacobs 2017-2018
license: BSD-2-Clause see LICENSE.txt for details
"""

from choppy.chop import chop, chop_encrypt
from choppy.merge import merge, decrypt_merge
from choppy import crypto
from choppy.version import VERSION as __version__

__all__ = ['__version__', 'chop', 'chop_encrypt', 'merge', 'decrypt_merge', 'crypto']
