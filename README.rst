choppy
=======
chop -> encrypt -> (?) -> decrypt -> merge

Choppy partitions files and encrypts using symmetric authenticated cryptography.
After decryption, embedded metadata provides for the original input file to be recreated and verified.

Features:
- selectable number of partitions and randomized file size
- straight forward cryptographic key/password input
- encrypted file chunks can have name and extension altered with no detriment to recreating input file
- chunks from multiple files can be located within the same directory and the merge command will locate and
reassemble original input files



Installation
------------

Using pip:

::

    pip install choppy

Without pip - clone repository:

::

    python setup.py install



Requirements
------------

- Python 3.6 or greater
- cryptography 2.1.3

License
-------

choppy is released under the BSD 2-clause license. See
`LICENSE <https://raw.githubusercontent.com/j4c0bs/choppy/master/LICENSE.txt>`_
for details.
