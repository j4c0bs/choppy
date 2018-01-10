#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script for installing choppy.

To install, run:

    python setup.py install

"""

# Modified from https://github.com/pypa/sampleproject/blob/master/setup.py

from setuptools import setup, find_packages
from codecs import open
from os import path
import sys


if sys.argv[-1] == 'setup.py':
    print("To install choppy, run 'python setup.py install'\n")

if sys.version_info[:3] < (3, 6):
    print('choppy requires Python 3.6 or later ({}.{}.{} detected)'.format(*sys.version_info[:3]))
    sys.exit(-1)


here = path.abspath(path.dirname(__file__))


setup(
    name='choppy',
    version='0.0.1',
    description='Partition, encrypt, decrypt, and reassemble files.',
    long_description=open('README.rst').read(),
    url='https://github.com/j4c0bs/choppy',
    author='Jeremy Jacobs',
    author_email='pub@j4c0bs.net',
    license='BSD',
    classifiers=[
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: End Users/Desktop',
        'Intended Audience :: Information Technology',
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3.6',
        'Topic :: Communications :: File Sharing',
        'Topic :: Security :: Cryptography',
        'Topic :: Utilities'
    ],

    keywords='cryptography partition',
    packages=find_packages(exclude=['docs']),
    python_requires='>3.6',
    install_requires=['cryptography'],
    extras_require={},
    package_data={'':['LICENSE.txt', 'MANIFEST.in', 'docs/*']},
    data_files=[],
    entry_points={
        'console_scripts':[
            'choppy=choppy.choppy:main'
        ],
    },
)
