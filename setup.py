#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
from setuptools import setup
import os
import sys
from agavedb import __version__

HERE = os.path.dirname(os.path.abspath(__file__))
readme = open(os.path.join(HERE, 'README.rst')).read()
requires = [pkg for pkg in open(
    os.path.join(HERE, 'requirements.txt')).readlines()]

setup(
    name='agavedb',
    packages=['agavedb'],
    version=__version__,
    long_description=readme,
    install_requires=requires,
    description='Multiuser-aware key/value store built atop AgaveAPI metadata',
    author='Matthew W. Vaughn',
    author_email='vaughn@tacc.utexas.edu',
    url='https://github.com/TACC/agavedb',
    package_dir={'agavedb': 'agavedb'},
    data_files=[('', ['requirements-travis.txt', 'requirements.txt'])],
    license="BSD",
    keywords='',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Natural Language :: English',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Operating System :: OS Independent',
        'Environment :: Other Environment',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
