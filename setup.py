#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
from setuptools import setup
import os
import sys
from agavedb import __version__

readme = open('README.rst').read()
HERE = os.path.dirname(os.path.abspath(__file__))


setup(
    name='agavedb',
    packages=['agavedb'],
    version=__version__,
    description='Multiuser-aware key/value store built atop AgaveAPI metadata',
    author='Matthew W. Vaughn',
    author_email='vaughn@tacc.utexas.edu',
    url='https://github.com/TACC/agavedb',
    package_dir={'agavedb': 'agavedb'},
    data_files=[('', ['VERSION', 'requirements.txt'])],
    install_requires=['attrdict>=2.0.0', 'agavepy>=0.7.0', 'hashids>=1.2.0'],
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
