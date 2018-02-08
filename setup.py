#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
from setuptools import setup
import os
import sys

readme = open('README.md').read()
HERE = os.path.dirname(os.path.abspath(__file__))


def get_version():
    version = '0.0.0'
    f = open(os.path.join(HERE, 'VERSION'), 'r')
    version = f.readline()
    f.close
    return version


setup(
    name='agavedb',
    packages=['agavedb'],
    version=get_version(),
    description='Multiuser-aware key/value store built atop AgaveAPI metadata',
    author='Matthew W. Vaughn',
    author_email='vaughn@tacc.utexas.edu',
    url='https://github.com/TACC/agavedb',
    package_dir={'agavedb': 'agavedb'},
    install_requires=['attrdict>=2.0.0', 'agavepy>=0.6.1', 'hashids>=1.2.0'],
    license="BSD",
    keywords='',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Natural Language :: English',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Operating System :: OS Independent',
        'Environment :: Other Environment',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
