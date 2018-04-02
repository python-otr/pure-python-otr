#!/usr/bin/env python
#    Copyright 2011 Kjell Braden <afflux@pentabarf.de>
#
#    This file is part of the python-potr library.
#
#    python-potr is free software; you can redistribute it and/or modify
#    it under the terms of the GNU Lesser General Public License as published by
#    the Free Software Foundation; either version 3 of the License, or
#    any later version.
#
#    python-potr is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Lesser General Public License for more details.
#
#    You should have received a copy of the GNU Lesser General Public License
#    along with this library.  If not, see <http://www.gnu.org/licenses/>.

args = {}
try:
    from setuptools import setup

    from setuptools.command.install_lib import install_lib

    args['install_requires']=['pycrypto>=2.1']
except ImportError:
    print('\n*** setuptools not found! Falling back to distutils\n\n')
    from distutils.core import setup

    from distutils.command.install_lib import install_lib


setup(
    packages=['potr', 'potr.compatcrypto'],
    package_dir={'potr':'src/potr'},

    name='python-potr',
    version='1.0.2-alpha',
    description='pure Python Off-The-Record encryption',
    long_description='''Python OTR
==========
This is a pure Python OTR implementation; it does not bind to libotr.

Install the potr Python module:

    sudo python setup.py install

**Dependencies**: pycrypto >= 2.1 (see `dlitz/pycrypto <https://github.com/dlitz/pycrypto>`_)

Usage Notes
===========
This module uses pycrypto's RNG. If you use this package in your application and your application
uses ``os.fork()``, make sure to call ``Crypto.Random.atfork()`` in both the parent and the child process.

Reporting bugs
==============
Please read the `FAQ <https://github.com/afflux/pure-python-otr/wiki>`_ before submitting your
issue to the `tracker <https://github.com/afflux/pure-python-otr/issues>`_.''',

    platforms='any',
    license='LGPLv3+',

    author='Kjell Braden',
    author_email='afflux@pentabarf.de',

    url='http://python-otr.pentabarf.de',

    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
        'Topic :: Communications :: Chat',
        'Topic :: Security :: Cryptography',
        ],

    **args
)
