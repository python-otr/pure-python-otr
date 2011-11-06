#!/usr/bin/env python
#    Copyright 2011 Kjell Braden <afflux@pentabarf.de>
#
#    This file is part of the python-potr library.
#
#    python-potr is free software; you can redistribute it and/or modify
#    it under the terms of the GNU Lesser General Public License as published by
#    the Free Software Foundation; either version 3 of the License, or
#    (at your option) any later version.
#
#    python-potr is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Lesser General Public License for more details.
#
#    You should have received a copy of the GNU Lesser General Public License
#    along with this library.  If not, see <http://www.gnu.org/licenses/>.

from distutils.command.install_lib import install_lib
from distutils.core import setup

class checked_install_lib(install_lib):
    def run(self):
        try:
            import Crypto
            if Crypto.version_info < (2,1):
                print('\n**** WARNING: ****\nYou seem to have pyCrypto < 2.1 '
                        'installed. python-potr will need at least pyCrypto 2.1 to run\n\n')
        except:
            print('\n**** WARNING: ****\nYou don\'t seem to have pyCrypto '
                    'installed. python-potr will need at least pyCrypto 2.1 to run\n\n')

        install_lib.run(self)


setup(
    name='python-potr',
    version='1.0.0b3',
    description='pure Python Off-The-Record encryption',
    author='Kjell Braden',
    author_email='afflux@pentabarf.de',
    url='http://python-otr.pentabarf.de',
    packages=['potr'],
    package_dir={'potr':'src/potr'},

    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU Library or Lesser General Public License (LGPL)',
        'Programming Language :: Python :: 2',
        'Topic :: Communications :: Chat',
        'Topic :: Security :: Cryptography',
        ],

    cmdclass={'install_lib':checked_install_lib},
)
