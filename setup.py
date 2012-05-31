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

from distutils.command.install import install
from distutils.command.install_lib import install_lib
from distutils.core import setup
from distutils.sysconfig import get_config_vars
import os.path

class gajimpath_install(install):
    user_options = install.user_options + [
            ('gajim-dir=', None,
                "gajim directory to install plugin to [default: $PREFIX/share/gajim]"),
        ]

    def initialize_options(self):
        install.initialize_options(self)
        self.gajim_dir = None


class checked_install_lib(install_lib):

    def __init__(self, dist):
        install_lib.__init__(self, dist)
        self.packages = dist.packages

    def initialize_options(self):
        install_lib.initialize_options(self)
        self.data_prefix = None
        self.gajim_dir = None

    def finalize_options(self):
        install_lib.finalize_options(self)
        self.set_undefined_options('install',
                                   ('install_data', 'data_prefix'),
                                   ('gajim_dir', 'gajim_dir'),
                                   )

        # prepapre gajim directory paths
        if self.gajim_dir is None:
            self.gajim_dir = os.path.join(self.data_prefix,
                    os.path.normpath('share/gajim'))
        else:
            self.gajim_dir = os.path.expanduser(self.gajim_dir)
        self.gajim_plugin_dir = os.path.join(self.gajim_dir,
                os.path.normpath('plugins/gotr'))

    def run(self):
        """ checks for a valid pycrypto version before running the install
        process, prints a warning if none was found """
        try:
            import Crypto
            if Crypto.version_info < (2,1):
                print('\n**** WARNING: ****\nYou seem to have pyCrypto < 2.1 '
                        'installed. python-potr will need at least pyCrypto 2.1 to run\n\n')
        except:
            print('\n**** WARNING: ****\nYou don\'t seem to have pyCrypto '
                    'installed. python-potr will need at least pyCrypto 2.1 to run\n\n')

        install_lib.run(self)

    def install(self):
        """ overwrites the default install handler, which installs everything
        from build.
        Instead, we regularly install potr packages and redirect the gotr
        package to the gajim plugins directory, if there is a gajim directory in
        the current $PREFIX """

        outfiles = []

        if os.path.isdir(self.build_dir):
            for package in self.packages:
                packagedir = os.path.join(*list(package.split('.')))
                if package == 'gotr':
                    if os.path.isdir(self.gajim_dir):
                        outfiles += self.copy_tree(
                                os.path.join(self.build_dir, 'gotr'),
                                self.gajim_plugin_dir)
                else:
                    outfiles += self.copy_tree(
                            os.path.join(self.build_dir, packagedir),
                            os.path.join(self.install_dir, packagedir))
        else:
            self.warn("'%s' does not exist -- no Python modules to install" %
                      self.build_dir)
            return
        return outfiles


setup(
    name='python-potr',
    version='1.0.0b5',
    description='pure Python Off-The-Record encryption',
    author='Kjell Braden',
    author_email='afflux@pentabarf.de',
    url='http://python-otr.pentabarf.de',
    packages=['potr', 'potr.compatcrypto', 'gotr'],
    package_dir={'potr':'src/potr', 'gotr':'src/gajim-plugin/gotr'},
    package_data={'gotr':['*.ini', '*.ui']},

    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU Library or Lesser General Public License (LGPL)',
        'Programming Language :: Python :: 2',
        'Topic :: Communications :: Chat',
        'Topic :: Security :: Cryptography',
        ],

    cmdclass={'install_lib':checked_install_lib, 'install':gajimpath_install},
)
