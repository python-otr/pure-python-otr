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

    from setuptools.command.install import install
    from setuptools.command.install_lib import install_lib

    args['install_requires']=['pycrypto>=2.1']
except ImportError:
    print('\n*** setuptools not found! Falling back to distutils\n\n')
    from distutils.core import setup

    from distutils.command.install import install
    from distutils.command.install_lib import install_lib


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
    packages=['potr', 'potr.compatcrypto', 'gotr'],
    package_dir={'potr':'src/potr', 'gotr':'src/gajim-plugin/gotr'},
    package_data={'gotr':['*.ini', '*.ui']},


    name='python-potr',
    version='1.0.0b7',
    description='pure Python Off-The-Record encryption',
    long_description='''This is a pure Python OTR implementation; it does not bind to libotr.

Included in this package is a Gajim Python plugin to enable OTR support
in the Gajim XMPP/Jabber client. This plugin is called gotr.


**Installing this module will install (but not activate) the gajim-otr plugin if a
gajim directory can be found in $PREFIX/share/gajim.**

The gajim search path can be changed manually by specifiying ``--gajim-dir`` to
the install commmand::

    sudo python setup.py install --gajim-dir=~/gajim

After installing, the plugin must be manually enabled in the Gajim plugin
interface.

Reporting bugs
==============
Please read the `FAQ <https://github.com/afflux/pure-python-otr/wiki>`_ before submitting your
issue to the `tracker <https:///afflux/pure-python-otr/issues>`_.''',

    platforms='any',
    license='LGPLv3+',

    author='Kjell Braden',
    author_email='afflux@pentabarf.de',

    url='http://python-otr.pentabarf.de',
    download_url='https://github.com/afflux/pure-python-otr/downloads',

    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
        'Topic :: Communications :: Chat',
        'Topic :: Security :: Cryptography',
        ],

    cmdclass={'install_lib':checked_install_lib, 'install':gajimpath_install},

    **args
)
