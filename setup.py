#!/usr/bin/env python

from distutils.core import setup

setup(name='python-otr', version='1.0-alpha',
    description='pure Python Off-The-Record encryption',
    author='Kjell Braden', author_email='afflux@pentabarf.de',
    url='http://python-otr.pentabarf.de', packages=['otr'],
    package_dir={'otr':'src/otr'})
