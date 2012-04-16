Python OTR
==========
This is a pure Python OTR implementation; it does not bind to libotr.

Included in this package is a Gajim Python plugin to enable OTR support
in the Gajim XMPP/Jabber client. This plugin is called gotr.

Install the potr Python module:

    sudo python setup.py install

Note that this will install (but not activate) the gajim-otr plugin if a
gajim directory can be found in $PREFIX/share/gajim.

__Dependencies__: pycrypto >= 2.1 (see [dlitz/pycrypto](/dlitz/pycrypto))

Gajim OTR Plugin
================
As mentioned above, a gajim-otr plugin is provided in src/gajim-plugin and
can be installed using distutils.

The gajim search path can be changed manually by specifiying `--gajim-dir` to
the install commmand:

    sudo python setup.py install --gajim-dir=~/gajim

After installing, the plugin must be manually enabled in the Gajim plugin
interface.

libotr SWIG bindings
====================
python-otr.pentabarf.de and pyotr.pentabarf.de redirect here.
If you are still looking for the old C library bindings, they have moved
to <http://python-otr-old.pentabarf.de/>
