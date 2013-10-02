Python OTR
==========
This is a pure Python OTR implementation; it does not bind to libotr.

Install the potr Python module:

    sudo python setup.py install

__Dependencies__: pycrypto >= 2.1 (see [dlitz/pycrypto](https://github.com/dlitz/pycrypto))

Usage Notes
===========
This module uses pycrypto's RNG. If you use this package in your application and your application
uses `os.fork()`, make sure to call `Crypto.Random.atfork()` in both the parent and the child process.

Reporting bugs
==============
Please read the [FAQ](https://github.com/afflux/pure-python-otr/wiki) before submitting your
issue to the [tracker](https://github.com/afflux/pure-python-otr/issues).

libotr SWIG bindings
====================
python-otr.pentabarf.de and pyotr.pentabarf.de redirect here.
If you are still looking for the old C library bindings, they have moved
to <http://python-otr-old.pentabarf.de/>
