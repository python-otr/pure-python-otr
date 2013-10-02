#!/usr/bin/python
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

from potr.compatcrypto.pycrypto import DSAKey

def parse(tokens):
    key = tokens.pop(0)[1:]

    parsed = {key:{}}

    while tokens:
        token = tokens.pop(0)
        if token.endswith(')'):
            if token[:-1]:
                val = token[:-1].strip('"')
                if val.startswith('#') and val.endswith('#'):
                    val = int(val[1:-1], 16)
                parsed[key] = val
            return parsed, tokens
        if token.startswith('('):
            pdata, tokens = parse([token]+tokens)
            parsed[key].update(pdata)

    return parsed, []

def convert(path):
    with open(path, 'r') as f:
        text = f.read().strip()
    tokens = text.split()
    oldkey = parse(tokens)[0]['privkeys']['account']

    k = oldkey['private-key']['dsa']
    newkey = DSAKey((k['y'],k['g'],k['p'],k['q'],k['x']), private=True)
    print('Writing converted key for %s/%s to %s' % (oldkey['name'],
            oldkey['protocol'], path+'2'))
    with open(path+'3', 'wb') as f:
        f.write(newkey.serializePrivateKey())

if __name__ == '__main__':
    import sys
    convert(sys.argv[1])
