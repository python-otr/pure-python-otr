#!/usr/bin/python2

import pickle
from potr.crypt import DSAKey

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
    newkey = DSAKey((k['y'],k['g'],k['p'],k['q'],k['x']))
    print 'Writing converted key for %s/%s to %s' % (oldkey['name'],
            oldkey['protocol'], path+'2')
    with open(path+'2', 'w') as f:
        pickle.dump(newkey, f)

if __name__ == '__main__':
    import sys
    convert(sys.argv[1])
