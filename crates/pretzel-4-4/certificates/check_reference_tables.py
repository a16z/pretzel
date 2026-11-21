#!/usr/bin/env python3
"""Recompute every entry of the reference tables of Pretzel-(4,4) and Pretzel-(5,5).

Standard library only. For each crate this reads the base theta = THETA_NUM / 2^256 and
the weights PROPOSAL_W0, WS, WE from params.rs, and the tables EVEN, ODD, SECRET, ERROR
from reference_tables.rs. The ideal mass of z is p_z = theta^(w z^2) / Z, with Z the sum
of theta^(w y^2) over all integers y of the stated parity. The check passes when the count
of every z (the difference of consecutive endpoints) equals floor(2^32 p_z), and that
floor is zero for the first z on either side of the table (p_z decreases in |z|, so it is
then zero for every z further out). Each floor is decided by an interval enclosure of
2^32 p_z whose two ends have the same integer part; the run fails otherwise.

python3 -B check_reference_tables.py [--self-test]
"""
from fractions import Fraction
from pathlib import Path
import re
import sys

BITS = 512
UNIT = 1 << BITS
CRATES = Path(__file__).resolve().parents[2]
# Crate, params.rs, tables, and the words of a row (leading, other head, error).
CASES = [('pretzel-4-4', 'pretzel-4-4/core/src/params.rs',
          'pretzel-4-4/certificates/rank4-spread/reference_tables.rs', (256, 1024, 1024)),
         ('pretzel-5-5', 'pretzel-5-5/src/params.rs',
          'pretzel-5-5/certificates/rank5-dither/reference_tables.rs', (256, 1280, 1280))]


def mul(a, b):
    return a[0]*b[0] >> BITS, -(-a[1]*b[1] >> BITS)


def power(a, n):
    result = (UNIT, UNIT)
    while n:
        if n & 1:
            result = mul(result, a)
        a, n = mul(a, a), n >> 1
    return result


def floors(theta, weight, parity):
    """Map z to floor(2^32 p_z) for every z of the lattice with a nonzero floor."""
    base = (theta << (BITS-256), theta << (BITS-256))
    values, y = {}, 0 if parity is None else parity
    while not values or values[y_last][1] >> (BITS-300):
        values[y] = power(base, weight*y*y)
        y_last, y = y, y+(1 if parity is None else 2)
    lo = sum(v[0]*(1 if z == 0 else 2) for z, v in values.items())
    hi = sum(v[1]*(1 if z == 0 else 2) for z, v in values.items())
    # Terms beyond y_last, over all integers: consecutive ratios are at most theta^(w(2 y_last+3)).
    first, ratio = power(base, weight*(y_last+1)**2), power(base, weight*(2*y_last+3))
    hi += -(-2*first[1]*UNIT // (UNIT-ratio[1]))
    out = {}
    for z, v in values.items():
        below, above = (v[0] << 32)//hi, (v[1] << 32)//lo
        assert below == above, ('enclosure does not decide the floor', z)
        if below:
            out[z] = out[-z] = below
    assert list(out) and all(abs(a) < y_last for a in out)
    return out


def tables(path):
    text = '\n'.join(line for line in path.read_text().splitlines() if not line.startswith('//'))
    out = {}
    for name in ('EVEN', 'ODD', 'SECRET', 'ERROR'):
        entries = re.findall(r'\((\d+),\s*(-?\d+)\)', re.search(name+r'[^=]*=\s*&\[(.*?)\];', text, re.S)[1])
        ends, values = [int(a) for a, _ in entries], [int(b) for _, b in entries]
        assert values == sorted(set(values)) and ends == sorted(set(ends)) and 0 < ends[0] and ends[-1] < 1 << 32
        out[name] = dict(zip(values, (b-a for a, b in zip([0]+ends, ends))))
    return out


def constants(path):
    text = path.read_text()
    limbs = re.search(r'const THETA_NUM_LIMBS: \[u64; 4\] = \[(.*?)\];', text, re.S)[1]
    theta = sum(int(x.replace('_', ''), 16) << (64*i) for i, x in enumerate(re.findall(r'0x[0-9a-f_]+', limbs)))
    w0, ws, we = (int(re.search(r'const '+n+r': u64 = (\d+);', text)[1]) for n in ('PROPOSAL_W0', 'WS', 'WE'))
    return theta, [('EVEN', w0, 0), ('ODD', w0, 1), ('SECRET', ws, None), ('ERROR', we, None)]


def check(theta, laws, table):
    for name, weight, parity in laws:
        assert table[name] == floors(theta, weight, parity), name+': an entry is not floor(2^32 p_z)'
    return {name: (1 << 32)-sum(counts.values()) for name, counts in table.items()}


def self_test():
    # Exact rational arithmetic on a small case: theta = 3/4, weight 1, all integers.
    theta = Fraction(3, 4)
    partial = sum(theta**(y*y) for y in range(-40, 41))
    tail = 2*theta**1681/(1-theta**83)
    exact = {z: (1 << 32)*theta**(z*z)/partial for z in range(-12, 13)}
    assert all(int(v) == int(v*partial/(partial+tail)) for v in exact.values())
    assert floors(3 << 254, 1, None) == {z: int(v) for z, v in exact.items() if int(v)}
    # One count moved by one, and one outermost entry removed, must both fail.
    name, params, path, _ = CASES[0]
    theta, laws = constants(CRATES/params)
    for change in ('count', 'support'):
        table = tables(CRATES/path)
        if change == 'count':
            table['SECRET'][0] -= 1
        else:
            del table['ERROR'][max(table['ERROR'])]
        try:
            check(theta, laws, table)
        except AssertionError:
            continue
        raise SystemExit('self-test: a changed table passed')
    print('PASS: exact small case; a changed count and a shortened table are rejected.')


if __name__ == '__main__':
    if sys.argv[1:] == ['--self-test']:
        self_test()
        sys.exit(0)
    assert not sys.argv[1:], 'usage: check_reference_tables.py [--self-test]'
    for name, params, path, (leading, head, error) in CASES:
        table = tables(CRATES/path)
        missing = check(*constants(CRATES/params), table)
        words = leading*max(missing['EVEN'], missing['ODD'])+head*missing['SECRET']+error*missing['ERROR']
        print(name, 'entries', {n: len(t) for n, t in table.items()}, 'words beyond the last endpoint', missing)
        print(name, 'every count equals floor(2^32 p_z); a row lacks a sample with probability at most',
              f'{words}/2^32')
    print('PASS')
