"""Source readers and source-transcribed finite geometry; no native execution."""
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent

def digest(value):
    return hashlib.sha256(json.dumps(value, separators=(',', ':'), sort_keys=True).encode()).hexdigest()

def array(path, name):
    text = path.read_text()
    m = re.search(r'\b'+name+r'[^=]*=\s*&?\[(.*?)\];', text, re.S)
    assert m, (path, name)
    return m[1]

def integer_array(path, name):
    return [int(v.replace('_', ''), 0) if v.startswith('0x') else int(v.replace('_', ''))
            for v in re.findall(r'0x[\da-fA-F_]+|\d[\d_]*', array(path, name))]

def cdf(path, name):
    return [(int(a), int(b)) for a,b in re.findall(r'\((\d+),\s*(-?\d+)\)', array(path, name))]

def law(path, name):
    out = {}
    last = 0
    for end, value in cdf(path, name):
        assert last < end < 2**32 and value not in out
        out[value] = end-last
        last = end
    return out

def const(path, name):
    m = re.search(r'\bconst\s+'+name+r'\s*:[^=]+?=\s*([\d_]+(?:\s*\*\s*[\d_]+)*)\s*;', path.read_text())
    assert m, (path, name)
    value = 1
    for factor in m[1].split('*'):
        value *= int(factor.strip().replace('_',''))
    return value

def capture(text, pattern):
    """The integers captured by the pattern; every occurrence in the source must give the same ones."""
    found = {m.groups() for m in re.finditer(pattern, text)}
    assert len(found) == 1, (pattern, sorted(found))
    return [int(x) for x in found.pop()]

def parameters(folder):
    p = {n: const(folder/'params.rs', n) for n in
         ('Q','N','ELL','M','LQ','CAP_INF_HEAD','CAP_INF_RES','FORMAT_HEAD_LIMIT_LEAD','FORMAT_HEAD_LIMIT',
          'FORMAT_RES_LIMIT','CAP_EUC2_HEAD','CAP_EUC2_RES','CAP_Q20','PROPOSAL_W0','WS','WE')}
    p.update({n: const(folder/'dither_frame.rs', n) for n in
              ('MAX_CANDIDATES','EXPANSION_CANDIDATES','DITHER_COEFFICIENTS')})
    limbs = integer_array(folder/'params.rs', 'THETA_NUM_LIMBS')
    p['theta'] = sum(x << (64*i) for i,x in enumerate(limbs))
    s = re.sub(r'\s+', '', (folder/'rice_codec.rs').read_text())
    # The format limits are constants of params.rs; the codec must name them at its comparisons.
    limits = [p.pop(n) for n in ('FORMAT_HEAD_LIMIT_LEAD', 'FORMAT_HEAD_LIMIT', 'FORMAT_RES_LIMIT')]
    p['head_caps'] = capture(s, r'letcap=ifi<(\d+)\{crate::params::FORMAT_HEAD_LIMIT_LEADasu32\}'
                                r'else\{crate::params::FORMAT_HEAD_LIMITasu32\};') + limits[:2]
    p['quotient_cap'] = capture(s, r'quotient>(\d+)')[0]
    p['rice_shifts'] = capture(s, r'letk=ifi<256\{(\d+)\}else\{(\d+)\}')
    # The exception limit is a literal in the source.
    p['label_exceptions'] = capture(s, r'EXCEPTIONS:usize=(\d+);')[0]
    named = set(re.findall(r'r\.unsigned_abs\(\)>([\w:]+?)asu32', s))
    assert named == {'crate::params::FORMAT_RES_LIMIT'}, named
    assert not re.search(r'letcap=ifi<\d+\{\d|r\.unsigned_abs\(\)>\d', s), 'a format limit written as a literal'
    p['residual_cap'] = limits[2]
    p['exception_first_index'] = capture(s, r'k>=(\d+)')[0]
    p['head_count'] = (p['ELL']+1)*p['N']
    p['residual_count'] = p['M']*p['N']
    return p

def centers(q, levels):
    left = [(q*j+levels-1)//levels for j in range(levels+1)]
    out, even = [], 0
    for a,b in zip(left,left[1:]):
        size = b-a
        out.append(a+(size-1)//2+(int(size%2==0)*(even%2)))
        even += int(size%2==0)
    return out

def centered(v, q=7681):
    return (v+q//2)%q-q//2

def local_labels(x, c):
    q = 7681
    j = 34*x//q
    dl, dr = centered(x-c[(j-1)%34]), centered(c[(j+1)%34]-x)
    s = -1 if dl<=dr else 1
    return [j,(j+s)%34,(j-s)%34,(j+2*s)%34]

def residual_rows(error, p):
    q, levels, cap = p['Q'],p['LQ'],p['residual_cap']
    c = centers(q,levels)
    assert max(map(abs,error)) < q
    prefix = [0]
    for z in range(-q,q+1):
        prefix.append(prefix[-1]+error.get(z,0))
    def mass(lo,hi):
        lo,hi = max(lo,-q),min(hi,q+1)
        return 0 if hi<=lo else prefix[hi+q]-prefix[lo+q]
    rows, recovery = [], []
    for x in range(q):
        labels = local_labels(x,c)
        local = {u:j for j,u in enumerate(labels) if u is not None}
        recovery.append(labels)
        row = []
        for u in range(levels):
            a = abs(centered(c[u]-x))
            assert a>cap or u in local, ('unaccounted recovery failure',x,u,a)
            lo,hi = (q*u+levels-1)//levels-x,(q*(u+1)+levels-1)//levels-x
            n = sum(mass(lo+k*q,hi+k*q) for k in (-1,0,1))
            if n:
                row.append((a,local.get(u),n))
        assert sum(n for _,_,n in row)==sum(error.values())
        rows.append(row)
    return rows, dict(centers=c, recovery_sha256=digest(recovery), contexts=q,
                      recovered_every_within_cap=True, rows_sha256=digest(rows))
