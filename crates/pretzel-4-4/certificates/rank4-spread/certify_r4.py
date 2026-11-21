#!/usr/bin/env python3
"""Exact rank-four Chernoff, cap and arithmetic self-test helpers."""
from fractions import Fraction
import importlib.util
import itertools
import math
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT/(name+'.py'))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m
C, S = module('certlib'), module('source_model')
if hasattr(sys, 'set_int_max_str_digits'):
    sys.set_int_max_str_digits(0)

def read():
    folder = ROOT.parents[1]/'core/src'
    p = S.parameters(folder)
    laws = {n:S.law(ROOT/'reference_tables.rs',n) for n in ('EVEN','ODD','SECRET','ERROR')}
    wh,wr = [S.integer_array(folder/'params_tables.rs',n) for n in ('W_HEAD','W_RES')]
    return p,laws,wh,wr

def moments(law, exponents, base):
    return C.archive.moments(law,exponents,base)

def bound_at(p,laws,target,a,b):
    assert a > b > 0, 'Chernoff base must exceed one'
    assert target in ('head','rice')
    base = C.rat(a,b)
    lead_count, cap0, caps = p['head_caps']
    ns = p['head_count']-lead_count
    threshold = {'head':p['CAP_EUC2_HEAD']+1,'rice':p['quotient_cap']+1}[target]
    def exponents(law,cap,shift):
        return {v:(((2*v if v>=0 else -2*v-1)>>shift) if target=='rice' else v*v)
                for v in law if abs(v)<=cap}
    lead = C.maximum(moments(laws[n],exponents(laws[n],cap0,p['rice_shifts'][0]),base) for n in ('EVEN','ODD'))
    secret = moments(laws['SECRET'],exponents(laws['SECRET'],caps,p['rice_shifts'][1]),base)
    blocks = [(lead,lead_count),(secret,ns)]
    value = (C.UNIT,C.UNIT)
    for m,n in blocks:
        value = C.mul(value,C.power(m,n))
    value = C.div(value,C.power(base,threshold))
    return value, dict(base=[a,b],integer_failure_threshold=threshold,worst_context=None,
                       moments=[dict(count=n,interval=C.record(m)) for m,n in blocks],
                       raw_chernoff=C.record(value))

def components(p,laws,rows):
    n0,c0,cs=p['head_caps']; ns=p['head_count']-n0; nr=p['residual_count']; cap=p['residual_cap']
    missing=Fraction(n0*max(C.WORD-sum(laws[n].values()) for n in ('EVEN','ODD'))+
                     ns*(C.WORD-sum(laws['SECRET'].values()))+nr*(C.WORD-sum(laws['ERROR'].values())),C.WORD)
    cap_parts=dict(leading=n0*max(sum(n for v,n in laws[k].items() if abs(v)>c0) for k in ('EVEN','ODD')),
                   secret=ns*sum(n for v,n in laws['SECRET'].items() if abs(v)>cs),
                   residual=nr*max(sum(n for a,_,n in row if a>cap) for row in rows))
    coefficient=Fraction(sum(cap_parts.values()),C.WORD)
    return missing,coefficient,cap_parts

def self_test():
    """Independent brute-force toys and independent direct error enumeration."""
    base=Fraction(7,6)
    got=C.power(C.rat(7,6),19)
    exact=base**19
    assert Fraction(got[0],C.UNIT)<=exact<=Fraction(got[1],C.UNIT)
    law={-1:2,0:3,2:1}; ex={v:v*v for v in law}
    got=moments(law,ex,C.rat(7,6))
    exact=sum(Fraction(n,C.WORD)*base**ex[v] for v,n in law.items())
    assert Fraction(got[0],C.UNIT)<=exact<=Fraction(got[1],C.UNIT)
    toy={0:2,1:1,3:1}; dist={0:1}
    for _ in range(3):
        nxt={}
        for x,w in dist.items():
            for y,v in toy.items(): nxt[x+y]=nxt.get(x+y,0)+w*v
        dist=nxt
    brute=sum(math.prod(toy[x] for x in xs) for xs in itertools.product(toy,repeat=3) if sum(xs)>=5)
    assert brute==sum(v for x,v in dist.items() if x>=5)
    p,laws,_,_=read()
    rows,_=S.residual_rows(laws['ERROR'],p)
    c=S.centers(p['Q'],p['LQ'])
    for x in (0,1,112,113,225,226,3840,7680):
        direct={}; labels=S.local_labels(x,c)
        for e,n in laws['ERROR'].items():
            u=p['LQ']*((x+e)%p['Q'])//p['Q']
            key=(abs(S.centered(c[u]-x)),labels.index(u) if u in labels else None)
            direct[key]=direct.get(key,0)+n
        interval={}
        for a,j,n in rows[x]: interval[a,j]=interval.get((a,j),0)+n
        assert interval==direct
    print('PASS: rational intervals, independent toy convolution, direct residual enumeration.')
