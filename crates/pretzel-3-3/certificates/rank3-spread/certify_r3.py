#!/usr/bin/env python3
"""Source-bound rank-three certificate. Pure Python, standard library only.
240-second wall guard per invocation (signal.alarm). No native code or timing.
--self-test: exact small cases and source/geometry checks.
--check: recompute and compare with certificate_r3.json byte for byte.
--check-core FILE: exact occupation test of one matrix given as JSON.
Default: generate certificate_r3.json. Caps, norms, score tables and expansion
limits are parsed from the crate sources. The word size of the reference
sample, the occupancy cap of the lemma and the limit of the recorded cap
frontier are the constants below. Arithmetic precisions are algorithm choices.

The code read here has one build configuration. binding.py states which code
is fixed, reads every cap from the function that enforces it, and checks that
neither Cargo feature of the crate (conformance, stack-wipe) gates any of the
files read here; the fixed configuration in the certificate names both.
"""
import argparse
import bisect
from collections import Counter
from fractions import Fraction as F
import hashlib
import importlib.util
import itertools
import json
import math
from pathlib import Path
import re
import signal
import sys

ROOT = Path(__file__).resolve().parent
SRC = ROOT.parents[1]/'src'
BITS, FBITS = 512, 192
U, D = 1 << BITS, 1 << FBITS
# Each coordinate of the reference sample is drawn from one uniform 32-bit word.
WORD_BITS = 32
# The occupation condition of the lemma: no absolute bin holds more than 54 points.
OCCUPANCY_CAP = 54
# The recorded cap frontier lists every cap whose row bound stays below 1 - 3/5.
FRONTIER_SUCCESS = (3, 5)
sys.set_int_max_str_digits(0)

def cd(a,b): return -(-a//b)
def rat(a,b=1): return (a*U//b,cd(a*U,b))
def add(*xs): return tuple(sum(x[i] for x in xs) for i in (0,1))
def mul(a,b):
    assert a[0]>=0 and b[0]>=0
    return a[0]*b[0]//U,cd(a[1]*b[1],U)
def div(a,b):
    assert b[0]>0
    return a[0]*U//b[1],cd(a[1]*U,b[0])
def scale(a,n,d=1): return a[0]*n//d,cd(a[1]*n,d)
def power(a,n):
    assert n>=0
    out=(U,U)
    while n:
        if n&1: out=mul(out,a)
        n//=2
        if n: a=mul(a,a)
    return out

def rec(x):
    x=F(x)
    k=cd(x.numerator*10**90,x.denominator)
    # Exact rational is authoritative; decimal is an upward enclosure.
    return {'numerator':str(x.numerator),'denominator':str(x.denominator),
            'decimal_upper':f'{k//10**90}.{k%10**90:090d}'}
def compact(x):
    x=F(x)
    return F(cd(x.numerator*U,x.denominator),U)
def digest(x): return hashlib.sha256(json.dumps(x,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def capture(text,pattern):
    # Patterns are written without white space; every match must agree.
    found=set(re.findall(pattern,re.sub(r'\s+','',text)))
    assert len(found)==1,(pattern,found)
    row=found.pop()
    return tuple(int(x.replace('_','')) for x in (row if isinstance(row,tuple) else (row,)))
def challenge_parameters():
    text=(SRC/'challenge.rs').read_text()
    weight,blocks=capture(text,r'letmutk=\[(\d+)usize;(\d+)\];')
    length,=capture(text,r'formin\(1\.\.=(\d+)\)\.rev\(\)')
    bits,=capture(text,r'letstart=\((\d+)\*j\)/8;')
    return dict(weight=weight,blocks=blocks,length=length,bits=bits)
def array(path,name):
    m=re.search(r'\b'+name+r'[^=]*=\s*&?\[(.*?)\];',path.read_text(),re.S)
    assert m,(path,name)
    return m[1]
def ints(path,name):
    return [int(x.replace('_',''),16 if x.startswith('0x') else 10)
            for x in re.findall(r'0x[\da-fA-F_]+|\d[\d_]*',array(path,name))]
def const(path,name):
    m=re.search(r'\bconst\s+'+name+r'\s*:[^=]+?=\s*([\d_]+(?:\s*\*\s*[\d_]+)*)\s*;',path.read_text())
    assert m,(path,name)
    return math.prod(int(t.strip().replace('_','')) for t in m[1].split('*'))
def binding():
    # Loaded by path, so the program does not depend on the module search path.
    spec=importlib.util.spec_from_file_location('binding',ROOT/'binding.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module
def read():
    bound=binding();configuration,parameters=bound.configuration,bound.parameters
    config=configuration(SRC)
    p={k:const(SRC/'params.rs',k) for k in ('Q','N','ELL','M','LQ','CAP_INF_HEAD','CAP_INF_RES',
        'CAP_EUC2_HEAD','CAP_EUC2_RES','CAP_Q20','PROPOSAL_W0','WS','WE')}
    p.update({k:const(SRC/'dither_frame.rs',k) for k in ('MAX_CANDIDATES','EXPANSION_CANDIDATES','DITHER_COEFFICIENTS')})
    p.update(parameters(SRC))
    p['word_bits']=WORD_BITS
    p['word']=1<<p['word_bits']; p['ns']=p['ELL']*p['N']; p['nr']=p['M']*p['N']; p['nh']=p['n0']+p['ns']
    p['target_success']=list(FRONTIER_SUCCESS)
    p['theta']=sum(x<<(64*i) for i,x in enumerate(ints(SRC/'params.rs','THETA_NUM_LIMBS')))
    p['theta_denominator']=1<<(64*len(ints(SRC/'params.rs','THETA_NUM_LIMBS')))
    tables=json.loads((ROOT/'reference_tables.json').read_text())
    assert set(tables)=={'EVEN','ODD','SECRET','ERROR'}
    laws={}; cdfs={}
    for name in ('EVEN','ODD','SECRET','ERROR'):
        endpoints=[tuple(pair) for pair in tables[name]]
        assert all(type(end) is int and type(value) is int for end,value in endpoints)
        law={}; last=0
        for end,v in endpoints:
            assert last<end<p['word'] and v not in law
            law[v]=end-last; last=end
        assert all(law.get(-v)==w for v,w in law.items())
        laws[name]=law; cdfs[name]=endpoints
    wh,wr=ints(SRC/'params_tables.rs','W_HEAD'),ints(SRC/'params_tables.rs','W_RES')
    assert p['n0']==p['N'] and p['nr']==p['DITHER_COEFFICIENTS']
    assert all(p['Q']%d for d in range(2,math.isqrt(p['Q'])+1))
    return p,laws,cdfs,wh,wr,config

def centers(q,l):
    edges=[cd(q*j,l) for j in range(l+1)]
    out=[]; even=0
    for a,b in zip(edges,edges[1:]):
        size=b-a
        out.append(a+(size-1)//2+(size%2==0)*(even%2))
        even+=size%2==0
    return out

def centered(x,q): return (x+q//2)%q-q//2

def labels(x,c,q):
    l=len(c); j=l*x//q
    dl=centered(x-c[(j-1)%l],q); dr=centered(c[(j+1)%l]-x,q)
    s=-1 if dl<=dr else 1
    return [j,(j+s)%l,(j-s)%l,(j+2*s)%l]

def geometry(p,law):
    q,l,cap=p['Q'],p['LQ'],p['residual_cap']; c=centers(q,l)
    prefix=[0]
    for e in range(-q,q+1): prefix.append(prefix[-1]+law.get(e,0))
    def mass(a,b):
        a=max(-q,a); b=min(q+1,b)
        return 0 if b<=a else prefix[b+q]-prefix[a+q]
    rows=[]; loc=[]
    for x in range(q):
        local=labels(x,c,q); loc.append(local); row=[]
        for u in range(l):
            a=abs(centered(c[u]-x,q))
            assert a>cap or u in local,(x,u,a)
            lo,hi=cd(q*u,l)-x,cd(q*(u+1),l)-x
            w=sum(mass(lo+k*q,hi+k*q) for k in (-1,0,1))
            if w: row.append((a,local.index(u) if u in local else None,w))
        assert sum(w for a,j,w in row)==sum(law.values())
        rows.append(row)
    return rows,{'centers':c,'rows_sha256':digest(rows),'recovery_sha256':digest(loc),'all_within_cap_recovered':True,
                 'cell_width_counts':dict(Counter(cd(q*(j+1),l)-cd(q*j,l) for j in range(l)))}

def downward(p,laws):
    theta=rat(p['theta'],p['theta_denominator']); out={}
    for name,w,parity in [('EVEN',p['PROPOSAL_W0'],0),('ODD',p['PROPOSAL_W0'],1),('SECRET',p['WS'],None),('ERROR',p['WE'],None)]:
        radius=1500 # Computation truncation, remainder proved below.
        weights={z:power(theta,w*z*z) for z in range(radius+1) if parity is None or z%2==parity}
        partial=add(*(scale(a,1 if z==0 else 2) for z,a in weights.items()))
        first=power(theta,w*(radius+1)**2); step=power(theta,w*(2*radius+3))
        tail=div(scale(first,2),(U-step[1],U-step[0]))
        normalizer=(partial[0],partial[1]+tail[1]); gaps=[]
        for z,count in laws[name].items():
            assert parity is None or z%2==parity
            lower=div(weights[abs(z)],normalizer)[0]
            assert count*U<=p['word']*lower,(name,z)
            gaps.append(p['word']*lower-count*U)
        out[name]={'atoms':len(laws[name]),'missing_words':p['word']-sum(laws[name].values()),
                   'normalizer_interval':[rec(F(x,U)) for x in normalizer],
                   'minimum_downward_margin_numerator':str(min(gaps)),'margin_denominator':str(U*p['word'])}
    return out

# Signed 192-bit outward intervals for cosine; Machin identity and alternating atan.
def iv(x):
    x=F(x); return x.numerator*D//x.denominator,cd(x.numerator*D,x.denominator)
def imul(a,b):
    z=[x*y for x in a for y in b];return min(z)//D,cd(max(z),D)
def idiv(a,n): return a[0]//n,cd(a[1],n)
def atan(k,terms=160):
    s=sum((F((-1)**j,(2*j+1)*k**(2*j+1)) for j in range(terms)),F(0))
    nxt=F((-1)**terms,(2*terms+1)*k**(2*terms+1))
    return min(s,s+nxt),max(s,s+nxt)
def cosines(q):
    a,b=atan(5),atan(239); pi=(iv(16*a[0]-4*b[1])[0],iv(16*a[1]-4*b[0])[1])
    terms=64
    assert F(22,7)**(2*terms)/math.factorial(2*terms)<F(1,D)
    out=[(D,D)]*q
    for k in range(1,q//2+1):
        x=idiv((2*k*pi[0],2*k*pi[1]),q); xx=imul(x,x); term=total=(D,D)
        for j in range(1,terms):
            term=idiv(imul(term,xx),(2*j-1)*(2*j))
            signed=term if j%2==0 else (-term[1],-term[0])
            total=(total[0]+signed[0],total[1]+signed[1])
        out[k]=out[q-k]=(max(-D,total[0]-1),min(D,total[1]+1))
    return out

def spectrum(law,co,q):
    den=sum(law.values()); out=[]
    for t in range(q//2+1):
        lo=hi=law.get(0,0)*D
        for v,w in law.items():
            if v>0:
                a,b=co[(t*v)%q];lo+=2*w*a;hi+=2*w*b
        lo,hi=lo//den,cd(hi,den)
        out.append(min(D,max(abs(lo),abs(hi))))
    return out

def product(spec,count,occ):
    out=(U,U); allocation=[]
    for t,upper in sorted(enumerate(spec),key=lambda z:z[1],reverse=True):
        take=min(occ,count);out=mul(out,power(rat(upper,D),take))
        allocation.append([t,take]);count-=take
        if count==0: break
    assert count==0
    return F(out[1],U),allocation

def head_chernoff(p,laws):
    threshold=p['CAP_EUC2_HEAD']+1
    # A fixed rational Chernoff base is valid independently of optimization.
    # This avoids host-libm differences in the committed certificate.
    def ex(name): return {v:v*v for v in laws[name] if abs(v)<=(p['secret_cap'] if name=='SECRET' else p['lead_cap'])}
    exps={name:ex(name) for name in ('EVEN','ODD','SECRET')}
    a,b=10000800,10000000
    base=rat(a,b); ms={}
    for name,ee in exps.items():
        cache={e:power(base,e) for e in set(ee.values())}
        ms[name]=scale(add(*(scale(cache[e],laws[name][v]) for v,e in ee.items())),1,p['word'])
    lead=(max(ms[n][0] for n in ('EVEN','ODD')),max(ms[n][1] for n in ('EVEN','ODD')))
    bound=div(mul(power(lead,p['n0']),power(ms['SECRET'],p['ns'])),power(base,threshold))
    return min(F(1),F(bound[1],U)),{'base':[a,b],'threshold':threshold}

def binomial_tail(n,p,t):
    a,b=p.numerator,p.denominator
    return F(sum(math.comb(n,k)*a**k*(b-a)**(n-k) for k in range(t,n+1)),b**n)

def worst_chernoff(p,laws,rows,wh,wr,target):
    threshold=p['CAP_EUC2_RES']+1 if target=='norm' else p['CAP_Q20']+1
    fn=(lambda a:a*a) if target=='norm' else (lambda a:wr[a])
    # Fixed valid bases; these diagnostic worst-context bounds are not optimized
    # during replay. All output arithmetic below is outward or exact.
    a,b=(10000000 if target=='norm' else 10000020),10000000
    base=rat(a,b);cache=[power(base,fn(a)) for a in range(p['residual_cap']+1)]
    ms=[scale(add(*(scale(cache[a],w) for a,j,w in row if a<=p['residual_cap'])),1,p['word']) for row in rows]
    maxcontext=max(range(p['Q']),key=lambda x:ms[x][1])
    result=power((max(x[0] for x in ms),max(x[1] for x in ms)),p['nr'])
    if target=='score':
        heads={k:scale(add(*(scale(power(base,wh[abs(v)]),w) for v,w in laws[k].items() if abs(v)<=(p['secret_cap'] if k=='SECRET' else p['lead_cap']))),1,p['word']) for k in ('EVEN','ODD','SECRET')}
        lead=(max(heads[k][0] for k in ('EVEN','ODD')),max(heads[k][1] for k in ('EVEN','ODD')))
        result=mul(result,mul(power(lead,p['n0']),power(heads['SECRET'],p['ns'])))
    result=div(result,power(base,threshold))
    return min(F(1),F(result[1],U)),{'base':[a,b],'maximizing_context':maxcontext,'threshold':threshold}

def moment(law,fn):
    den=sum(law.values());mean=F(sum(w*fn(v) for v,w in law.items()),den)
    return mean,F(sum(w*fn(v)**2 for v,w in law.items()),den)-mean*mean

def fourth_comparator(p,laws,rows,wh,wr):
    """Independent uniform-context comparison ONLY; not a fixed-core theorem."""
    def stats(law):
        den=sum(law.values())
        raw=[F(sum(w*x**k for x,w in law.items()),den) for k in range(1,5)]
        mu=raw[0];variance=raw[1]-mu*mu
        fourth=raw[3]-4*mu*raw[2]+6*mu*mu*raw[1]-3*mu**4
        return mu,variance,fourth
    def push(law,fn):
        out=Counter()
        for v,w in law.items():out[fn(v)]+=w
        return out
    hs={k:stats(push(laws[k],lambda x:wh[abs(x)] if abs(x)<=(p['secret_cap'] if k=='SECRET' else p['lead_cap']) else 0)) for k in ('EVEN','ODD','SECRET')}
    rs=Counter()
    for row in rows:
        for a,j,w in row:rs[wr[a] if a<=p['residual_cap'] else 0]+=w
    r=stats(rs)
    mu,var,fourth=[p['n0']*max(hs[k][i] for k in ('EVEN','ODD'))+p['ns']*hs['SECRET'][i]+p['nr']*r[i] for i in range(3)]
    bound=(fourth+3*var*var)/(p['CAP_Q20']+1-mu)**4
    return {'classification':'COMPUTED_COMPARATOR_ONLY; NEEDS FOUR-COORDINATE SPREAD AND HEAD-DELETION LEMMAS',
            'independent_score_fourth_moment_tail_upper':rec(compact(bound))}

def statistics(p,laws,rows,wh,wr):
    den=p['Q']*sum(laws['ERROR'].values()); out={}
    for name,fn in [('norm',lambda a,j:a*a),('score',lambda a,j:wr[a]),('exception',lambda a,j:int(j>=p['exception_index']))]:
        mu=F(sum(w*fn(a,j) for row in rows for a,j,w in row if a<=p['residual_cap']),den)
        var=F(sum(w*fn(a,j)**2 for row in rows for a,j,w in row if a<=p['residual_cap']),den)-mu*mu
        out[name]=(mu,var)
    head={name:moment(laws[name],lambda x:wh[abs(x)] if abs(x)<=(p['secret_cap'] if name=='SECRET' else p['lead_cap']) else 0) for name in ('EVEN','ODD','SECRET')}
    hm=p['n0']*max(head[k][0] for k in ('EVEN','ODD'))+p['ns']*head['SECRET'][0]
    hv=p['n0']*max(head[k][1] for k in ('EVEN','ODD'))+p['ns']*head['SECRET'][1]
    return out,hm,hv

def residual_bounds(p,stats,hm,hv,wh,wr,tv):
    out={};details={}; n=p['nr']; hmax=max(wh[:p['secret_cap']+1])
    for name,cap,b in [('norm',p['CAP_EUC2_RES'],p['residual_cap']**2),('score',p['CAP_Q20'],max(wr[:p['residual_cap']+1])),('exception',p['label_exceptions'],1)]:
        mu,var=stats[name]; mean=n*(mu+b*tv);variance=n*var+3*n*n*b*b*tv
        if name=='score':mean+=hm;variance+=hv+4*p['nh']*n*hmax*b*tv
        if mean>=cap+1:bound=F(1)
        else:bound=variance/(variance+(cap+1-mean)**2)
        out[name]=bound;details[name]={'mean_upper':rec(mean),'variance_upper':rec(variance),'threshold':cap+1,
            'uniform_coordinate_mean':rec(mu),'uniform_coordinate_variance':rec(var),
            'squared_standard_deviation_margin_lower':rec((cap+1-mean)**2/variance) if mean<cap+1 else None}
    return out,details

def bad_core(p,occ):
    q,n,m,ns=p['Q'],p['N'],p['M'],p['ns']
    bins=F((q+1)**2,2);first=occ+1;half=cd(first,2)
    same=m*(n//2)*bins*2*math.comb(ns//2,half)*F(2,q)**half
    cross=math.comb(m,2)*n*bins*math.comb(ns,first)*F(2,q)**first
    return same+cross

def sources():
    # Hash parsed values, not entire production files. Every cap occurrence is
    # still parsed and cross-checked by binding.parameters before this returns.
    p,_,cdfs,wh,wr,config=read()
    values={'parameters_and_cap_bindings':p, 'fixed_configuration':config,
            'W_HEAD':wh, 'W_RES':wr, 'reference_CDFs':cdfs,
            'challenge':challenge_parameters()}
    return {name:digest(value) for name,value in values.items()}

def compute():
    p,laws,cdfs,wh,wr,config=read()
    rows,geo=geometry(p,laws['ERROR']); print('Source and complete geometry checked.',flush=True)
    dom=downward(p,laws); print('All finite atoms dominated by ideal Gaussian.',flush=True)
    co=cosines(p['Q']);spec=spectrum(laws['SECRET'],co,p['Q'])
    missing=F(p['n0']*max(p['word']-sum(laws[k].values()) for k in ('EVEN','ODD'))+p['ns']*(p['word']-sum(laws['SECRET'].values()))+p['nr']*(p['word']-sum(laws['ERROR'].values())),p['word'])
    caps={'leading':p['n0']*max(sum(w for v,w in laws[k].items() if abs(v)>p['lead_cap']) for k in ('EVEN','ODD')),
          'secret':p['ns']*sum(w for v,w in laws['SECRET'].items() if abs(v)>p['secret_cap']),
          'residual':p['nr']*max(sum(w for a,j,w in row if a>p['residual_cap']) for row in rows)}
    coefficient=F(sum(caps.values()),p['word'])
    hn,hd=head_chernoff(p,laws)
    ep=F(sum(w for v,w in laws['SECRET'].items() if v< -p['low_min_magnitude'] or v>p['low_max']),p['word'])
    he=compact(binomial_tail(p['ns'],ep,p['head_exception_cap']+1))
    worstnorm,wninfo=worst_chernoff(p,laws,rows,wh,wr,'norm')
    worstscore,wsinfo=worst_chernoff(p,laws,rows,wh,wr,'score')
    worstexception=F(max(sum(w for a,j,w in row if a<=p['residual_cap'] and j>=p['exception_index']) for row in rows),p['word'])
    residual_encoding_universal=compact(binomial_tail(p['nr'],worstexception,p['label_exceptions']+1))
    worstencoding=min(F(1),he+residual_encoding_universal)
    worstparts={'failed_samples':missing,'coordinate_caps_and_recovery':coefficient,'head_norm':hn,
                'residual_norm':worstnorm,'score':worstscore,'encoding_capacities':worstencoding}
    assert sum(worstparts.values())>=1
    fixed=missing+coefficient+hn+he
    stats,hm,hv=statistics(p,laws,rows,wh,wr)
    fourth=fourth_comparator(p,laws,rows,wh,wr)
    frontier=[];chosen=None
    # Both bounds at every cap, up to the first cap whose row bound reaches the
    # frontier limit. The statement uses the entry at OCCUPANCY_CAP.
    for occ in range(1,p['ns']+1):
        eta,alloc=product(spec,p['ns']-1,occ);tv=min(F(1),F(p['Q']**2-1,2)*eta)
        residual,details=residual_bounds(p,stats,hm,hv,wh,wr,tv)
        # Conditional on the full head, independent error words give a much
        # sharper universal binomial tail than a pairwise Cantelli bound.
        details['exception']['pair_cantelli_upper']=rec(compact(residual['exception']))
        residual['exception']=min(residual['exception'],residual_encoding_universal)
        details['exception']['used_upper']=rec(compact(residual['exception']))
        details['exception']['chosen_method']='minimum of pair Cantelli and universal conditional-head binomial'
        epsilon=fixed+sum(residual.values(),F(0))
        if epsilon>=1-F(*p['target_success']):
            frontier.append({'occupancy':occ,'meets_target':False});break
        bad=bad_core(p,occ)
        frontier.append({'occupancy':occ,'epsilon_upper':rec(compact(epsilon)),'bad_core_upper':rec(compact(bad)),
                         'meets_target':True})
        if occ==OCCUPANCY_CAP:chosen=(occ,eta,tv,residual,details,epsilon,bad,alloc)
    assert chosen is not None,'the row bound at the occupancy cap is not below the frontier limit'
    occ,eta,tv,residual,details,epsilon,bad,alloc=chosen
    print('Occupancy cap',occ,'epsilon',float(epsilon),'bad core',float(bad),flush=True)
    contributions={'failed_samples':missing,'coordinate_caps_and_recovery':coefficient,'head_norm':hn,
                   'residual_norm':residual['norm'],'score':residual['score'],'encoding_capacities':he+residual['exception']}
    assert sum(contributions.values())==epsilon
    worst={str(x):p['nr']*min(a for a,j,w in rows[x])**2 for x in (0,p['Q']-1)}
    assert all(v>p['CAP_EUC2_RES'] for v in worst.values())
    # Dither expansion keeps the low ceil(log2 q) bits of each word and accepts values below q.
    accepted=F(p['Q'],1<<p['Q'].bit_length())
    expansion=binomial_tail(p['EXPANSION_CANDIDATES'],1-accepted,p['EXPANSION_CANDIDATES']-p['nr']+1)
    out={'status':'COMPUTED_CONDITIONAL_THEOREM',
         'acceptance_source_sha256':{name:hashlib.sha256((SRC/name).read_bytes()).hexdigest()
                                    for name in ('dither_setup.rs', 'dither_frame.rs',
                                                 'public_common_prefix.rs', 'keygen_dither_check.rs')},
         'parsed_inputs_sha256':sources(),
         'binding_program_sha256':hashlib.sha256((ROOT/'binding.py').read_bytes()).hexdigest(),
         'program_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
         'arithmetic':'exact rational; 512-bit positive outward intervals; 192-bit signed Fourier intervals',
         'parameters':p,'fixed_configuration':config,'geometry':geo,'downward_sampler_domination':dom,
         'worst_context':{'failure_probability':rec(1),'residual_norm_lower':worst,
                          'six_failure_contributions':{k:rec(compact(v)) for k,v in worstparts.items()},
                          'norm_chernoff':wninfo,'score_chernoff':wsinfo,
                          'worst_residual_exception_probability':rec(worstexception),
                          'clipped_complete_failure_upper':rec(min(F(1),sum(worstparts.values())))},
         'six_failure_contributions':{k:rec(compact(v)) for k,v in contributions.items()},
         'coefficient_cap_word_numerators':caps,'head_norm_chernoff':hd,'head_encoding_tail':rec(he),
         'residual_encoding_universal_tail':rec(residual_encoding_universal),
         'head_encoding_coordinate_probability':rec(ep),'row_failure_upper':rec(compact(epsilon)),
         'occupancy_cap':occ,'pair_tv_upper':rec(tv),
         'fourier_product_upper_after_one_deletion':rec(eta),'product_allocation':alloc,
         'spectrum_intervals_sha256':digest(spec),'secret_nonzero_spectrum_max_upper':rec(F(max(spec[1:]),D)),
         'honest_core_exception_upper':rec(compact(bad)),'cap_frontier':frontier,
         'moment_details':details,'head_score_mean_upper':rec(hm),'head_score_variance_upper':rec(hv),
         'higher_moment_route':fourth,
         'candidate_expansion':{'candidate_expansion_failure_upper':rec(compact(expansion)),
                     'all_candidate_expansion_failures_upper':rec(F(power(rat(compact(expansion).numerator,compact(expansion).denominator),p['MAX_CANDIDATES'])[1],U)),
                     'meaning':'independent uniform words; one dither candidate fails to expand, and all candidates fail; bounds, not real SHAKE frequencies'},
         'G_check_projection_updates':(p['M']*(p['N']//2)+math.comb(p['M'],2)*p['N'])*(p['Q']+1)*p['ns'],
         'any_production_core_checked':False}
    assert epsilon < F(16575, 1000000)
    assert bad < F(2701, 10**51)
    serialized=json.dumps(out,indent=2,sort_keys=True)+'\n'
    target=ROOT/'certificate_r3.json'
    if args.check:
        assert target.read_text()==serialized, 'stale rank-three certificate; rerun certify_r3.py'
    else:
        target.write_text(serialized)
    for k,v in contributions.items():print(k,float(v),flush=True)

def coefficient_rows(matrix,r,i,q):
    n=len(matrix[0][0])
    return [(poly[(i-k)%n]*(1 if k<=i else -1))%q for poly in matrix[r] for k in range(n)]
def representatives(m,n):
    for r in range(m):
        for d in range(1,n//2+1):yield r,0,r,d
        for s in range(r+1,m):
            for d in range(n):yield r,0,s,d

def occupancy(points,q):
    return max(max(Counter(min((t*a+s*b)%q,(-t*a-s*b)%q) for a,b in points).values())
               for t,s in itertools.chain(((1,s) for s in range(q)),[(0,1)]))

def check_core(path):
    p,*_=read();certificate=json.loads((ROOT/'certificate_r3.json').read_text())
    limit=certificate['occupancy_cap'];matrix=json.loads(path.read_text());q=p['Q']
    assert len(matrix)==p['M'] and all(len(row)==p['ELL'] for row in matrix)
    assert all(len(poly)==p['N'] and all(type(v) is int and 0<=v<q for v in poly) for row in matrix for poly in row)
    maximum=0
    for r,i,s,j in representatives(p['M'],p['N']):
        aa,bb=coefficient_rows(matrix,r,i,q),coefficient_rows(matrix,s,j,q)
        for t,u in itertools.chain(((1,u) for u in range(q)),[(0,1)]):
            counts=Counter(min((t*a+u*b)%q,(-t*a-u*b)%q) for a,b in zip(aa,bb))
            maximum=max(maximum,max(counts.values()))
            if maximum>limit:
                print(json.dumps({'G':False,'occupancy_cap':limit,'pair':[r,i,s,j],'direction':[t,u],'occupancy':maximum}));return
    print(json.dumps({'G':True,'occupancy_cap':limit,'maximum_occupancy':maximum,'matrix_sha256':digest(matrix)}))

def self_test():
    p,laws,cdfs,wh,wr,config=read();rows,geo=geometry(p,laws['ERROR']);q=p['Q'];cs=geo['centers']
    # CDF endpoint lookup, suffix failure and symmetry, all atoms.
    for name,cdf in cdfs.items():
        ends=[e for e,v in cdf];values=[v for e,v in cdf];last=0
        for i,(end,v) in enumerate(cdf):
            assert values[bisect.bisect_right(ends,last)]==v
            assert values[bisect.bisect_right(ends,end-1)]==v
            assert bisect.bisect_right(ends,end)==i+1
            last=end
        assert bisect.bisect_right(ends,p['word']-1)==len(ends)
    # Independent direct enumeration at every context and every retained error.
    for x in range(q):
        direct=Counter();ll=labels(x,cs,q)
        for e,w in laws['ERROR'].items():
            u=p['LQ']*((x+e)%q)//q;a=abs(centered(cs[u]-x,q))
            direct[a,ll.index(u) if u in ll else None]+=w
        assert direct==Counter({(a,j):sum(w for aa,jj,w in rows[x] if (aa,jj)==(a,j)) for a,j,_ in rows[x]})
    print('PASS all source CDF endpoints and full residual enumeration.',flush=True)
    # Independent integer identities for production q_label_ct and center_ct.
    mult=cd(1<<32,q)
    assert all((p['LQ']*x*mult)>>32==p['LQ']*x//q for x in range(q))
    assert cs==[226*j+112+((j&1)^int(12<=j<23))-int(j>=11)-int(j>=22)-int(j>=33) for j in range(p['LQ'])]
    # Zero and endpoint-dither obstruction, including missing error mass.
    for x in (0,q-1):assert p['nr']*min(a for a,j,w in rows[x])**2>p['CAP_EUC2_RES']
    # Uniform residual moments agree with convolution of error and quantization error.
    quant=Counter(centered(cs[p['LQ']*t//q]-t,q) for t in range(q))
    for power_ in (2,4):
        direct=sum(w*a**power_ for row in rows for a,j,w in row if a<=p['residual_cap'])
        convolution=sum(w*v*abs(e+z)**power_ for e,w in laws['ERROR'].items() for z,v in quant.items() if abs(e+z)<=p['residual_cap'])
        assert direct==convolution
    # Interval power and exhaustive binomial toy.
    got=power(rat(7,6),19);assert F(got[0],U)<=F(7,6)**19<=F(got[1],U)
    for size in range(1,8):
        for t in range(1,size+1):
            brute=sum((F(2**sum(bits),3**size) for bits in itertools.product((0,1),repeat=size) if sum(bits)>=t),F(0))
            assert brute==binomial_tail(size,F(2,3),t)
    # Fourier bound and deletion conditional on a coordinate, exact toy laws and all dithers.
    co=cosines(5);sp=spectrum({-1:1,0:2,1:1},co,5);points=[(1,0),(0,1),(1,1),(1,2)]
    for fixed in (None,-1,0,1):
        k=4 if fixed is None else 3;distribution=Counter();mean=second=F(0)
        for xs in itertools.product((-1,0,1),repeat=k):
            full=xs if fixed is None else (fixed,)+xs;weight=math.prod(2 if v==0 else 1 for v in xs)
            aa=sum(x*a for x,(a,b) in zip(full,points))%5;bb=sum(x*b for x,(a,b) in zip(full,points))%5
            distribution[aa,bb]+=weight;value=sum(x*x for x in xs)+int(aa==0)+int(bb==0)
            mean+=F(weight*value,4**k);second+=F(weight*value*value,4**k)
        fsum=F(0)
        for t,s in itertools.product(range(5),repeat=2):
            if (t,s)==(0,0):continue
            prod=F(1)
            for a,b in (points if fixed is None else points[1:]):
                v=(t*a+s*b)%5;prod*=F(sp[min(v,5-v)],D)
            fsum+=prod
        tv=min(F(1),fsum/2)
        for da,db in itertools.product(range(5),repeat=2):
            true=sum(abs(F(distribution[((a-da)%5,(b-db)%5)],4**k)-F(1,25)) for a,b in itertools.product(range(5),repeat=2))/2
            assert true<=tv
        assert mean<=F(k,2)+2*(F(1,5)+tv)
        assert second-mean*mean<=F(k,4)+F(8,25)+3*4*tv+4*k*2*tv
    # All small matrices: representative symmetry and negacyclic dependence.
    for flat in itertools.product(range(3),repeat=4):
        matrix=[[list(flat[:2])],[list(flat[2:])]]
        maximum=max(occupancy(list(zip(coefficient_rows(matrix,r,i,3),coefficient_rows(matrix,s,j,3))),3) for r,i,s,j in representatives(2,2))
        allrows=[coefficient_rows(matrix,r,i,3) for r in range(2) for i in range(2)]
        assert maximum==max(occupancy(list(zip(a,b)),3) for a,b in itertools.combinations(allrows,2))
    zero=[[[0]*p['N'] for _ in range(p['ELL'])] for _ in range(p['M'])]
    identity=[[[int(r==c and k==0) for k in range(p['N'])] for c in range(p['ELL'])] for r in range(p['M'])]
    for matrix in (zero,identity):assert sum(v==0 for v in coefficient_rows(matrix,0,0,q))>=p['ns']-1
    # Sparse wire has exactly the claimed capacities; boundary representability.
    for v in range(-p['secret_cap'],p['secret_cap']+1):
        low=(v+128)%256-128
        exceptional=v< -p['low_min_magnitude'] or v>p['low_max']
        restored=low+(256 if low<0 else -256) if exceptional else low
        assert restored==v and (not exceptional or low!=0)
    print('PASS all exact self-tests.',flush=True)

if __name__=='__main__':
    signal.signal(signal.SIGALRM,lambda *_:sys.exit('Process guard expired; no completed certificate.'))
    signal.alarm(240)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true')
    parser.add_argument('--self-test',action='store_true')
    parser.add_argument('--check-core',type=Path,help='Exact but expensive G test; timeout emits no success certificate.')
    args=parser.parse_args()
    if args.check_core:check_core(args.check_core)
    elif args.self_test:self_test()
    else:compute()
