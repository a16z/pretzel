#!/usr/bin/env python3
"""Rank-four finite sampler spread certificate. Standard library only.

python3 -I -B certify_r4_spread.py --self-test
python3 -I -B certify_r4_spread.py
Optional --check-core FILE reads a 4 by 4 by 256 coefficient array. The
deliberately simple exact G verifier is expensive and may hit the 240s guard.
No seed expansion, native execution, network, timing, or sampling is used.
"""
import argparse
from collections import Counter
from fractions import Fraction as F
import hashlib
import importlib.util
import itertools
import json
import math
from pathlib import Path
import signal

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('r4', ROOT/'certify_r4.py')
R = importlib.util.module_from_spec(spec)
spec.loader.exec_module(R)
Q, N, D, OCC = 7681, 256, 1 << 160, 48

def ceildiv(a, b):
    return -((-a)//b)

def rec(x):
    x = F(x)
    # The decimal upper bound is exact, rounded upward at 60 decimal places.
    v = ceildiv(x.numerator*10**60, x.denominator)
    return {'numerator': str(x.numerator), 'denominator': str(x.denominator),
            'decimal_upper': f'{v//10**60}.{v%10**60:060d}'}

def iv(x):
    x = F(x)
    return x.numerator*D//x.denominator, ceildiv(x.numerator*D, x.denominator)

def add(a, b):
    return a[0]+b[0], a[1]+b[1]

def neg(a):
    return -a[1], -a[0]

def mul(a, b):
    p = [x*y for x in a for y in b]
    return min(p)//D, ceildiv(max(p), D)

def divide(a, n):
    assert n > 0
    return a[0]//n, ceildiv(a[1], n)

def atan_recip(k, terms=128):
    s = sum((F((-1)**j, (2*j+1)*k**(2*j+1)) for j in range(terms)), F(0))
    nxt = F((-1)**terms, (2*terms+1)*k**(2*terms+1))
    return min(s, s+nxt), max(s, s+nxt)

def pi_interval():
    a, b = atan_recip(5), atan_recip(239)
    return 16*a[0]-4*b[1], 16*a[1]-4*b[0]

def cosine_table(q):
    lo, hi = pi_interval()
    assert F(3) < lo < hi < F(22, 7)
    pi = (iv(lo)[0], iv(hi)[1])
    table = [(D, D)]*q
    # Taylor remainder after degree 94 is at most pi^96/96! < 2^-160.
    assert F(22, 7)**96/F(math.factorial(96)) < F(1, D)
    for k in range(1, q//2+1):
        x = divide((pi[0]*2*k, pi[1]*2*k), q)
        x2 = mul(x, x)
        term, total = (D, D), (D, D)
        for j in range(1, 48):
            term = divide(mul(term, x2), (2*j-1)*(2*j))
            total = add(total, term if j % 2 == 0 else neg(term))
        table[k] = table[q-k] = (max(-D, total[0]-1), min(D, total[1]+1))
    return table

def spectrum(law, cosines, q=Q):
    assert all(law.get(-v, 0) == w for v, w in law.items())
    total = sum(law.values())
    atoms = [(v, 2*w) for v, w in law.items() if v > 0]
    result = []
    for t in range(q//2+1):
        a = b = law.get(0, 0)*D
        for v, w in atoms:
            lo, hi = cosines[(t*v) % q]
            a += w*lo
            b += w*hi
        lo, hi = a//total, ceildiv(b, total)
        lower = 0 if lo <= 0 <= hi else min(abs(lo), abs(hi))
        result.append((lower, min(D, max(abs(lo), abs(hi)))))
    return result

def product_enclosure(specs, count=1023, occupancy=OCC):
    # At most occupancy copies of any absolute frequency. Sort rigorous
    # upper endpoints, not numerical approximations to the true spectrum.
    ordered = sorted(enumerate(specs), key=lambda z: z[1][1], reverse=True)
    value = F(1)
    used = []
    for frequency, (_, upper) in ordered:
        take = min(occupancy, count)
        value *= F(upper, D)**take
        used.append({'absolute_frequency': frequency, 'copies': take,
                     'magnitude_upper': rec(F(upper, D))})
        count -= take
        if not count:
            break
    assert count == 0
    # Compress the enormous rational upward to a 160-bit dyadic.
    return F(ceildiv(value.numerator*D, value.denominator), D), used

def row_coefficients(matrix, r, i, q=Q):
    n = len(matrix[0][0])
    return [(poly[(i-k) % n] * (1 if k <= i else -1)) % q
            for poly in matrix[r] for k in range(n)]

def representatives(m, n):
    for r in range(m):
        for d in range(1, n//2+1):
            yield r, 0, r, d
        for s in range(r+1, m):
            for d in range(n):
                yield r, 0, s, d

def occupancy(points, q):
    largest = 0
    for t, s in itertools.chain(((1, s) for s in range(q)), [(0, 1)]):
        counts = Counter(min((t*a+s*b) % q, (-t*a-s*b) % q) for a, b in points)
        largest = max(largest, max(counts.values()))
    return largest

def check_core(matrix, limit=OCC, q=Q):
    m, n = len(matrix), len(matrix[0][0])
    assert n > 1 and n & (n-1) == 0
    assert all(len(row) == len(matrix[0]) for row in matrix)
    assert all(len(poly) == n and all(isinstance(x, int) and 0 <= x < q for x in poly)
               for row in matrix for poly in row)
    worst = 0
    for r, i, s, j in representatives(m, n):
        a, b = row_coefficients(matrix, r, i, q), row_coefficients(matrix, s, j, q)
        value = occupancy(list(zip(a, b)), q)
        worst = max(worst, value)
        if value > limit:
            return {'G': False, 'witness_pair': [r, i, s, j], 'occupancy': value}
    return {'G': True, 'maximum_occupancy': worst}

def moment(law, fn):
    den = sum(law.values())
    mu = F(sum(w*fn(v) for v, w in law.items()), den)
    return mu, F(sum(w*fn(v)**2 for v, w in law.items()), den)-mu*mu

def cantelli(mean, variance, threshold):
    assert variance >= 0 and threshold > mean
    return variance/(variance+(threshold-mean)**2)

def compute():
    p, laws, wh, wr = R.read()
    assert all(Q % d for d in range(2, math.isqrt(Q)+1))
    assert OCC == 48 and len(list(representatives(4, N))) == 2048
    assert (p['Q'], p['N'], p['ELL'], p['M'], p['LQ']) == (Q, N, 4, 4, 34)
    assert p['head_count'] == 1280 and p['residual_count'] == 1024
    assert p['head_caps'] == [256, 288, 255]
    assert (p['PROPOSAL_W0'], p['WS'], p['WE']) == (9216, 196, 121)
    assert p['rice_shifts'] == [3, 6] and p['exception_first_index'] == 2
    assert p['residual_cap'] == 450
    R.C.archive.THETA = p['theta']
    R.C.archive.WEIGHTS = [p[name] for name in ('PROPOSAL_W0', 'WS', 'WE')]
    downward = R.C.archive.downward(laws)
    rows, geometry = R.S.residual_rows(laws['ERROR'], p)
    cosines = cosine_table(Q)
    spectral = {k: spectrum(v, cosines) for k, v in laws.items()}
    eta, extremizers = product_enclosure(spectral['SECRET'])
    tv = min(F(1), F(Q*Q-1, 2)*eta)
    spectral_summary = {}
    for name, values in spectral.items():
        index = max(range(1, len(values)), key=lambda i: values[i][1])
        spectral_summary[name] = {
            'normalization': 'CDF law conditional on nonmissing draw',
            'nonzero_max_abs_lower': rec(F(max(v[0] for v in values[1:]), D)),
            'nonzero_max_abs_upper': rec(F(max(v[1] for v in values[1:]), D)),
            'maximizing_upper_endpoint_frequency': index,
            'all_intervals_sha256': R.S.digest(values)}
    missing, coefficient, parts = R.components(p, laws, rows)
    n0, ns, nr = 256, 1024, 1024
    den = Q*sum(laws['ERROR'].values())
    stats = {}
    for name, fn in [('norm', lambda a, j: a*a), ('score', lambda a, j: wr[a]),
                     ('exception', lambda a, j: int(j >= 2))]:
        mu = F(sum(w*fn(a, j) for row in rows for a, j, w in row if a <= 450), den)
        var = F(sum(w*fn(a, j)**2 for row in rows for a, j, w in row if a <= 450), den)-mu*mu
        stats[name] = (mu, var)
    head = {k: moment(laws[k], lambda x: wh[abs(x)] if abs(x) <= (255 if k == 'SECRET' else 288) else 0)
            for k in ('EVEN', 'ODD', 'SECRET')}
    headmean = n0*max(head[k][0] for k in ('EVEN', 'ODD'))+ns*head['SECRET'][0]
    headvar = n0*max(head[k][1] for k in ('EVEN', 'ODD'))+ns*head['SECRET'][1]
    hm, rm = max(wh), max(wr[:451])
    bounds, details = {}, {}
    bounds['failed_samples'] = missing
    bounds['coordinate_caps_and_recovery'] = coefficient
    for target, name in [('head', 'head_norm'), ('rice', 'head_encoding')]:
        a, b = (10000320, 10000000) if target == 'head' else (11500, 10000)
        result, info = R.bound_at(p, laws, target, a, b)
        bounds[name] = F(result[1], R.C.UNIT)
        details[name] = info
    for name, cap, maximum in [('norm', p['CAP_EUC2_RES'], 450**2),
                                ('score', p['CAP_Q20'], rm),
                                ('exception', p['label_exceptions'], 1)]:
        mu, var = stats[name]
        mean = nr*(mu+maximum*tv)
        variance = nr*var+3*nr**2*maximum**2*tv
        if name == 'score':
            mean += headmean
            variance += headvar+4*(n0+ns)*nr*hm*maximum*tv
        bounds[{'norm': 'residual_norm', 'score': 'score', 'exception': 'residual_encoding'}[name]] = cantelli(mean, variance, cap+1)
        details[name] = {'uniform_coordinate_mean': rec(mu), 'uniform_coordinate_variance': rec(var),
                         'sum_mean_upper': rec(mean), 'sum_variance_upper': rec(variance),
                         'integer_failure_threshold': cap+1, 'coordinate_maximum': maximum}
    bounds['encoding_capacities'] = bounds.pop('head_encoding')+bounds.pop('residual_encoding')
    total = sum(bounds.values(), F(0))
    assert len(bounds) == 6 and total < F(293, 1000), 'Row failure must be below 0.293'
    # 512 within-row representatives, 1536 cross-row representatives.
    # Each direction has at most (q+1)/2 absolute projection bins.
    bins = F((Q+1)**2, 2)
    same = 512*bins*2*math.comb(512, 25)*F(2, Q)**25
    cross = 1536*bins*math.comb(1024, 49)*F(2, Q)**49
    repository = ROOT.parents[3]
    backend = repository/'crates/pretzel-4-4/core/src'
    sources = list(ROOT.glob('*.py')) + [
        repository/'crates/pretzel-5-5/certificates/rank5-dither/certify.py',
        ROOT/'reference_tables.rs']
    # Only the inputs parsed by certify_r4.read/source_model.parameters.
    # Whole-file hashes keep changes to these inputs fail-closed without tying
    # the certificate to unrelated backend implementations.
    sources += [backend/name for name in (
        'params.rs', 'params_tables.rs',
        'rice_codec.rs', 'dither_frame.rs')]
    output = {
        'status': 'COMPUTED_CONDITIONAL_THEOREM; CHEAP_CORE_CHECK_OPEN',
        'source_sha256': {str(s.relative_to(repository)): hashlib.sha256(s.read_bytes()).hexdigest() for s in sources},
        'program_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'arithmetic': 'Exact integer/rational; 160-bit signed outward Fourier intervals; 512-bit outward Chernoff',
        'parameters': p, 'geometry': geometry, 'spectra': spectral_summary,
        'uniform_quantization_error_second_moment': rec(F(34*sum(k*k for k in range(-112, 113))+31*113**2, Q)),
        'downward_sampler_domination': downward,
        'G': {'absolute_projection_occupancy_cap': OCC, 'coefficient_columns': 1024,
              'pair_representatives': 2048, 'one_coordinate_deletion_allowed': True,
              'any_real_core_checked': False},
        'fourier_product_upper_after_one_deletion': rec(eta), 'pair_tv_upper': rec(tv),
        'product_upper_allocation': extremizers,
        'six_failure_contributions': {k: rec(v) for k, v in bounds.items()},
        'row_failure_upper': rec(total), 'below_293_over_1000': total < F(293, 1000),
        'safe_reported_bound': rec(F(292944128348880, 10**15)),
        'head_score_mean_upper': rec(headmean), 'head_score_variance_upper': rec(headvar),
        'details': details, 'coefficient_cap_word_numerators': parts,
        'honest_expanded_core_exception_upper': rec(same+cross),
        'honest_exception_components': {'same_output_polynomial': rec(same), 'different_output_polynomials': rec(cross)},
        'honest_model': '4096 iid uniform F_q coefficients in A0, independent row tapes; b arbitrary, including honest correlated b',
        'scope': 'Pointwise in the dither; honestly expanded matrix in the ideal uniform-matrix model. G neither implies nor is implied by invertibility.'}
    assert total <= F(292944128348880, 10**15), 'Row failure exceeds the paper bound'
    assert same+cross < F(1423, 10**40)
    return output

def self_test():
    # Independent exact residual enumeration, including both dither endpoints.
    R.self_test()
    assert mul(iv(F(-3, 7)), iv(F(8, 11)))[0] <= -F(24, 77)*D <= mul(iv(F(-3, 7)), iv(F(8, 11)))[1]
    c = cosine_table(5)
    phi = spectrum({-1: 1, 0: 2, 1: 1}, c, 5)
    # Exhaustive four-coordinate head law, pair dependence, all 25 shifts,
    # and conditioning on each possible value of one head coordinate.
    coeffs = [(1, 0), (0, 1), (1, 1), (1, 2)]
    for fixed in (None, -1, 0, 1):
        indices = range(4) if fixed is None else range(1, 4)
        distribution = Counter()
        for xs in itertools.product((-1, 0, 1), repeat=len(indices)):
            full = xs if fixed is None else (fixed,)+xs
            w = math.prod(2 if x == 0 else 1 for x in xs)
            a = sum(x*y[0] for x, y in zip(full, coeffs)) % 5
            b = sum(x*y[1] for x, y in zip(full, coeffs)) % 5
            distribution[a, b] += w
        den = 4**len(indices)
        fourier_sum = F(0)
        for t, s in itertools.product(range(5), repeat=2):
            if (t, s) == (0, 0):
                continue
            bound = F(1)
            for k in indices:
                f = (t*coeffs[k][0]+s*coeffs[k][1]) % 5
                bound *= F(phi[min(f, 5-f)][1], D)
            fourier_sum += bound
        for delta in itertools.product(range(5), repeat=2):
            tv = sum(abs(F(distribution[((a-delta[0]) % 5, (b-delta[1]) % 5)], den)-F(1, 25))
                     for a, b in itertools.product(range(5), repeat=2))/2
            assert tv <= fourier_sum/2
        # Independent exact check of the variance constants used for a score
        # which shares its head coordinates with the residuals.
        hs, rs, products = F(0), F(0), F(0)
        total_first = total_second = F(0)
        for xs in itertools.product((-1, 0, 1), repeat=len(indices)):
            full = xs if fixed is None else (fixed,)+xs
            probability = F(math.prod(2 if x == 0 else 1 for x in xs), den)
            a = sum(x*y[0] for x, y in zip(full, coeffs)) % 5
            b = sum(x*y[1] for x, y in zip(full, coeffs)) % 5
            h = sum(x*x for x in xs)
            residual = int(a == 0)+int(b == 0)
            total_first += probability*(h+residual)
            total_second += probability*(h+residual)**2
        # Here exact independence of heads gives Var(H)=len(indices)/4;
        # uniform residual indicators have mean 1/5 and variance 4/25.
        delta = min(F(1), fourier_sum/2)
        mean_upper = F(len(indices), 2)+2*(F(1, 5)+delta)
        variance_upper = F(len(indices), 4)+F(8, 25)+3*4*delta+4*len(indices)*2*delta
        assert total_first <= mean_upper
        assert total_second-total_first**2 <= variance_upper
    # Exhaust all small cores. Check representative reduction against all
    # output-coordinate pairs, including common column sign changes.
    for flat in itertools.product(range(3), repeat=4):
        matrix = [[list(flat[:2])], [list(flat[2:])]]
        represented = check_core(matrix, 2, 3)['maximum_occupancy']
        all_rows = [row_coefficients(matrix, r, i, 3) for r in range(2) for i in range(2)]
        brute = max(occupancy(list(zip(a, b)), 3) for a, b in itertools.combinations(all_rows, 2))
        assert represented == brute
    # Larger power-of-two example checks the half-period representatives.
    matrix = [[[((r+2)*(k+1)+k*k) % 7 for k in range(8)]] for r in range(2)]
    represented = check_core(matrix, 8, 7)['maximum_occupancy']
    all_rows = [row_coefficients(matrix, r, i, 7) for r in range(2) for i in range(8)]
    assert represented == max(occupancy(list(zip(a, b)), 7) for a, b in itertools.combinations(all_rows, 2))
    zero = [[[0]*256 for _ in range(4)] for _ in range(4)]
    identity = [[[int(r == c and k == 0) for k in range(256)] for c in range(4)] for r in range(4)]
    # One direction witnesses failure immediately; no large G enumeration.
    for matrix in (zero, identity):
        points = list(zip(row_coefficients(matrix, 0, 0), row_coefficients(matrix, 0, 1)))
        assert sum(a == 0 for a, b in points) > OCC
    p, laws, wh, wr = R.read()
    rows, _ = R.S.residual_rows(laws['ERROR'], p)
    assert all(a >= 112 for a, j, w in rows[0])
    assert all(a >= 112 for a, j, w in rows[Q-1])
    assert 1024*112**2 > p['CAP_EUC2_RES']
    # Uniform-context residual moments agree with an independent error plus
    # quantization-error convolution, without assuming fixed-dither uniformity.
    centers = R.S.centers(Q, 34)
    quantization = Counter(R.S.centered(centers[34*t//Q]-t) for t in range(Q))
    assert quantization == Counter({**{k: 34 for k in range(-112, 113)}, -113: 16, 113: 15})
    for power in (2, 4):
        direct = sum(w*a**power for row in rows for a, j, w in row if a <= 450)
        convolution = sum(w*v*abs(e+z)**power for e, w in laws['ERROR'].items()
                          for z, v in quantization.items() if abs(e+z) <= 450)
        assert direct == convolution
    print('PASS: exact toy Fourier/TV with all shifts and conditional heads; exhaustive small cores; representative symmetry; sparse/invertible counterexamples; residual geometry.')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--check', action='store_true', help='recompute and reject any certificate or source drift')
    parser.add_argument('--check-core', type=Path)
    args = parser.parse_args()
    signal.alarm(240)
    if args.self_test:
        self_test()
    elif args.check_core:
        matrix = json.loads(args.check_core.read_text())
        assert len(matrix) == 4 and all(len(row) == 4 for row in matrix)
        assert all(len(poly) == 256 for row in matrix for poly in row)
        print(json.dumps(check_core(matrix), indent=2))
    else:
        output = compute()
        serialized = json.dumps(output, indent=2, sort_keys=True)+'\n'
        target = ROOT/'certificate_r4_spread.json'
        if args.check:
            assert target.read_text() == serialized, 'Stale rank-four certificate: rerun without --check and review the change'
        else:
            target.write_text(serialized)
        for k, v in output['six_failure_contributions'].items():
            print(k, v['decimal_upper'])
        print('ROW_FAILURE_UPPER', output['row_failure_upper']['decimal_upper'])
        print('PAIR_TV_UPPER', output['pair_tv_upper']['decimal_upper'])
        print('HONEST_CORE_EXCEPTION_UPPER', output['honest_expanded_core_exception_upper']['decimal_upper'])
