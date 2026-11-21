#!/usr/bin/env python3
"""Row certificate of Pretzel-(5,5). Standard library only, no native code execution.

All deciding arithmetic is integer, rational, or outward dyadic arithmetic.
Finite row laws are read from reference_tables.rs in this directory, never normalized.
Every residual moment is maximized over all 7681 contexts. JSON decimals
are directed rational enclosures. This program does not benchmark anything.
"""
from fractions import Fraction
import hashlib
import json
from math import comb
from pathlib import Path
import re
import sys
import ast
import argparse

ROOT = Path(__file__).resolve().parent
BITS = 512
UNIT = 1 << BITS
WORD = 1 << 32
REPOSITORY = ROOT.parents[3]
SOURCE = REPOSITORY / 'crates/pretzel-5-5/src'


def source_constant(file, name):
    """Only integer literals, names and arithmetic; never execute Rust source."""
    text = (SOURCE/file).read_text()
    matches = re.findall(r'\bconst '+name+r'\s*:[^=]+ = ([^;]+);', text)
    require(len(matches) == 1, 'ambiguous or missing constant: '+name)
    def evaluate(node):
        if isinstance(node, ast.Constant) and type(node.value) is int:
            return node.value
        if isinstance(node, ast.Name):
            return source_constant(file, node.id)
        if isinstance(node, ast.BinOp):
            left, right = evaluate(node.left), evaluate(node.right)
            if isinstance(node.op, ast.Add): return left+right
            if isinstance(node.op, ast.Sub): return left-right
            if isinstance(node.op, ast.Mult): return left*right
        raise ArithmeticError('unsupported constant expression: '+name)
    return evaluate(ast.parse(matches[0], mode='eval').body)


def source_function(file, name):
    """Scope literal checks to one top-level Rust function, excluding test copies."""
    text = (SOURCE/file).read_text()
    matches = re.findall(r'\bfn '+re.escape(name)+r'\s*\([^\{]*\{(.*?)^\}', text, re.S | re.M)
    require(len(matches) == 1, 'ambiguous or missing function: '+file+':'+name)
    return re.sub(r'//[^\n]*', '', matches[0])


def unique_literals(pattern, body, label):
    matches = re.findall(pattern, body)
    require(len(matches) == 1, 'ambiguous or missing admission literals: '+label)
    values = (matches[0],) if isinstance(matches[0], str) else matches[0]
    return tuple(map(int, values))


def admission_caps():
    """The limits that the admission enforces, read from the sources.

    The scalar predicate and the NEON function compiled for tests state them as literals.
    The NEON function that the signer runs and the two verifier sites name the format limits
    of params.rs. All must agree; the value returned is the literal of the scalar predicate.
    """
    head = r'let \(cap, half\) = if i < (\d+) \{ \((\d+), (\d+)\) \} else \{ \((\d+), (\d+)\) \}'
    residual = (r'let in_residuals = opaque\(vcleq_u32\(\s*'
                r'vreinterpretq_u32_s32\(vabsq_s32\(r\)\),\s*vdupq_n_u32\(%s\),\s*\)\);')
    scalar = source_function('signature_codec.rs', 'capacity_mask_scalar')
    scalar_head = unique_literals(head, scalar, 'scalar head')
    scalar_res = unique_literals(r'residual\[i\]\.unsigned_abs\(\) <= (\d+)',
                                 scalar, 'scalar residual')
    body = source_function('admission_neon.rs', 'capacity_mask')
    require(unique_literals(head, body, 'capacity_mask head') == scalar_head,
            'NEON/scalar head admission mismatch: capacity_mask')
    require(unique_literals(residual % r'(\d+)', body, 'capacity_mask residual') == scalar_res,
            'NEON/scalar residual admission mismatch: capacity_mask')
    limits = tuple(source_constant('params.rs', name) for name in
                   ('FORMAT_HEAD_LIMIT_LEAD', 'FORMAT_HEAD_LIMIT', 'FORMAT_RES_LIMIT'))
    body = source_function('admission_neon.rs', 'capacity_mask_aux_i16')
    count, lead_half, half = unique_literals(
        r'let \(cap, half\) = if i < (\d+) \{\s*'
        r'\(crate::params::FORMAT_HEAD_LIMIT_LEAD as u32, (\d+)\)\s*\} else \{\s*'
        r'\(crate::params::FORMAT_HEAD_LIMIT as u32, (\d+)\)\s*\};',
        body, 'capacity_mask_aux_i16 head')
    require((count, limits[0], lead_half, limits[1], half) == scalar_head,
            'NEON/scalar head admission mismatch: capacity_mask_aux_i16')
    require(len(re.findall(residual % r'crate::params::FORMAT_RES_LIMIT as u32', body)) == 1
            and (limits[2],) == scalar_res,
            'NEON/scalar residual admission mismatch: capacity_mask_aux_i16')
    require((SOURCE/'signature_codec.rs').read_text().count(
                'if magnitude <= crate::params::FORMAT_RES_LIMIT as u32 {') == 1
            and (SOURCE/'neon.rs').read_text().count(
                'if vmaxvq_u16(magnitude) > crate::params::FORMAT_RES_LIMIT as u16 {') == 1,
            'verifier residual limit sites changed; review binding')
    return scalar_head, scalar_res[0]


def configure():
    global Q, THETA, N, HEAD_COUNT, RES_COUNT, LEAD_CAP, HEAD_CAP, RES_CAP
    global LEAD_HALF, HEAD_HALF, HEAD_EXCEPTIONS, LABEL_EXCEPTIONS, CAPS, WEIGHTS
    global EXPANSION_WORDS, MAX_CANDIDATES
    Q = source_constant('params.rs', 'Q')
    N = source_constant('params.rs', 'N')
    HEAD_COUNT = N*source_constant('params.rs', 'ELL')
    RES_COUNT = N*source_constant('params.rs', 'M')
    require(source_constant('params.rs', 'LQ') == 64 and Q == 7681,
            'quantizer proof requires review for new geometry')
    head, RES_CAP = admission_caps()
    leading_count, LEAD_CAP, LEAD_HALF, HEAD_CAP, HEAD_HALF = head
    require(leading_count == N, 'leading admission dimension mismatch')
    require(HEAD_CAP == source_constant('params.rs', 'CAP_INF_HEAD'), 'head cap mismatch')
    require(RES_CAP <= source_constant('params.rs', 'CAP_INF_RES'), 'residual cap mismatch')
    require(source_constant('signature_codec.rs', 'HEAD_COEFFICIENTS') == N+HEAD_COUNT,
            'head dimension mismatch')
    require(source_constant('signature_codec.rs', 'LABELS') == RES_COUNT, 'residual dimension mismatch')
    HEAD_EXCEPTIONS = source_constant('signature_codec.rs', 'HEAD_EXCEPTIONS')
    LABEL_EXCEPTIONS = source_constant('signature_codec.rs', 'LABEL_EXCEPTIONS')
    CAPS = {target: source_constant('params.rs', name) for target, name in
            [('head', 'CAP_EUC2_HEAD'), ('res', 'CAP_EUC2_RES'), ('secant', 'CAP_Q20')]}
    WEIGHTS = [source_constant('params.rs', name) for name in ('PROPOSAL_W0', 'WS', 'WE')]
    limbs = [int(x.replace('_',''), 16) for x in re.findall(r'0x[0-9a-f_]+',
             parse_array(SOURCE/'params.rs', 'THETA_NUM_LIMBS'))]
    require(len(limbs) == 4, 'theta dimensions')
    THETA = sum(x << (64*i) for i, x in enumerate(limbs))
    EXPANSION_WORDS = source_constant('dither_frame.rs', 'EXPANSION_CANDIDATES')
    MAX_CANDIDATES = source_constant('dither_frame.rs', 'MAX_CANDIDATES')
    require(source_constant('dither_frame.rs', 'DITHER_COEFFICIENTS') == RES_COUNT,
            'expansion dimension mismatch')
    # These are executable predicate connections, not names in comments.
    signer = (SOURCE/'prepared_signer.rs').read_text()
    require('check_caps_ct(z_h, r_e)' in signer and
            'crate::signature_codec::capacity_mask(z_h, u_labels, r_e, &mut local)' in signer,
            'signer admission call sites changed; review binding')
    verifier = (SOURCE/'verifier.rs').read_text()
    for predicate in ['head >> 32 > CAP_EUC2_HEAD', 'packed >> 32 > CAP_EUC2_RES',
                      '(head as u32 as u64) + (packed as u32 as u64) > CAP_Q20']:
        require(predicate in verifier, 'selected verifier cap checks changed: '+predicate)
    require('signed_head_caps::packed(head)' in verifier and
            'compact_residual_caps(' in verifier and 'W_RES[i] as u64' in verifier,
            'selected verifier statistics changed; review binding')
    return dict(q=Q, leading=N, head=HEAD_COUNT, residual=RES_COUNT,
                leading_cap=LEAD_CAP, head_cap=HEAD_CAP, residual_cap=RES_CAP,
                leading_half=LEAD_HALF, head_half=HEAD_HALF, caps=CAPS, weights=WEIGHTS,
                head_exceptions=HEAD_EXCEPTIONS, label_exceptions=LABEL_EXCEPTIONS,
                expansion_words=EXPANSION_WORDS, maximum_candidates=MAX_CANDIDATES,
                theta=str(THETA))


def require(ok, message):
    if not ok:
        raise ArithmeticError(message)


def ceildiv(a, b):
    return -(-a // b)


def rat(a, b=1):
    require(a >= 0 and b > 0, 'nonnegative interval domain')
    return (a*UNIT//b, ceildiv(a*UNIT, b))


def add(*values):
    return tuple(sum(v[j] for v in values) for j in (0, 1))


def mul(a, b):
    return (a[0]*b[0]//UNIT, ceildiv(a[1]*b[1], UNIT))


def div(a, b):
    require(b[0] > 0, 'positive denominator')
    return (a[0]*UNIT//b[1], ceildiv(a[1]*UNIT, b[0]))


def power(a, n):
    result = (UNIT, UNIT)
    while n:
        if n & 1:
            result = mul(result, a)
        n //= 2
        if n:
            a = mul(a, a)
    return result


def scaled(a, n, d=1):
    return (a[0]*n//d, ceildiv(a[1]*n, d))


def maximum(values):
    values = list(values)
    return (max(v[0] for v in values), max(v[1] for v in values))


def decimal(n, d, upward=False, places=100):
    z = ceildiv(n*10**places, d) if upward else n*10**places//d
    s = str(z).rjust(places+1, '0')
    return s[:-places]+'.'+s[-places:]


def record(a):
    return dict(lower_numerator=str(a[0]), upper_numerator=str(a[1]),
                denominator_power_of_two=BITS,
                lower_decimal=decimal(a[0], UNIT),
                upper_decimal=decimal(a[1], UNIT, True),
                scientific_upper=scientific_upper(a[1], UNIT))


def scientific_upper(n, d):
    if n == 0:
        return '0'
    exponent = 0
    if n >= d:
        while n >= 10*d:
            d *= 10
            exponent += 1
    else:
        while n < d:
            n *= 10
            exponent -= 1
    return decimal(n, d, upward=True, places=14)+'e'+str(exponent)


def exact_record(a):
    return record(rat(a.numerator, a.denominator))


def parse_array(path, name):
    text = path.read_text()
    match = re.search(r'\b'+name+r'[^=]*=\s*&?\[(.*?)\];', text, re.S)
    require(match is not None, 'missing array '+name)
    return match[1]


def parse_law(name):
    raw = parse_array(ROOT/'reference_tables.rs', name)
    endpoints = [(int(a), int(b)) for a, b in re.findall(r'\((\d+),\s*(-?\d+)\)', raw)]
    previous = 0
    values = {}
    for end, value in endpoints:
        require(previous < end < WORD and value not in values, 'CDF ordering')
        values[value] = end-previous
        previous = end
    return values


def moments(law, exponents, base):
    cache = {e: power(base, e) for e in set(exponents.values())}
    return scaled(add(*(scaled(cache[exponents[v]], n) for v, n in law.items()
                        if v in exponents)), 1, WORD)


def binomial_prefix(n, a, b, limit):
    """Integer masses, common denominator b**n; no subtraction of floats."""
    return [comb(n, k)*a**k*(b-a)**(n-k) for k in range(min(n, limit)+1)]


def binomial_tail(n, a, b, first):
    if first <= 0:
        return Fraction(1)
    if first > n:
        return Fraction(0)
    numerator = sum(comb(n, k)*a**k*(b-a)**(n-k) for k in range(first, n+1))
    return Fraction(numerator, b**n)


def input_hashes():
    # Include predicate implementations: any change requires a fresh certificate
    # and native predicate-binding tests, even if the six numerical terms agree.
    names = ['params_tables.rs', 'params.rs', 'signature_codec.rs',
             'quantize.rs', 'dither_frame.rs', 'scheme.rs', 'prepared_signer.rs',
             'keygen_dither_check.rs', 'dither_setup.rs', 'public_common_prefix.rs',
             'ct_lookup.rs', 'ct_caps_piecewise.rs', 'cap_piecewise_tables.rs',
             'admission_neon.rs', 'public_recovery_table.rs', 'dither_certificate_tests.rs',
             'verifier.rs', 'signed_head_caps.rs', 'neon.rs', 'api.rs']
    hashes = {name: hashlib.sha256((SOURCE/name).read_bytes()).hexdigest() for name in names}
    hashes['reference_tables.rs'] = hashlib.sha256((ROOT/'reference_tables.rs').read_bytes()).hexdigest()
    return hashes


def downward(laws):
    theta = rat(THETA, 1 << 256)
    result = {}
    for name, weight, parity in [('EVEN', WEIGHTS[0], 0), ('ODD', WEIGHTS[0], 1),
                                 ('SECRET', WEIGHTS[1], None), ('ERROR', WEIGHTS[2], None)]:
        weights = {z: power(theta, weight*z*z) for z in range(1501)
                   if parity is None or z % 2 == parity}
        partial = add(*(scaled(w, 1 if z == 0 else 2) for z, w in weights.items()))
        # A two-sided tail over ALL integers is conservative for each parity.
        first, step = power(theta, weight*1501**2), power(theta, weight*3003)
        tail = div(scaled(first, 2), (UNIT-step[1], UNIT-step[0]))
        normalizer = (partial[0], partial[1]+tail[1])
        gaps = []
        for z, count in laws[name].items():
            require(parity is None or z % 2 == parity, 'sample parity')
            lower = div(weights[abs(z)], normalizer)[0]
            require(count*UNIT <= WORD*lower, 'atom not downward: '+name+':'+str(z))
            gaps.append(WORD*lower-count*UNIT)
        result[name] = dict(atoms=len(laws[name]), missing_words=WORD-sum(laws[name].values()),
                            full_normalizer=record(normalizer), omitted_weight=record(tail),
                            minimum_downward_margin_numerator=str(min(gaps)),
                            margin_denominator_power_of_two=BITS+32)
    return result


def centered(x):
    return (x+3840) % Q-3840


def center(u):
    return 120*u+60+int(u != 0 and u % 2 == 0)


def residual_rows(error):
    prefix = [0]
    for z in range(-Q, Q+1):
        prefix.append(prefix[-1]+error.get(z, 0))

    def mass(lo, hi):
        lo, hi = max(lo, -Q), min(hi, Q+1)
        return 0 if hi <= lo else prefix[hi+Q]-prefix[lo+Q]

    rows = []
    list_counts = {7: 0, 8: 0}
    for x in range(Q):
        expected = sorted((abs(centered(center(u)-x)), centered(center(u)-x), u)
                          for u in range(64) if abs(centered(center(u)-x)) <= RES_CAP)
        require(len(expected) in (7, 8), 'local list size')
        list_counts[len(expected)] += 1
        local = {u: j for j, (_, _, u) in enumerate(expected)}
        # Independently transcribed source's two-frontier public table algorithm.
        base = 64*x//Q
        left = (base-int(center(base)-x >= 0)) & 63
        right = (left+1) & 63
        actual = []
        for j in range(8):
            a, b = centered(center(left)-x), centered(center(right)-x)
            if -a <= b:
                label, residual = left, a
                left = (left-1) & 63
            else:
                label, residual = right, b
                right = (right+1) & 63
            if abs(residual) <= RES_CAP:
                actual.append((abs(residual), residual, label))
        require(actual == expected, 'public recovery list mismatch')
        row = []
        for u in range(64):
            lo, hi = (Q*u+63)//64-x, (Q*(u+1)+63)//64-x
            count = sum(mass(lo+k*Q, hi+k*Q) for k in (-1, 0, 1))
            if count:
                a = abs(centered(center(u)-x))
                row.append((a, local.get(u), count))
        require(sum(n for _, _, n in row) == sum(error.values()), 'residual mass conservation')
        require(all((j is not None) == (a <= RES_CAP) for a, j, _ in row), 'found equivalence')
        rows.append(row)
    return rows, dict(contexts=Q, total_present_slots=sum(k*v for k, v in list_counts.items()),
                      list_counts=list_counts, source_algorithm_matches_sorted_definition=True)


def chernoff(laws, rows, wh, wr, target, base_num, base_den):
    base = rat(base_num, base_den)
    blocks = []
    if target in ('head', 'secant'):
        f = (lambda a: wh[a]) if target == 'secant' else (lambda a: a*a)
        lead = maximum(moments(laws[name], {v: f(abs(v)) for v in laws[name] if abs(v) <= LEAD_CAP}, base)
                       for name in ('EVEN', 'ODD'))
        middle = moments(laws['SECRET'], {v: f(abs(v)) for v in laws['SECRET'] if abs(v) <= HEAD_CAP}, base)
        blocks.extend([(lead, N), (middle, HEAD_COUNT)])
    worst = None
    if target in ('res', 'secant'):
        f = (lambda a: wr[a]) if target == 'secant' else (lambda a: a*a)
        cache = {a: power(base, f(a)) for a in range(RES_CAP+1)}
        candidates = [scaled(add(*(scaled(cache[a], n) for a, _, n in row if a <= RES_CAP)), 1, WORD)
                      for row in rows]
        worst = max(range(Q), key=lambda x: candidates[x][1])
        blocks.append((maximum(candidates), RES_COUNT))
    value = (UNIT, UNIT)
    for moment, count in blocks:
        value = mul(value, power(moment, count))
    threshold = CAPS[target]+1
    value = div(value, power(base, threshold))
    return value, dict(base=[base_num, base_den], integer_failure_threshold=threshold,
                       moments=[dict(count=n, interval=record(m)) for m, n in blocks],
                       worst_context=worst, tail_upper=record(value))


def capacities(laws, rows):
    p0 = max(sum(n for v, n in laws[name].items() if not -LEAD_HALF <= v < LEAD_HALF)
             for name in ('EVEN', 'ODD'))
    ps = sum(n for v, n in laws['SECRET'].items() if not -HEAD_HALF <= v < HEAD_HALF)
    pr = max(sum(n for a, j, n in row if a <= RES_CAP and j >= 4) for row in rows)
    lead = binomial_prefix(N, p0, WORD, HEAD_EXCEPTIONS)
    middle = binomial_prefix(HEAD_COUNT, ps, WORD, HEAD_EXCEPTIONS)
    denom = WORD**(N+HEAD_COUNT)
    good = sum(lead[i]*middle[j] for i in range(HEAD_EXCEPTIONS+1)
               for j in range(HEAD_EXCEPTIONS+1-i))
    head_tail = Fraction(denom-good, denom)
    label_tail = binomial_tail(RES_COUNT, pr, WORD, LABEL_EXCEPTIONS+1)
    bound = head_tail+label_tail
    return rat(bound.numerator, bound.denominator), dict(
        probability_numerators=[p0, ps, pr], head_tail=exact_record(head_tail),
        label_tail=exact_record(label_tail), total=exact_record(bound))


def run(check):
    result = dict(arithmetic='outward 512-bit dyadic intervals and exact rational tails',
                  source_constants=configure(), input_sha256=input_hashes())
    laws = {name: parse_law(name) for name in ('EVEN', 'ODD', 'SECRET', 'ERROR')}
    wh, wr = [list(map(int, re.findall(r'\d+', parse_array(SOURCE/'params_tables.rs', name))))
              for name in ('W_HEAD', 'W_RES')]
    require(len(wh) == HEAD_CAP+1 and len(wr) == source_constant('params.rs', 'CAP_INF_RES')+1, 'score table lengths')
    result['downward_sampling'] = downward(laws)
    print('Downward finite sampler certified.', flush=True)
    rows, geometry = residual_rows(laws['ERROR'])
    result['geometry'] = geometry
    missing = Fraction(N*max(WORD-sum(laws[name].values()) for name in ('EVEN', 'ODD'))
                       +HEAD_COUNT*(WORD-sum(laws['SECRET'].values()))
                       +RES_COUNT*(WORD-sum(laws['ERROR'].values())), WORD)
    leading_cap = N*max(sum(n for v, n in laws[name].items() if abs(v) > LEAD_CAP) for name in ('EVEN', 'ODD'))
    middle_cap = HEAD_COUNT*sum(n for v, n in laws['SECRET'].items() if abs(v) > HEAD_CAP)
    residual_cap = RES_COUNT*max(sum(n for a, _, n in row if a > RES_CAP) for row in rows)
    coefficient = Fraction(leading_cap+middle_cap+residual_cap, WORD)
    total_common = rat((missing+coefficient).numerator, (missing+coefficient).denominator)
    result['row_components'] = dict(missing_mass_union=exact_record(missing),
                                    cap_word_numerators=dict(leading=leading_cap, middle=middle_cap, residual=residual_cap),
                                    coefficient_cap_union=exact_record(coefficient))
    for target, a, b in [('head', 1000037, 1000000), ('res', 1000023, 1000000),
                         ('secant', 10000027, 10000000)]:
        bound, details = chernoff(laws, rows, wh, wr, target, a, b)
        result['row_components'][target] = details
        total_common = add(total_common, bound)
    capacity, details = capacities(laws, rows)
    result['capacity_components'] = details
    total = add(total_common, capacity)
    require(Fraction(total[1], UNIT) < Fraction(11, 1000),
            'row failure bound violates proof requirement 11/1000')
    require(total[1]*10**7 < 106685*UNIT, 'row failure bound exceeds 0.0106685')
    result['row_failure_upper'] = record(total)
    expansion = binomial_tail(EXPANSION_WORDS, 8192-Q, 8192,
                              EXPANSION_WORDS-RES_COUNT+1)
    require(expansion < Fraction(1, 2**366), 'dither expansion failure bound exceeds 2^-366')
    result['expansion_failure'] = exact_record(expansion)
    result['program_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    result['printed_total'] = decimal(total[1], UNIT, upward=True, places=16)
    for name in ('missing_mass_union', 'coefficient_cap_union', 'head', 'res', 'secant'):
        value = result['row_components'][name]
        print(name+': '+value.get('tail_upper', value)['scientific_upper'])
    print('encoding: '+details['total']['scientific_upper'])
    print('total < '+result['printed_total'])
    print('Proof requirement: total < 11/1000; regression lock: total < 0.0106685.')
    print('expansion_failure: '+result['expansion_failure']['scientific_upper']+' < 2^-366')
    encoded = json.dumps(result, indent=2, sort_keys=True)+'\n'
    output = ROOT/'certificate_r5.json'
    if check:
        require(output.read_text() == encoded, 'stale certificate: rerun certify.py and review the change')
        print('Current-source certificate matches.')
    else:
        output.write_text(encoded)
        print('Wrote certificate_r5.json.')


if __name__ == '__main__':
    # Arguments are read before any computation, so that a mistyped flag fails at once.
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='recompute and compare with the committed certificate')
    arguments = parser.parse_args()
    if hasattr(sys, 'set_int_max_str_digits'):
        sys.set_int_max_str_digits(0)
    run(arguments.check)
