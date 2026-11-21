"""Source-derived CDT boundaries and hashes; no native code execution."""
import ast
from decimal import Decimal, localcontext, ROUND_FLOOR
import hashlib
import re
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / 'core/src'
MASK = (1 << 64) - 1


def read(name):
    return (SRC / name).read_text()


def match(name, pattern):
    m = re.search(pattern, read(name), re.S)
    if not m:
        raise ValueError(f'Unsupported source syntax in {name}: {pattern}')
    return m


def integer(name, symbol):
    # Delegate cfg selection to the same parser used for the domain table.
    from gen_spec_tables import Expr
    source = read(name)
    values = []
    for m in re.finditer(r'(?m)^(?:pub(?:\(crate\))?\s+)?const\s+' + symbol + r'\s*:[^=]+=(.*?);', source):
        enabled = True
        for line in reversed(source[:m.start()].splitlines()):
            line = line.strip()
            if line.startswith('#[cfg('):
                enabled &= Expr(line[len('#[cfg('):-2]).cfg()
            elif line.startswith('//'):
                continue
            else:
                break
        if enabled:
            def evaluate(node):
                if isinstance(node, ast.Constant) and isinstance(node.value, int):
                    return node.value
                if isinstance(node, ast.Name):
                    return integer(name, node.id)
                if isinstance(node, ast.BinOp):
                    a, b = evaluate(node.left), evaluate(node.right)
                    for op, fn in [(ast.Add, lambda: a+b), (ast.Sub, lambda: a-b),
                                   (ast.Mult, lambda: a*b), (ast.Div, lambda: a//b), (ast.LShift, lambda: a << b)]:
                        if isinstance(node.op, op):
                            return fn()
                raise ValueError('Unsupported integer expression: ' + symbol)
            values.append(evaluate(ast.parse(m.group(1).strip(), mode='eval').body))
    if len(values) != 1:
        raise ValueError(f'{name}:{symbol}: expected one selected integer, got {values}')
    return values[0]


def theta():
    body = match('params.rs', r'const THETA_NUM_LIMBS:.*?=\s*\[(.*?)\];').group(1)
    limbs = [int(x.strip(), 0) for x in body.split(',') if x.strip()]
    return sum(w << (64*i) for i, w in enumerate(limbs)), 64*len(limbs)


def serialize(rows):
    return b''.join(w.to_bytes(8, 'little') for row in rows for w in row)


def decode_bounds(name, count):
    encoded = (SRC / name).read_bytes()
    cur = value = 0
    rows = []
    for _ in range(count):
        size = encoded[cur]; cur += 1
        value += int.from_bytes(encoded[cur:cur+size], 'little'); cur += size
        rows.append([(value >> shift) & MASK for shift in (128, 64, 0)])
    assert cur == len(encoded)
    return rows


def cdt(weight, step, precision):
    # Decimal reconstruction is cross-checked at two precisions and against
    # every stored secret/error boundary. It is not a new interval certificate.
    numerator, bits = theta()
    frac = 64 * integer('fixed.rs', 'FRAC_LIMBS')
    with localcontext() as ctx:
        ctx.prec = precision
        logtheta = (Decimal(numerator) / (1 << bits)).ln()
        scale = Decimal(1 << frac)
        values, weights = [0], [Decimal(1)]
        x = step
        value = (logtheta * (weight*step*step)).exp()
        ratio = (logtheta * (3*weight*step*step)).exp()
        ratio_step = (logtheta * (2*weight*step*step)).exp()
        while True:
            if value*scale <= 1:
                break
            values.extend([x, -x]); weights.extend([value, value]); x += step
            value *= ratio
            ratio *= ratio_step
        cumulative, total = [], Decimal(0)
        for value in weights:
            total += value
            cumulative.append(int((total*scale).to_integral_value(rounding=ROUND_FLOOR)))
        z = cumulative[-1]
        draw_bits = z.bit_length()
        def window(value):
            return [(value >> (draw_bits - n)) & MASK for n in (64, 128, 192)]
        return values, [window(c) for c in cumulative], window(z), draw_bits


def tables():
    steps = tuple(map(int, match('gauss.rs', r'let step = if even_only \{ (\d+) \} else \{ (\d+) \}').groups()))
    normalizers = [[int(x, 16) for x in row.split(',')] for row in
                   re.findall(r'\d+=>\[(0x[0-9a-f]+,0x[0-9a-f]+,0x[0-9a-f]+)\]', read('ct_rarequeue.rs'))]
    result = []
    for name, symbol, step in [('lead', 'PROPOSAL_W0', steps[0]), ('sec', 'WS', steps[1]), ('err', 'WE', steps[1])]:
        weight = integer('params.rs', symbol)
        value = cdt(weight, step, 240)
        assert value == cdt(weight, step, 320), 'CDT precision sensitivity'
        values, bounds, z, draw_bits = value
        assert z in normalizers, name
        if name != 'lead':
            assert bounds == decode_bounds('collapsed_bounds_' + name + '.bin', len(values)), name
            record = match('warm_collapsed_identities.rs', rf'static {name.upper()}:Table=Table\{{z:\[(\d+), (\d+), (\d+)\],bounds:(\d+)')
            assert list(map(int, record.groups()[:3])) == z
            assert int(record.group(4)) == len(values)
        data = serialize(bounds)
        result.append(dict(name=name, weight=weight, step=step, entries=len(values), maximum=max(values),
                           draw_bits=draw_bits, z=z, bytes=len(data),
                           sha256=hashlib.sha256(data).hexdigest(),
                           with_z_sha256=hashlib.sha256(data+serialize([z])).hexdigest()))
    return result


def literal_table(file, symbol):
    source = read(file)
    start = source.index('{', source.index(symbol))
    stop = source.index('};', start)
    body = re.sub(r'UINT64_C\((\d+)\)', r'\1', source[start:stop+1])
    words = [int(x) for x in re.findall(r'-?\d+(?=\)|,|})', body)]
    data = b''.join((w & MASK).to_bytes(8, 'little') for w in words)
    return len(words), hashlib.sha256(data).hexdigest()
