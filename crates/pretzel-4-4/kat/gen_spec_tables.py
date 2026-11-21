#!/usr/bin/env python3
"""Extract the selected Rust byte domains; no Rust execution or dependencies.

The parser deliberately accepts only the constant/cfg syntax used here. Unknown
syntax fails instead of guessing. --check detects stale checked-in output.
"""
import argparse
import ast
from pathlib import Path
import re
import tomllib

ROOT = Path(__file__).resolve().parents[3]
BACKEND = ROOT / 'crates/pretzel-4-4/core'
OUTPUT = ROOT / 'crates/pretzel-4-4/kat/spec_domains_table.tex'


def features():
    backend = tomllib.loads((BACKEND / 'Cargo.toml').read_text())
    facade = tomllib.loads((BACKEND.parent / 'Cargo.toml').read_text())
    # Two features, both empty and off by default. The table is extracted for the
    # default configuration: `stack-wipe` is treated as disabled, and it gates no
    # byte domain.
    if backend.get('features') != {'conformance': [], 'stack-wipe': []}:
        raise ValueError('Expected the fixed rank-four backend with only conformance and stack-wipe')
    if facade.get('features') != {'conformance': ['pretzel-4-4-core/conformance'],
                                  'stack-wipe': ['pretzel-4-4-core/stack-wipe']}:
        raise ValueError('Unexpected facade feature surface')
    if backend['dependencies']['libc'].get('optional', False):
        raise ValueError('The fixed native dependency must be mandatory')
    return set()


FEATURES = features()
TOKEN = re.compile(r'\s*(b"(?:[^"\\]|\\.)*"|"(?:[^"\\]|\\.)*"|[A-Za-z_][\w-]*|::|[^\s])')


class Expr:
    def __init__(self, text):
        self.tokens = TOKEN.findall(text)
        self.i = 0

    def take(self, expected=None):
        value = self.tokens[self.i]
        self.i += 1
        if expected is not None and value != expected:
            raise ValueError((expected, value))
        return value

    def cfg(self):
        name = self.take()
        if name == 'feature':
            self.take('=')
            feature = ast.literal_eval(self.take())
            if feature != 'conformance':
                raise ValueError('Unresolved implementation selector: ' + feature)
            return feature in FEATURES
        self.take('(')
        values = [self.cfg()]
        while self.tokens[self.i] == ',':
            self.take(',')
            values.append(self.cfg())
        self.take(')')
        if name == 'all':
            return all(values)
        if name == 'any':
            return any(values)
        if name == 'not' and len(values) == 1:
            return not values[0]
        raise ValueError('Unsupported cfg: ' + name)

    def value(self):
        token = self.take()
        if token.startswith('b"'):
            return ast.literal_eval(token)
        if token == 'if':
            self.take('cfg'); self.take('!'); self.take('(')
            condition = self.cfg()
            self.take(')')
            yes = self.value()
            self.take('else')
            no = self.value()
            return yes if condition else no
        if token == '{':
            values = []
            while self.tokens[self.i] != '}':
                enabled = True
                while self.tokens[self.i] == '#':
                    self.take('#'); self.take('['); self.take('cfg'); self.take('(')
                    enabled &= self.cfg()
                    self.take(')'); self.take(']')
                value = self.value()
                if enabled:
                    values.append(value)
            self.take('}')
            if len(values) != 1:
                raise ValueError('Ambiguous cfg block')
            return values[0]
        if token == 'crate':
            self.take('::'); module = self.take(); self.take('::'); name = self.take()
            return constant(module, name)
        raise ValueError('Unsupported expression: ' + token)


def constant(module, name):
    source = (BACKEND / 'src' / (module + '.rs')).read_text()
    matches = []
    pattern = r'(?m)^(?:pub(?:\(crate\))?\s+)?const\s+' + name + r'\s*:[^=]+='
    for found in re.finditer(pattern, source):
        preceding = source[:found.start()].splitlines()
        enabled = True
        for line in reversed(preceding):
            line = line.strip()
            if line.startswith('#[cfg(') and line.endswith(']'):
                enabled &= Expr(line[len('#[cfg('):-2]).cfg()
            elif line.startswith('//'):
                continue
            else:
                break
        if enabled:
            parser = Expr(source[found.end():source.index(';', found.end())])
            value = parser.value()
            if parser.i != len(parser.tokens):
                raise ValueError('Trailing constant syntax: ' + name)
            matches.append(value)
    if len(matches) != 1:
        raise ValueError(f'{module}::{name}: expected one selected definition, got {len(matches)}')
    return matches[0]


def domains():
    rows = [('id', 'Parameter identifier', constant('params', 'PROFILE_ID')),
            ('key', 'Key seed', constant('params', 'DOM_KEY')),
            ('matrix', 'Matrix', constant('direct_ntt_profile', 'MATRIX_DOMAIN')),
            ('dither', 'Dither', constant('dither_frame', 'DOMAIN')),
            ('message', 'Message', constant('params', 'DOM_MSG')),
            ('challenge', 'Challenge', constant('params', 'DOM_CHAL')),
            ('public_row', 'Public test sample', b'PRETZEL-RICE-PUBLIC-ROW-v1'),
            ('schedule', 'Attempt schedule', constant('randomness', 'CT_TAPE_DOMAIN'))]
    for key, label, name in [('salt', 'Salt', 'DOM_SALT'), ('lead', 'Lead', 'DOM_MASK_LEAD'),
                             ('secret', 'Secret', 'DOM_MASK_SEC'), ('error', 'Error', 'DOM_MASK_ERR'),
                             ('transport', 'Transport', 'DOM_TRANSPORT'), ('dummy', 'Dummy', 'DOM_DUMMY')]:
        rows.append((key, label, constant('params', name)))
    rows.append(('integrity', 'Public-body integrity', b''))
    # The optimized public prefix has local constants too. Fail on divergence.
    values = dict((key, value) for key, _, value in rows)
    for name, key in [('DD', 'dither'), ('DM', 'message'), ('DC', 'challenge')]:
        assert constant('public_common_prefix', name) == values[key], name
    return rows


def check_layouts(rows):
    d = {key: value for key, _, value in rows}
    field = lambda value: len(value).to_bytes(8, 'little') + value
    core = bytes(32 + 4 * 256 * 13 // 8)
    seed = bytes(32)
    body = core + seed
    common = field(d['id']) + field(core)
    layouts = {
        'key': d['key'] + field(seed),
        'public_row': d['public_row'] + common + field(seed) + (0).to_bytes(4, 'little'),
        'integrity': body,
        'challenge': common + d['challenge'] + seed + field(bytes(64)) + field(seed) + field(bytes(4 * 256)),
    }
    for key, expected in [('key', 53), ('public_row', 1796), ('integrity', 1728), ('challenge', 2916)]:
        if len(layouts[key]) != expected:
            raise ValueError(f'{key}: {len(layouts[key])} != {expected}')
    if len(d['id']) != 14:
        raise ValueError('Wrong key tag size')


def render():
    rows = domains()
    check_layouts(rows)
    lines = [r'% Generated by kat/gen_spec_tables.py; do not edit.',
             r'\begin{center}\scriptsize',
             r'\begin{tabular}{@{}p{.23\linewidth}p{.73\linewidth}@{}}',
             r'Use & Bytes (hexadecimal; empty means no prefix)\\\hline']
    for key, label, value in rows:
        chunks = [value.hex()[i:i+40] for i in range(0, len(value.hex()), 40)] or ['']
        cell = r'\allowbreak{}'.join(r'\texttt{' + c + '}' for c in chunks)
        lines.append(label + ' & ' + cell + r' \\ % spec:' + key)
    lines.extend([r'\end{tabular}\end{center}',
        r'\noindent Let $[x]=\operatorname{len}(x)\mid x$, with an unsigned 64-bit',
        r'little-endian byte length. Below, $C$ is the core public key, $B=C\mid d$',
        r'is the untagged public body, $d$ is the dither seed, and $D_r$ is the',
        r'table entry for role $r$. Seeds, the PRF key $k$, entropy $e$ and salt',
        r'$\rho$ have 32 bytes; $\mu$ has 64 bytes. Both indices are unsigned',
        r'32-bit little-endian integers; the matrix stream $s$ is one byte.',
        r'\begin{center}\scriptsize',
        r'\begin{tabular}{@{}ll@{}}',
        r'Key seed & $D_{\rm key}\mid[\mathit{seed}]$\\',
        r'Matrix & $D_{\rm matrix}\mid[\rho_A]\mid[s]$\\',
        r'Dither & $[\mathit{id}]\mid[C]\mid D_{\rm dither}\mid[d]$\\',
        r'Message & $[\mathit{id}]\mid[C]\mid D_{\rm message}\mid d\mid[\mathit{context}]\mid[\mathit{message}]$\\',
        r'Challenge & $[\mathit{id}]\mid[C]\mid D_{\rm challenge}\mid d\mid[\mu]\mid[\rho]\mid[U]$\\',
        r'Public test sample & $D_{\rm public\ row}\mid[\mathit{id}]\mid[C]\mid[\mathit{pool}]\mid i$\\',
        r'Attempt role $r$ & $D_r\mid[\mathit{id}]\mid[D_{\rm schedule}]\mid[k]\mid[B]\mid[\mu]\mid[j]\mid[e]$\\',
        r'\end{tabular}\end{center}', ''])
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    result = render()
    if args.check:
        if OUTPUT.read_text() != result:
            raise SystemExit('Stale domain table; run ' + str(Path(__file__).relative_to(ROOT)))
    else:
        OUTPUT.write_text(result)
    print('Domain bytes and four specified input lengths checked.')


if __name__ == '__main__':
    main()
