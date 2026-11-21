#!/usr/bin/env python3
"""Regenerate public tables without compiling or running a signer.

Run: python3 crates/pretzel-4-4/core/generators/gen_public_tables.py --check
Use --output-dir DIR to write candidates beneath DIR, never into the source tree.
README.md describes the integer constructions.
CDTs use the existing independent, two-precision specification reconstruction.
Only byte-exact outputs belong in outputs(); compiler output is excluded.
"""
import argparse
from fractions import Fraction
import json
from pathlib import Path
import re
import sys

REPO = Path(__file__).resolve().parents[4]
R4 = Path("crates/pretzel-4-4/core/src")
R5 = Path("crates/pretzel-5-5/src")
sys.path.insert(0, str(REPO / "crates/pretzel-4-4/scripts"))
sys.path.insert(0, str(REPO / "crates/pretzel-4-4/kat"))
import spec_sampler

MASK = (1 << 64) - 1


def theta(src):
    text = (REPO / src / "params.rs").read_text()
    body = re.search(r"const THETA_NUM_LIMBS:.*?=\s*\[(.*?)\];", text, re.S)[1]
    words = [int(x.strip(), 0) for x in body.split(",") if x.strip()]
    return Fraction(sum(w << (64 * i) for i, w in enumerate(words)), 1 << (64 * len(words)))


def key_table(src, count):
    # Directed Q1024 recurrence for
    # (2 * 2^18 * j * (-log(theta)))^(2k) / (2k)!, then Q1024 -> Q256.
    h = (1 - theta(src)) / (1 + theta(src))
    lower = 2 * sum((h ** (2 * j + 1) / (2 * j + 1) for j in range(24)), Fraction())
    upper = lower + 2 * h**49 / 49 / (1 - h*h)
    q = 1 << 1024
    lo = (lower * q).numerator // (lower * q).denominator
    hi = -(-(upper * q).numerator // (upper * q).denominator)

    def mul(a, b):
        return a[0] * b[0] // q, (a[1] * b[1] + q - 1) // q

    rows = []
    for j in range(1, count + 1):
        u = (lo * (1 << 19) * j, hi * (1 << 19) * j)
        eta = mul(u, u)
        if src == R5:
            # The Pretzel-(5,5) interval-transport.c specifies L squared = 2^37.
            eta = eta[0]*2, eta[1]*2
        term = (q, q)
        row = []
        for k in range(35):
            if k:
                a, b = mul(term, eta)
                den = 2 * k * (2 * k - 1)
                term = a // den, (b + den - 1) // den
            low = term[0] >> 768
            high = (term[1] + (1 << 768) - 1) >> 768
            assert high - low <= 2
            row.append("{{" + ",".join(f"UINT64_C({(low >> (64*w)) & MASK})" for w in range(5)) + "}}")
        rows.append("{" + ",".join(row) + "}")
    return (f"static const U256 key_d256[{count}][35]={{" + ",".join(rows) + "};\n").encode()


def aux32():
    # Auxiliary 32-bit static tables, integer arithmetic.
    p, root = 516809729, 75035968
    z = [0] + [(pow(root, int(f"{k:08b}"[::-1], 2), p) + p//2) % p - p//2 for k in range(1, 256)]
    mu = lambda x: (x * (1 << 31) + p//2) // p
    iz = [-x for x in z]
    q, iq = list(map(mu, z)), list(map(mu, iz))
    tv = []
    for inverse in (False, True):
        blocks = []
        for sb in range(16):
            slots = [[0]*4 for _ in range(6)]
            for b in range(4):
                ks = [127-4*sb-b, 255-8*sb-2*b, 254-8*sb-2*b] if inverse else [64+4*sb+b, 128+8*sb+2*b, 129+8*sb+2*b]
                for j, k in enumerate(ks):
                    slots[2*j][b] = (iz if inverse else z)[k]
                    slots[2*j+1][b] = (iq if inverse else q)[k]
            blocks.append(slots)
        tv.append(blocks)
    fmt = lambda x: json.dumps(x, separators=(",", ":"))
    return ("// Exact public tables. Independent runtime-constructor equality tested.\n"
            "static STATIC_TABLES:Tables=Tables{zr:" + fmt(z[:64]) + ",zq:" + fmt(q[:64])
            + ",izr:" + fmt(iz[:64]) + ",izq:" + fmt(iq[:64]) + ",fwd:" + fmt(tv[0])
            + ",inv:" + fmt(tv[1]) + "};\n").encode()


def auxiliary():
    # Auxiliary static tables, unpadded layout.
    p, n = 2013265921, 256
    r = (1 << 32) % p
    ri, ni = pow(r, -1, p), pow(n, -1, p)
    psi = pow(31, (p-1)//512, p)
    ip = pow(psi, -1, p)

    def factors(values):
        pairs = []
        for w in values:
            w = w * ri % p
            b = w - p * (w > p//2)
            mu = (b * (1 << 31) + p//2) // p
            pairs.append((b % (1 << 32), mu % (1 << 32)))
        return "Factors{b:[" + ",".join(str(x[0]) for x in pairs) + "],beta:[" + ",".join(str(x[1]) for x in pairs) + "]}"

    stages = []
    for inv in (False, True):
        root = (ip if inv else psi)**2 % p
        v, h = [0]*(n-1), 1
        while h < n:
            for j in range(h):
                v[h-1+j] = pow(root, j*n//(2*h), p) * r % p
            h *= 2
        stages.append(v)
    return ("// Generated exactly from P, root31 and the Montgomery\n"
            "// convention; tests keep the independent runtime constructor.\n"
            "const _:()=assert!(P==2013265921 && N==256);\n#[repr(align(64))]\n"
            "struct AlignedTables(Tables);\nstatic STATIC_TABLES:AlignedTables=AlignedTables(Tables {\n"
            "twist:" + factors([pow(psi, i, p)*r*r % p for i in range(n)]) + ",\nuntwist:"
            + factors([pow(ip, i, p)*ni % p for i in range(n)]) + ",\nstages:["
            + ",".join(factors(v) for v in stages) + "],\n});\n").encode()


def fair_alias(bounds, z):
    # Initial masses of the collapsed alias table, then balancing.
    total = z + 1
    original = [(bounds[0], 0, False, False, False)]
    for j in range(1, (len(bounds)-1)//2 + 1):
        a, b = bounds[2*j-1]-bounds[2*j-2], bounds[2*j]-bounds[2*j-1]
        assert abs(a-b) <= 1
        original.append((a+b, 2*j-1, True, a <= b, True))
    original.append((total-bounds[-1], len(bounds), False, False, True))
    masses = [bounds[0]] + [x[0]-2 for x in original[1:511]] + [total-bounds[1020]+1020]
    extras = []
    for j in range(1, 511):
        if masses[j] & 1:
            extras.append(2*j-1 + original[j][3])
            masses[j] -= 1
    masses[511] += len(extras)
    assert sum(masses) == total
    work = [m*512 for m in masses]
    small = [i for i, w in enumerate(work) if w < total]
    large = [i for i, w in enumerate(work) if w >= total]
    rows = [None]*512
    while small and large:
        lo, hi = small.pop(), large.pop()
        threshold = work[lo]
        work[hi] -= total-threshold
        rows[lo] = threshold, hi
        (small if work[hi] < total else large).append(hi)
    for i in small + large:
        assert work[i] == total
        rows[i] = total, i
    tail = [(i+1, count) for i, count in enumerate(extras)]
    cursor = len(extras)
    for mass, base, pair, flip, tie in original[511:]:
        if mass:
            cursor += mass
            tail.append((cursor, base | (pair << 12) | (flip << 13) | (tie << 14)))
    assert cursor+1020 == masses[511]
    return rows, tail


def planes(rows, columns):
    # Planes: blocks of sixteen, Gray-code block traversal,
    # omit all-zero byte planes. This is data generation, no assembly compiler.
    if len(rows) < 16:
        rows = rows + [bytes(len(rows[0]))]*(16-len(rows))
    assert len(rows) % 16 == 0
    data = bytearray()
    blocks = len(rows)//16
    for group in range((blocks+7)//8):
        for g in range(min(8, blocks-group*8)):
            block = group*8 + (g ^ (g >> 1))
            for column in columns:
                plane = bytes(rows[16*block+i][column] for i in range(16))
                if any(plane):
                    data.extend(plane)
    return bytes(data)


def main_planes(rows):
    # The selected main32 gather scans consecutive 64-row TBX4 blocks.
    out = bytearray()
    for start in range(0, len(rows), 64):
        # The main32 kernel derives endpoint flags from column zero.
        for column in [0, 1, 2, 3, 8, 9]:
            plane = bytes(row[column] for row in rows[start:start+64])
            if any(plane):
                out.extend(plane)
    return bytes(out)


def warm_tree(kind, tail):
    # Warm tree, with split 192-bit endpoints.
    n = 1 << (len(tail)-1).bit_length()
    depth = n.bit_length()-1
    ends = [x[0] for x in tail] + [tail[-1][0]]*(n-len(tail))
    tags = [x[1] for x in tail] + [0]*(n-len(tail))
    out = {}
    for level in range(depth):
        step = n >> (level+1)
        values = [ends[(2*j+1)*step-1] for j in range(1 << level)]
        out[f"warm_tree_{kind}_{level}.bin"] = planes([(x & ((1 << 128)-1)).to_bytes(16, "little") for x in values], range(16))
        if any(x >> 128 for x in values):
            out[f"warm_tree_{kind}_{level}_hi.bin"] = planes([(x >> 128).to_bytes(16, "little") for x in values], range(8))
    out[f"warm_tree_{kind}_tags.bin"] = planes([(tags[2*j] | (tags[2*j+1] << 16)).to_bytes(16, "little") for j in range(n//2)], range(4))
    return out


def sampler_tables():
    out = {}
    for kind, symbol in (("sec", "WS"), ("err", "WE")):
        weight = spec_sampler.integer("params.rs", symbol)
        result = spec_sampler.cdt(weight, 1, 240)
        assert result == spec_sampler.cdt(weight, 1, 320), "CDT precision sensitivity"
        _, words, zw, _ = result
        integer = lambda w: (w[0] << 128) | (w[1] << 64) | w[2]
        bounds, z = list(map(integer, words)), integer(zw)
        previous, encoded = 0, bytearray()
        for bound in bounds:
            delta = bound-previous
            size = (delta.bit_length()+7)//8
            encoded.append(size)
            encoded.extend(delta.to_bytes(size, "little"))
            previous = bound
        out[f"collapsed_bounds_{kind}.bin"] = bytes(encoded)
        alias, tail = fair_alias(bounds, z)
        rows = {name: [] for name in ("main", "mid", "suffix")}
        for threshold, tag in alias:
            p = (threshold << 192)//(z+1)
            flag = (p == 1 << 192) | ((p == 0) << 1)
            v = p & ((1 << 192)-1)
            rows["main"].append((v >> 160).to_bytes(8, "little") + (tag | (flag << 16)).to_bytes(8, "little"))
            rows["mid"].append((v >> 88).to_bytes(13, "little") + (tag | (flag << 9)).to_bytes(2, "little") + b"\0")
            rows["suffix"].append((v & ((1 << 88)-1)).to_bytes(11, "little") + bytes(5))
        for name, columns in (("main", [0, 1, 2, 3, 8, 9, 10]), ("mid", range(15)), ("suffix", range(11))):
            out[f"reservoir_{name}_{kind}.bin"] = main_planes(rows[name]) if name == "main" else planes(rows[name], columns)
        out.update(warm_tree(kind, tail))
    return out


def outputs():
    out = {R4 / name: data for name, data in sampler_tables().items()}
    out[R4 / "aux32_static_tables.rs"] = aux32()
    out[R4 / "auxiliary_static_tables.rs"] = auxiliary()
    for src, count in ((R4, 38), (R5, 36)):
        out[src / "interval-key256-table.h"] = key_table(src, count)
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    data = outputs()
    if args.check:
        failures = [str(path) for path, content in data.items() if (REPO/path).read_bytes() != content]
        if failures:
            raise SystemExit("Generated table drift:\n" + "\n".join(failures))
        print(f"Generated public tables: {len(data)} files match byte-for-byte")
    else:
        dest = args.output_dir.resolve()
        if dest == REPO or REPO in dest.parents:
            parser.error("output directory must be outside the source worktree")
        for path, content in data.items():
            target = dest/path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)


if __name__ == "__main__":
    main()
