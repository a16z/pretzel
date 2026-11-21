#!/usr/bin/env python3
"""Recompute the largest values that the 192-bit sampler tables can produce.

Run: python3 crates/pretzel-4-4/core/generators/check_sampler_bounds.py --check

`core/src/aux32_initial.rs` states a bound on the weighted product of a mask
with a key that rests on four figures: a mask coefficient of an output is at
most 739 (secret block) or 937 (error block) in magnitude, and a value held
in an aborted attempt is at most 744 or 946. `core/src/params.rs` adds 108
for the leading block. This program derives the figures from the tables and
compares them with the two source files.

What is computed. The Gaussian boundaries are reconstructed from `params.rs`
and `fixed.rs` at 240 and 320 decimal digits (`scripts/spec_sampler.py`); the
two results must agree. For each table the 192-bit prefixes b[0] <= b[1] <=
... of the cumulative bounds are taken, as `Cdt::new` does. The rule applied
is that of the reference classifier (`Cdt::ct_classify`): a 192-bit draw u
selects the count i of prefixes b[j] <= u, a count i below the table length
decodes to the i-th value (0, 1, -1, 2, -2, ...) and any other count to 0,
and a draw equal to a prefix or not below the normalizer aborts the attempt.

- A value is produced by an attempt that does not abort only if some draw
  lies strictly between b[i-1] and b[i], that is b[i] - b[i-1] >= 2.
- A draw equal to a prefix b[j] selects the count of prefixes <= b[j].

The program also recomputes the two products of the comment: the largest
value of 196 * a * n_s + 121 * b * n_e over 0 <= n_s, n_e <= 1024 with
196 * n_s + 121 * n_e <= SHELL_HI - W0, for (a, b) = (744, 946) and for the
table maxima (1064, 1355).

What is not computed. That the alias, tree and queue routines of the signer
select the same count as the reference classifier for every draw is the
subject of the Rust tests, not of this program. The reconstruction is decimal
arithmetic at two precisions, not an interval certificate.
"""
import argparse
import bisect
from pathlib import Path
import re
import sys

REPO = Path(__file__).resolve().parents[4]
SRC = REPO / "crates/pretzel-4-4/core/src"
sys.path.insert(0, str(REPO / "crates/pretzel-4-4/scripts"))
sys.path.insert(0, str(REPO / "crates/pretzel-4-4/kat"))
import spec_sampler

EXPECTED = {
    "lead": {"maximum": 154, "output": 108, "held": 108},
    "sec": {"maximum": 1064, "output": 739, "held": 744},
    "err": {"maximum": 1355, "output": 937, "held": 946},
}
EXPECTED_PRODUCT = 189281598
EXPECTED_TABLE_PRODUCT = 270955245


def table(symbol, step):
    weight = spec_sampler.integer("params.rs", symbol)
    result = spec_sampler.cdt(weight, step, 240)
    assert result == spec_sampler.cdt(weight, step, 320), "CDT precision sensitivity"
    values, words, zw, _ = result
    integer = lambda w: (w[0] << 128) | (w[1] << 64) | w[2]
    bounds, z = [integer(w) for w in words], integer(zw)
    assert all(a <= b for a, b in zip(bounds, bounds[1:])) and bounds[-1] <= z
    return weight, values, bounds


def figures(values, bounds):
    count = len(values)
    inside = [i for i in range(count) if bounds[i] - (bounds[i - 1] if i else 0) >= 2]
    on_boundary = {bisect.bisect_right(bounds, b) for b in bounds}
    on_boundary = {i for i in on_boundary if i < count}
    output = max(abs(values[i]) for i in inside)
    held = max(abs(values[i]) for i in on_boundary | set(inside))
    return {"maximum": max(values), "output": output, "held": held}


def product(ws, we, a, b, budget):
    best = 0
    for ns in range(1025):
        rest = budget - ws * ns
        if rest < 0:
            break
        ne = min(1024, rest // we)
        best = max(best, ws * a * ns + we * b * ne)
    return best


def compute():
    out = {}
    weights = {}
    for name, symbol, step in (("lead", "PROPOSAL_W0", 2), ("sec", "WS", 1), ("err", "WE", 1)):
        weight, values, bounds = table(symbol, step)
        weights[name] = weight
        out[name] = figures(values, bounds)
    budget = spec_sampler.integer("params.rs", "SHELL_HI") - spec_sampler.integer("params.rs", "W0")
    out["product"] = product(weights["sec"], weights["err"], out["sec"]["held"], out["err"]["held"], budget)
    out["table_product"] = product(
        weights["sec"], weights["err"], out["sec"]["maximum"], out["err"]["maximum"], budget
    )
    return out


def check_sources(found):
    aux = (SRC / "aux32_initial.rs").read_text()
    needles = [
        f"const HELD_SEC: i64 = {found['sec']['held']};",
        f"const HELD_ERR: i64 = {found['err']['held']};",
        f"assert!(best == {found['product']});",
        f"at most {found['sec']['output']}",
        f"(secret) and {found['err']['output']} (error) in an output",
        f"the worst case over all keys in the shell is {found['table_product']}",
    ]
    for needle in needles:
        if aux.count(needle) != 1:
            raise SystemExit(f"aux32_initial.rs does not state: {needle}")
    params = (SRC / "params.rs").read_text()
    sentence = (
        f"at most {found['lead']['output']} (leading), {found['sec']['output']} (secret) "
        f"and {found['err']['output']}"
    )
    if len(re.findall(re.escape(sentence).replace(r"\ ", r"[\s/]+"), params)) != 1:
        raise SystemExit(f"params.rs does not state: {sentence}")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="compare with the figures in the sources")
    args = parser.parse_args()
    found = compute()
    for name in ("lead", "sec", "err"):
        print(name, " ".join(f"{k}={v}" for k, v in found[name].items()))
    print("product", found["product"])
    print("table_product", found["table_product"])
    if args.check:
        for name, expected in EXPECTED.items():
            if found[name] != expected:
                raise SystemExit(f"{name}: computed {found[name]}, expected {expected}")
        if found["product"] != EXPECTED_PRODUCT or found["table_product"] != EXPECTED_TABLE_PRODUCT:
            raise SystemExit("product mismatch")
        check_sources(found)
        print("PASS")


if __name__ == "__main__":
    main()
