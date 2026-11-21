#!/usr/bin/env python3
"""Replay the Pretzel-(4,4) known-answer vectors on Apple silicon macOS.

The library is built with the `conformance` feature and linked into three
fixture executables together with the public test entropy tape of
tests/native/entropy.c. Public fixtures only; never application keys.

Checked, in this order:
  1. the entropy contract executable runs to completion;
  2. the conformance executable writes 4 keys and 32 signing cases (140 files)
     whose SHA-256 inventory equals tests/native/fixture-inventory.json,
     and its summary line equals the one recorded there;
  3. the known-answer executable, run twice, writes kat/pretzel-kat.txt byte for byte.

With --stack-wipe the library is also built with the feature `stack-wipe`; the
recorded bytes are the same, because the stack-range wipes change no output.

Usage: python3 crates/pretzel-4-4/scripts/run_kat_replay.py --output FRESH_DIRECTORY [--stack-wipe]
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys

from native_host import ROOT, TOOLS, host_cpu_features, host_errors, reject_feature_shim

TESTS = ROOT / "tests/native"
INVENTORY = TESTS / "fixture-inventory.json"
KAT = ROOT / "kat/pretzel-kat.txt"
KEYS, CASES = 4, 8


class ReplayError(Exception):
    pass


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fixture_names():
    # 4 keys * (3 key files + 8 cases * 4 case files) = 140 files.
    names = {f"key-{key}.{ext}" for key in range(KEYS)
             for ext in ("pk", "fixture-sk", "tape")}
    names |= {f"key-{key}-case-{case}.{ext}" for key in range(KEYS) for case in range(CASES)
              for ext in ("sig", "msg", "ctx", "tape")}
    return names


def recorded_inventory():
    if not INVENTORY.is_file():
        raise ReplayError(f"missing known-answer inventory: {INVENTORY}")
    recorded = json.loads(INVENTORY.read_text())
    for field in ("schema", "file_count", "byte_exact_files", "conformance"):
        if field not in recorded:
            raise ReplayError(f"{INVENTORY.name}: missing field {field!r}")
    if (recorded["schema"] != 1 or recorded["file_count"] != 140
            or set(recorded["byte_exact_files"]) != fixture_names()):
        raise ReplayError(f"{INVENTORY.name} differs from the 4-key, 8-case fixture layout")
    return recorded


def first_difference(left, right):
    for index, (a, b) in enumerate(zip(left, right)):
        if a != b:
            return index
    return min(len(left), len(right))


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--output", required=True, type=Path,
                        help="fresh directory for build products and replay outputs")
    parser.add_argument("--stack-wipe", action="store_true",
                        help="also build the library with the feature stack-wipe")
    args = parser.parse_args()

    system, machine = platform.system(), platform.machine()
    if system != "Darwin" or machine != "arm64" or sys.byteorder != "little":
        parser.error(f"this replay requires Apple silicon macOS; found {system} {machine}")
    reject_feature_shim(os.environ)
    evidence, features = host_cpu_features()
    errors = host_errors(system, machine, sys.byteorder, features)
    errors += ["missing executable on PATH: " + tool for tool in TOOLS if shutil.which(tool) is None]
    for key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_TARGET"):
        if os.environ.get(key):
            errors.append("unset " + key + ": the library is built with its default flags")
    for path in (KAT, TESTS / "entropy.c", TESTS / "entropy_contract.rs", TESTS / "conformance.rs",
                 ROOT / "examples/spec_kat.rs"):
        if not path.is_file():
            errors.append(f"missing input: {path}")
    if errors:
        parser.error("; ".join(errors))
    recorded = recorded_inventory()

    out = args.output.resolve()
    if out.exists() and any(out.iterdir()):
        parser.error(f"--output must be a fresh or empty directory: {out}")
    out.mkdir(parents=True, exist_ok=True)
    (out / "host.txt").write_text(str(platform.uname()) + "\n" + evidence)
    env = dict(os.environ, CARGO_TARGET_DIR=str(out / "fixture-target"))

    def run(argv, **kwargs):
        argv = list(map(str, argv))
        print("+ " + " ".join(argv), flush=True)
        try:
            result = subprocess.run(argv, cwd=ROOT, env=env, **kwargs)
        except OSError as error:
            raise ReplayError(f"cannot start {argv[0]}: {error}") from error
        if result.returncode:
            raise ReplayError(f"command failed with exit code {result.returncode}: {' '.join(argv)}")

    features = "conformance,stack-wipe" if args.stack_wipe else "conformance"
    run(["cargo", "build", "--locked", "--release", "--lib", "--features", features])
    release = out / "fixture-target/release"
    library = release / "libpretzel_4_4.rlib"
    if not library.is_file():
        raise ReplayError(f"cargo build did not produce {library}")

    compiler = [os.environ["CC"]] if os.environ.get("CC") else ["xcrun", "--sdk", "macosx", "clang"]
    entropy = out / "entropy.c.o"
    run([*compiler, "-O2", "-Wall", "-Wextra", "-Werror", "-DPRETZEL_LOGICAL_ENTROPY",
         "-c", TESTS / "entropy.c", "-o", entropy])

    def harness(source, name):
        binary = out / name
        run(["rustc", "--edition=2021", "-C", "opt-level=3", "-C", "lto=fat",
             source, "--extern", "pretzel_4_4=" + str(library),
             "-L", "dependency=" + str(release / "deps"), "-o", binary,
             "-C", "link-arg=" + str(entropy)])
        return binary

    # 1. Entropy contract.
    contract = harness(TESTS / "entropy_contract.rs", "entropy-contract")
    with (out / "entropy-contract.txt").open("w") as log:
        run([contract], stdout=log)

    # 2. Keys, signatures and entropy tape records against the recorded inventory.
    conformance = harness(TESTS / "conformance.rs", "conformance")
    with (out / "conformance.jsonl").open("w") as log:
        run([conformance, out / "rank4"], stdout=log)
    lines = (out / "conformance.jsonl").read_text().splitlines()
    try:
        records = [json.loads(line) for line in lines]
    except json.JSONDecodeError as error:
        raise ReplayError(f"conformance output is not JSON lines: {error}") from error
    if len(records) != KEYS * CASES + 1:
        raise ReplayError(f"expected {KEYS * CASES + 1} conformance records, found {len(records)}")
    cases = {(row.get("key"), row.get("case")) for row in records[:-1]}
    if cases != {(key, case) for key in range(KEYS) for case in range(CASES)}:
        raise ReplayError("conformance records do not cover every key and case exactly once")
    if records[-1] != recorded["conformance"]:
        raise ReplayError(f"conformance summary {records[-1]} differs from the recorded "
                          f"{recorded['conformance']}")
    produced = sorted((out / "rank4").iterdir())
    if any(not path.is_file() or path.is_symlink() for path in produced):
        raise ReplayError("the fixture directory must contain only regular files")
    inventory = {path.name: digest(path) for path in produced}
    if set(inventory) != fixture_names():
        raise ReplayError("fixture file names differ: missing "
                          f"{sorted(fixture_names() - set(inventory))}, "
                          f"unexpected {sorted(set(inventory) - fixture_names())}")
    (out / "rank4-inventory.json").write_text(json.dumps(inventory, indent=2) + "\n")
    differing = sorted(name for name in inventory
                       if inventory[name] != recorded["byte_exact_files"][name])
    if differing:
        raise ReplayError(f"{len(differing)} fixture files differ from {INVENTORY.name}: "
                          + ", ".join(differing[:10]) + (" ..." if len(differing) > 10 else ""))

    # 3. Known-answer file, twice.
    expected = KAT.read_bytes()
    kat = harness(ROOT / "examples/spec_kat.rs", "spec-kat")
    for name in ("kat-first.txt", "kat-second.txt"):
        run([kat, out / name])
        if not (out / name).is_file():
            raise ReplayError(f"the known-answer executable did not write {out / name}")
        actual = (out / name).read_bytes()
        if actual != expected:
            raise ReplayError(f"{name} differs from kat/pretzel-kat.txt: {len(actual)} bytes against "
                              f"{len(expected)}, first difference at byte "
                              f"{first_difference(actual, expected)}")
    print(f"Replay passed: 140 fixture files, {KEYS * CASES} signing cases, entropy contract, "
          f"known-answer file twice ({len(expected)} bytes, sha256={hashlib.sha256(expected).hexdigest()})")


if __name__ == "__main__":
    try:
        main()
    except ReplayError as error:
        raise SystemExit("KAT replay failed: " + str(error))
