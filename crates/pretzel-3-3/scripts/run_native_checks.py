#!/usr/bin/env python3
"""Library tests against the test list, and byte-exact known-answer replays.

Native execution is CI-only; `self-test` is pure Python.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'conformance'
COUNTED = ROOT.parent / 'pretzel-4-4/scripts/run_counted_tests.py'
GOLD_SHA = '6f6ed860caf01c76fd7bbe7d4362016ee67a04bf233f7663d7def2a30ac613a0'
GOLD_LEN = 169093
GOLD_HEADER = b'PRETZEL33 known-answer transcript v1\n'


EXPECTED_COUNTS = (282, 0, 0)  # passing, ignored, excluded


def policy():
    """Return (excluded names, {required name: status}) from conformance/unit-tests.json."""
    listed = json.loads((FIXTURES / 'unit-tests.json').read_text())
    required = listed['required']
    excluded = [row['name'] for row in listed['excluded']]
    assert all(row['reason'] for row in listed['excluded'])
    assert len(excluded) == len(set(excluded)) and not set(excluded) & required.keys()
    assert set(required.values()) <= {'ok', 'ignored'}
    assert (list(required.values()).count('ok'),
            list(required.values()).count('ignored'), len(excluded)) == EXPECTED_COUNTS
    return excluded, required


def validate_inventory(text):
    excluded, required = policy()
    actual = [line.removesuffix(': test') for line in text.splitlines()
              if line.endswith(': test')]
    expected = set(excluded) | required.keys()
    if len(actual) != len(set(actual)) or set(actual) != expected:
        raise ValueError(f'test inventory drift: missing={sorted(expected - set(actual))}, '
                         f'added={sorted(set(actual) - expected)}')


def validate_results(text):
    excluded, required = policy()
    records = re.findall(r'^test (\S+)(?: - should panic)? \.\.\. (ok|ignored|FAILED)\b', text, re.M)
    actual = dict(records)
    if len(records) != len(actual) or actual != required:
        raise ValueError('test results differ from the required test list')
    count = sum(status == 'ok' for status in required.values())
    summary = f'test result: ok. {count} passed; 0 failed; 0 ignored; 0 measured; {len(excluded)} filtered out;'
    if summary not in text:
        raise ValueError('missing exact nonzero test summary')


def require_ci():
    if (os.environ.get('GITHUB_ACTIONS') != 'true' or platform.system() != 'Darwin'
            or platform.machine() != 'arm64'):
        raise SystemExit('native checks require GitHub Actions on Apple silicon macOS')


def cargo(operation, *tail):
    return ['cargo', '+1.90.0', operation, '--locked', '--offline', '--release',
            '--manifest-path', str(ROOT / 'Cargo.toml'), *tail]


def tests(features):
    extra = ['--features', features] if features else []
    build = subprocess.run(cargo('test', '--lib', '--no-run', '--message-format=json', *extra),
                           check=True, stdout=subprocess.PIPE, text=True)
    images = [row['executable'] for line in build.stdout.splitlines()
              if (row := json.loads(line)).get('reason') == 'compiler-artifact'
              and row.get('executable') and row.get('profile', {}).get('test')]
    if len(images) != 1:
        raise ValueError('expected one library test executable')
    image = images[0]
    inventory = subprocess.check_output([image, '--list'], text=True)
    validate_inventory(inventory)
    excluded, _ = policy()
    command = [sys.executable, str(COUNTED), image, '--test-threads=1']
    command += [arg for name in excluded for arg in ('--skip', name)]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True)
    print(result.stdout, end='')
    result.check_returncode()
    validate_results(result.stdout)


def checked_golden(data):
    if (len(data) != GOLD_LEN or not data.startswith(GOLD_HEADER)
            or hashlib.sha256(data).hexdigest() != GOLD_SHA):
        raise ValueError('known-answer file length, header or SHA-256 mismatch')


def validate_keys(data):
    lines = data.decode('ascii').splitlines()
    if not lines or lines[0] != 'PRETZEL33-IMPORT-PUBLIC-KEY-BYTES-v1 seeds=0..16':
        raise ValueError('wrong key transcript header')
    if len(lines) != 49:
        raise ValueError('expected 16 public/secret/entropy records')
    for seed in range(16):
        for offset, kind, size in [(0, 'pk', 1326), (1, 'sk', 526)]:
            if not re.fullmatch(fr'{kind} {seed} [0-9a-f]{{{size * 2}}}',
                                lines[1 + 3 * seed + offset]):
                raise ValueError('malformed serialized key record')
        if not re.fullmatch(fr'entropy {seed} \[\d+(?:, \d+)*\] [0-9a-f]{{128}}',
                            lines[3 + 3 * seed]):
            raise ValueError('malformed entropy record')


KEY_TAPE_DOMAIN = b'PRETZEL33-IMPORT-PUBLIC-KEY-BYTES-v1'


def validate_key_digests(data):
    validate_keys(data)
    lines = data.decode('ascii').splitlines()
    expected = json.loads((FIXTURES / 'keygen-digests.json').read_text())['records']
    assert len(expected) == 16 and [r['seed'] for r in expected] == list(range(16))
    for seed, record in enumerate(expected):
        for offset, kind in ((0, 'pk'), (1, 'sk')):
            digest = hashlib.sha256(bytes.fromhex(lines[1 + 3*seed + offset].split()[2])).hexdigest()
            print(f'fixed-seed {seed} {kind}_sha256={digest}')
            if digest != record[kind + '_sha256']:
                raise ValueError(f'fixed-seed {seed} {kind} differs from keygen-digests.json')
        if lines[3 + 3*seed] != record['entropy']:
            raise ValueError(f'fixed-seed {seed} entropy consumption differs')


def validate_replays(kind, runs):
    if len(runs) != 2 or runs[0] != runs[1]:
        raise ValueError('two independent process transcripts must be identical')
    if kind == 'golden':
        expected = (FIXTURES / 'known-answer.txt').read_bytes()
        checked_golden(expected)
        checked_golden(runs[0])
        if runs[0] != expected:
            raise ValueError('replay differs from conformance/known-answer.txt')
    elif kind == 'keys':
        # known-answer.txt uses another entropy domain and framing, so none of its
        # keys belongs to this 16-seed tape. Check repeatability, the recorded
        # key digests, and the entropy request lengths and continuation.
        validate_keys(runs[0])
        validate_key_digests(runs[0])
    else:
        raise ValueError('unknown replay kind')


def replay(kind, output, features):
    output.mkdir(parents=True, exist_ok=True)
    binary = 'rank3_golden' if kind == 'golden' else 'rank3_key_bytes'
    selected = 'conformance,' + features if features else 'conformance'
    subprocess.run(cargo('build', '--features', selected, '--bin', binary), check=True)
    # The workspace target directory at the repository root, or an explicit CI override.
    image = Path(os.environ.get('CARGO_TARGET_DIR', ROOT.parent.parent / 'target')) / 'release' / binary
    runs = []
    for name in ('first', 'second'):
        result = subprocess.run([str(image)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (output / f'{kind}-{name}.txt').write_bytes(result.stdout)
        (output / f'{kind}-{name}.stderr').write_bytes(result.stderr)
        result.check_returncode()
        if result.stderr:
            raise ValueError('unexpected replay stderr')
        runs.append(result.stdout)
    validate_replays(kind, runs)
    claim = ('two replays byte-identical to conformance/known-answer.txt' if kind == 'golden'
             else '16-seed public and secret key SHA-256 and entropy records match keygen-digests.json')
    print(f'PASS: {kind}, {claim}, {len(runs[0])} bytes, '
          f'sha256={hashlib.sha256(runs[0]).hexdigest()}')


class PortableTests(unittest.TestCase):
    def listing(self):
        excluded, required = policy()
        inventory = '\n'.join(name + ': test' for name in [*excluded, *required])
        result = '\n'.join(f'test {name} ... {status}' for name, status in required.items())
        result += (f"\ntest result: ok. {list(required.values()).count('ok')} passed; 0 failed; "
                   f"0 ignored; 0 measured; {len(excluded)} filtered out;")
        return excluded, required, inventory, result

    def test_exact_inventory_and_missing_test_rejection(self):
        _, _, inventory, _ = self.listing()
        validate_inventory(inventory)
        with self.assertRaises(ValueError):
            validate_inventory(inventory.split('\n', 1)[1])
        with self.assertRaises(ValueError):
            validate_inventory(inventory + '\nunexpected::test: test')

    def test_results_and_zero_or_changed_status_rejection(self):
        _, required, _, result = self.listing()
        count = sum(value == 'ok' for value in required.values())
        validate_results(result)
        for bad in ('', result.replace(' ... ok', ' ... ignored', 1),
                    result.replace(f'{count} passed', '0 passed'),
                    result + '\ntest unexpected::test ... ok'):
            with self.assertRaises(ValueError):
                validate_results(bad)

    def test_each_required_test_must_be_listed_and_pass_once(self):
        _, required, inventory, result = self.listing()
        for name, status in required.items():
            if status != 'ok':
                continue
            for bad in (inventory.replace(name + ': test', '', 1),
                        inventory + '\n' + name + ': test'):
                with self.assertRaises(ValueError):
                    validate_inventory(bad)
            line = f'test {name} ... ok\n'
            for bad in (result.replace(line, '', 1), result.replace(line, line.replace('ok', 'ignored'), 1),
                        result.replace(line, line.replace('ok', 'FAILED'), 1), result + '\n' + line):
                with self.assertRaises(ValueError):
                    validate_results(bad)

    def test_golden_authentication_rejects_mutation(self):
        data = (FIXTURES / 'known-answer.txt').read_bytes()
        checked_golden(data)
        with self.assertRaises(ValueError):
            checked_golden(bytes([data[0] ^ 1]) + data[1:])

    def test_key_record_shape_rejects_truncation(self):
        text = 'PRETZEL33-IMPORT-PUBLIC-KEY-BYTES-v1 seeds=0..16\n'
        for seed in range(16):
            text += f'pk {seed} ' + '00' * 1326 + '\n'
            text += f'sk {seed} ' + '00' * 526 + '\n'
            text += f'entropy {seed} [32] ' + '00' * 64 + '\n'
        validate_keys(text.encode())
        with self.assertRaises(ValueError):
            validate_keys(text.rsplit('\n', 2)[0].encode())

    def test_key_self_consistency_rejects_different_bytes(self):
        text = 'PRETZEL33-IMPORT-PUBLIC-KEY-BYTES-v1 seeds=0..16\n'
        for seed in range(16):
            text += f'pk {seed} ' + '00' * 1326 + '\n'
            text += f'sk {seed} ' + '00' * 526 + '\n'
            text += f'entropy {seed} [32, 32, 32] ' + '00' * 64 + '\n'
        data = text.encode()
        # All-zero keys do not have the recorded digests.
        with self.assertRaises(ValueError):
            validate_replays('keys', [data, data])
        # With the digest comparison replaced by the shape check, two equal runs
        # pass, so below only the difference between the two runs can raise.
        with mock.patch.dict(globals(), {'validate_key_digests': validate_keys}):
            validate_replays('keys', [data, data])
            for old, new in ((b'pk 0 0', b'pk 0 1'), (b'sk 0 0', b'sk 0 1'),
                             (b'[32, 32, 32]', b'[32, 32, 32, 32]'),
                             (b'] 0', b'] 1')):
                changed = data.replace(old, new, 1)
                self.assertNotEqual(changed, data)
                validate_keys(changed)
                validate_replays('keys', [changed, changed])
                with self.assertRaises(ValueError):
                    validate_replays('keys', [data, changed])
            with self.assertRaises(ValueError):
                validate_replays('keys', [data])

    def test_entropy_records_lie_on_the_public_tape(self):
        records = json.loads((FIXTURES / 'keygen-digests.json').read_text())['records']
        self.assertEqual(len(records), 16)
        for seed, record in enumerate(records):
            head, sizes, continuation = re.fullmatch(
                r'(entropy \d+) \[([\d, ]+)\] ([0-9a-f]{128})', record['entropy']).groups()
            self.assertEqual(head, f'entropy {seed}')
            sizes = [int(size) for size in sizes.split(', ')]
            # Every request is 32 bytes and the last one is the candidate dither seed.
            self.assertGreaterEqual(len(sizes), 4)
            self.assertEqual(set(sizes), {32})
            tape = hashlib.shake_256(KEY_TAPE_DOMAIN + seed.to_bytes(8, 'little')).digest(sum(sizes) + 64)
            self.assertEqual(continuation, tape[sum(sizes):].hex())

    def test_golden_replays_must_equal_the_file_even_when_repeatable(self):
        data = (FIXTURES / 'known-answer.txt').read_bytes()
        validate_replays('golden', [data, data])
        changed = bytes([data[0] ^ 1]) + data[1:]
        with self.assertRaises(ValueError):
            validate_replays('golden', [changed, changed])

    def test_golden_keys_use_distinct_entropy_tapes(self):
        data = (FIXTURES / 'known-answer.txt').read_bytes()
        checked_golden(data)
        keys = re.findall(rb'^pk ([0-3]) ([0-9a-f]+)$', data, re.M)
        self.assertEqual([int(seed) for seed, _ in keys], list(range(4)))
        candidate_prefixes = {
            hashlib.shake_256(b'PRETZEL33-IMPORT-PUBLIC-KEY-BYTES-v1'
                             + seed.to_bytes(8, 'little')).digest(32)
            for seed in range(16)
        }
        for seed, key in keys:
            # tag_public prepends the profile; seed_a is the first body field.
            public = bytes.fromhex(key.decode('ascii'))
            profile = b'PZWB3-R3-N0001'
            self.assertEqual(public[:len(profile)], profile)
            prefix = public[len(profile):len(profile) + 32]
            expected = hashlib.shake_256(
                b'PRETZEL33-SPEED-PUBLIC-AUDIT-v1' + (8).to_bytes(8, 'little')
                + int(seed).to_bytes(8, 'little')).digest(32)
            self.assertEqual(prefix, expected)
            self.assertNotIn(prefix, candidate_prefixes)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['tests', 'golden', 'keys', 'self-test'])
    parser.add_argument('--output', type=Path)
    parser.add_argument('--features', default='',
                        help='further Cargo features of the crate, for example stack-wipe')
    args = parser.parse_args()
    if args.mode == 'self-test':
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(PortableTests)
        if not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful():
            raise SystemExit(1)
        return
    require_ci()
    if args.mode == 'tests':
        tests(args.features)
    else:
        if args.output is None:
            parser.error('replay requires --output')
        replay(args.mode, args.output, args.features)


if __name__ == '__main__':
    main()
