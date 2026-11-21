# Known-answer files and test list of Pretzel-(3,3)

The files in this directory are inputs of
`scripts/run_native_checks.py`. `known_answer.rs` and `key_bytes.rs` are the two
executables built with the `conformance` feature; they print fixed public test
seeds and their outputs, never keys that may be used.

## `known-answer.txt`

The output of the `rank3_golden` executable (`known_answer.rs`; the replay itself is
`known_answer_replay.rs`): 169093 bytes, a header line, four public keys and 64
signatures of 1160 bytes, with attempt counts and entropy continuation. Its
SHA-256 is `6f6ed860caf01c76fd7bbe7d4362016ee67a04bf233f7663d7def2a30ac613a0`.
`run_native_checks.py golden` runs the executable in two processes and
requires both outputs to equal the file byte for byte. The executable also
checks prepared and scalar verification, malformed inputs and the erasure of
the signing scratch. The replay is a finite check and contains no secret key.

The test entropy is `Xof::new` with the domain
`PRETZEL33-SPEED-PUBLIC-AUDIT-v1`, an 8-byte little-endian length prefix and
the little-endian seed.

## `keygen-digests.json`

For the seeds 0 to 15 of the `rank3_key_bytes` executable (`key_bytes.rs`):
the SHA-256 of the 1326-byte public key and of the 526-byte secret key, and
the entropy record (the lengths of the entropy requests of key generation and
the next 64 bytes of the test tape). `run_native_checks.py keys` runs the
executable in two processes, requires identical outputs, and compares every
digest and entropy record with this file. The executable also checks that a
prepared secret key recovers the same public key.

The test entropy is raw SHAKE256 over the domain
`PRETZEL33-IMPORT-PUBLIC-KEY-BYTES-v1` followed by the seed, so its keys differ
from those of `known-answer.txt` although the seed labels 0 to 3 occur in both.

## `unit-tests.json`

The library tests by full name. `required` maps each test to the status it
must report (`ok` or `ignored`); `excluded` would list tests that are skipped,
each with its reason, and is empty. `run_native_checks.py tests` fails when
the test executable contains a test that is in neither list, when a listed
test is missing, and when a result differs. Expected: 282 passed, 0 ignored,
0 excluded.
