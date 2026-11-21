# Known-answer executables of Pretzel-(4,4)

`scripts/run_kat_replay.py` builds the library with the `conformance` feature
and links it with the files of this directory. See the crate README for the
command.

- `entropy.c`: a public test entropy tape (SplitMix64), linked only into the three replay
  executables. Never link it into an application.
- `entropy_contract.rs`: checks the behaviour of the entropy hook itself.
- `conformance.rs`: generates four keys from the tape and signs eight cases
  with each (empty and non-empty messages and contexts). It writes 140 files:
  for each key the public key, the secret key and its entropy record; for each
  case the signature, message, context and entropy record. It also fails
  entropy requests and corrupts signatures, and prints a summary record.
- `fixture-inventory.json`: the SHA-256 of each of the 140 files and the
  summary record. The replay requires every hash and the summary to match.

The secret keys written by `conformance.rs` are public fixtures derived from a
public tape, not keys that may be used.

These are finite checks. They do not show that the whole signer runs in
constant time or that copies made by the compiler are erased.
