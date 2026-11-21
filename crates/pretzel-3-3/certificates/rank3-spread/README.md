# Rank-three spread and row quality

From the repository root, run

```sh
python3 -I -B crates/pretzel-3-3/certificates/rank3-spread/certify_r3.py --self-test
python3 -I -B crates/pretzel-3-3/certificates/rank3-spread/certify_r3.py --check
```

Without `--check`, the second command regenerates `certificate_r3.json`.
Both are pure Python (3.11 or newer, standard library only), and both run in
the `certificate` job of the workflow. `-I` is optional: the program loads
`binding.py` from its own directory by path and imports nothing else outside
the standard library.

The checker computes the two figures of Lemma H.1 of the paper
(`paper/pretzel.pdf`, "Rank-three spread and row quality"): a row failure
bound below $0.016575$ on the occupation condition $G_{54}$ (the condition
$G_3$ of the lemma), and an exceptional-matrix bound below
$2.701\cdot10^{-48}$. The cap $54$ is the constant of the lemma; the program
states it and does not search for it. These are exact rational or
outward-rounded computed upper bounds, not measurements. Chernoff bases are
fixed rationals so replay does not depend on floating-point optimizer
choices. The JSON rationals are authoritative.

Let $A_0$ be an honestly expanded matrix with independent uniform coefficients
in $R_q^{3\times3}$, where $R_q=\mathbb F_{7681}[X]/(X^{256}+1)$.
For every distinct pair of output coefficients and every nonzero frequency
direction, $G_c$ requires that no absolute bin of the projected matrix columns
has occupation exceeding $c$. This condition concerns $A_0$ alone; $b$ may
depend on it arbitrarily. It neither requires nor implies invertibility.
On $G_{54}$ the row bound is pointwise in every fixed dither and every leading
parity vector. The dither is fixed before the sample words are drawn. A row
is one reference sample of the lemma: 1792 independent uniform 32-bit words,
256 for the leading coefficients, 768 for the other head coefficients and 768
for the errors. Key generation draws no such sample and does not test
$G_{54}$.

The Fourier calculation bounds products of 767 secret characteristic
functions under the occupation cap, including deletion of any one shared head
coordinate. Fourier inversion gives one- and two-coordinate total variation
bounds. These control residual moments and head/residual covariances. Cantelli,
head Chernoff, exact binomial encoding tails, missing mass and coordinate caps
give the six recorded terms. The exceptional bound uses two independent
matchings within each same-polynomial displacement and independent columns
for cross-polynomial pairs, followed by a union bound. It does not assume
independence of all residual coordinates.

The exceptional-matrix bound is for one matrix. For several fresh matrices,
apply the union bound over their number.

`reference_tables.json` contains the four finite CDFs of the reference sample
(`EVEN` and `ODD` for the leading coefficients, `SECRET` for the other head
coefficients, `ERROR` for the errors). It is certificate input data, not a
compiled Rust module or a sampler of the signer. The CDF atoms are checked
against the full ideal Gaussian law with downward rounding.

Under `candidate_expansion` the certificate also records two bounds for the
dither expansion of key generation with independent uniform words: one
candidate, which reads at most `EXPANSION_CANDIDATES` words and needs
`DITHER_COEFFICIENTS` values below $q$, fails to expand; and all
`MAX_CANDIDATES` candidates fail. Both are recorded as at most $2^{-512}$,
the resolution of the arithmetic.

Score tables, norm and score caps and expansion limits come from the crate
sources. `binding.py` reads the caps of signer admission (`capacity_mask` and
the four-lane scan it calls), the sparse decoders, scalar recovery, and the
residual cap at every caller of the eight-lane recovery (the
`public_row_caps.rs` row, its test reference and the reference in `neon.rs`),
requiring equality, one definition of each function, and no further caller.
The code that the certificate reads has one build configuration: `binding.py`
lists the code that is fixed, and checks that the manifest declares exactly
the two features `conformance` and `stack-wipe`, both empty and off by
default, and that no file read by the certificate is gated by either. The
fixed configuration recorded in `certificate_r3.json` names both features and
counts their gates in the other source files. The Rust predicate
test additionally exercises actual signer admission, actual verifier decoding
and fused row checks against an independent scalar predicate. It reads all
34 model centres from `certificate_r3.json` and compares each with
`quantize::center`, tying the Python geometry to the native quantizer.

`parsed_inputs_sha256` hashes canonical JSON representations of the parsed
parameters and cap bindings, the fixed configuration, score tables, reference
CDFs and the challenge parameters. The checker programs have separate
whole-file hashes.
`acceptance_source_sha256` additionally pins `dither_setup.rs`,
`dither_frame.rs`, `public_common_prefix.rs` and
`keygen_dither_check.rs`.
Other source files use parsed value identities;
unrelated edits in those files do not stale this certificate. Changes to parsed proof inputs do, even if a
numerical bound would stay the same. All production cap occurrences are still
parsed and cross-checked on every run. This is a value binding, not a proof of
arbitrary Rust control flow; the native predicate and fixture tests cover
implementation behavior.

The certificate has these qualifications: ideal XOF behavior, NTT,
NEON, SHAKE and compiler correctness are imported premises. The occupation
condition is not checked per key. This is not a concrete-SHAKE frequency or an
adversarial-seed guarantee. The all-expanded-matrix statement is false: a zero
core at an endpoint dither fails the residual norm cap for every row. No seed
expanding to that core is asserted. `cap_frontier` in the JSON lists both
bounds at every cap whose row bound stays below $2/5$; the last one is 58.
Only its entry at cap 54 is the statement above. The fourth-moment
comparison in the JSON is diagnostic and is not used by this theorem.

`--check` reads the current inputs, recomputes the bounds and compares the
result with `certificate_r3.json` byte for byte. `--self-test` checks exact
small cases, the CDF lookups and the complete residual enumeration.

`--check-core FILE` tests $G_{54}$ exactly for one matrix, given as a JSON
array of $3\times3$ polynomials with 256 coefficients in $[0,q)$ each, and
prints one JSON line. It stops at the first bin above the cap. A full pass
makes `G_check_projection_updates` bin updates (about $6.8\cdot10^{9}$), more
than pure Python performs within the 240-second guard of the program, and a
run stopped by the guard prints no result. No key or matrix of the crate has
been tested this way (`any_production_core_checked` is false).

The crate's tests check that signer and verifier predicates agree, the quantizer centres,
candidate selection and entropy failures, and the known-answer files. These
tests complement the conditional statement; they do not prove equality for
arbitrary seeds.
