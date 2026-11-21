# Pretzel-(5,5) reference row and dither expansion

From the repository root, run

```sh
python3 -B crates/pretzel-5-5/certificates/rank5-dither/certify.py --check
```

Without `--check`, the command regenerates `certificate_r5.json`. The program
is pure Python (standard library only) and runs in the
`reference-certificates` job of the workflow.

The program carries out the numerical steps that the paper states for the
reference row of Pretzel-(5,5) (Appendix I.1, "Bounded dither selection and
its scope"). The reference row uses $2816$ independent uniform 32-bit words:
$256$ for the leading coefficients, $1280$ for the other head coefficients and
$1280$ for the errors, decoded through the tables EVEN or ODD, SECRET and
ERROR of `reference_tables.rs`. A word beyond the last endpoint of its table
is a missing sample and fails; it is never redrawn. For every fixed core,
dither and prescribed parity, the program bounds the probability of the union
of six events:

| Failure contribution | Computed upper bound |
|---|---:|
| Missing samples | $0.000221431255340577$ |
| Coefficient caps | $0.000067651271820069$ |
| Capped head norm | $3.393103608912\cdot10^{-9}$ |
| Capped residual norm | $1.546708057555\cdot10^{-14}$ |
| Capped secant score | $0.010293822690649243$ |
| Limits of the 1908-byte encoding | $0.000085589061162208$ |

Their sum is below $0.0106684976720912<11/1000$. The program rejects a total
of $11/1000$ or more, and a total of $0.0106685$ or more. The JSON intervals
are authoritative; the table repeats the figures of the paper.

The head norm, residual norm and secant score use Chernoff bounds with fixed
rational bases and outward-rounded 512-bit dyadic intervals. Every residual
moment is maximized over all $7681$ contexts; the paper gives the conditioning
argument that justifies multiplying these maxima. The encoding term is an
exact rational computation: the tail of the sum of two binomial counts of head
coefficients outside the low range of their fields (at most $40$ exceptions in
all), plus a binomial tail for the labels with local index at least $4$ (at
most $16$ exceptions), with the probability of such a label maximized over
contexts. Missing samples and coefficient caps are exact counts of 32-bit
words.

The program also checks that every table count is at most $2^{32}$ times a
lower bound of the ideal Gaussian mass of its value, under the base $\theta$
and the weights read from `params.rs`. The finite row therefore succeeds with
probability at most that of the ideal product law. The stronger statement that
each count equals the floor is checked by
`crates/pretzel-4-4/certificates/check_reference_tables.py`.

For the dither, the program computes
$d=\Pr[\mathrm{Bin}(1664,511/8192)\ge385]$, the probability that the bounded
expansion of one candidate fails to obtain $1280$ values from $1664$ words,
and requires $d<2^{-366}$. The value is below $4.93260021844487\cdot10^{-111}$.

## What the program reads

Caps, counts and limits come from the crate sources: `params.rs`,
`params_tables.rs` (the score tables), `signature_codec.rs` (the scalar admission
predicate, which is compiled for tests only and serves as the reference, and
the limits of the encoding), `admission_neon.rs` (the two
NEON admission functions, whose literals must equal the scalar ones) and
`dither_frame.rs` (the expansion limits). The program also requires that
`prepared_signer.rs` calls both admission predicates and that `verifier.rs`
contains the three cap comparisons and the statistics they use. These are
checks of literals and call sites in the text of the sources, not a proof of
arbitrary Rust control flow.

`input_sha256` records whole-file hashes of those files, of
`reference_tables.rs`, and of the other files that implement the predicates
or are compiled only to test them
(`quantize.rs`, `scheme.rs`, `keygen_dither_check.rs`, `dither_setup.rs`,
`public_common_prefix.rs`, `ct_lookup.rs`, `ct_caps_piecewise.rs`,
`cap_piecewise_tables.rs`, `public_recovery_table.rs`,
`dither_certificate_tests.rs`, `signed_head_caps.rs`, `neon.rs`, `api.rs`).
`--check` compares the complete recomputed JSON with `certificate_r5.json`, so
an edit to any of these files, comments included, requires regenerating the
certificate in the same change and reviewing the difference.

The Rust tests in `dither_certificate_tests.rs` compare the quantizer centres,
the recovery lists and the cap predicates of signer and verifier with a scalar
specification on finite cases. They complement this certificate; they do not
prove the sampler law.

## Qualifications

The bounds concern the reference row, a mathematical experiment on public
data. They are not a bound for private transport or for a complete signing
call, and they say nothing about a concrete SHAKE function: ideal XOF
behaviour is an imported premise, as are the correctness of the NEON code, of
SHAKE and of the compiler. The signer uses a different finite implementation
of its Gaussian laws; relating it to the ideal experiment is done in the
paper, not here.

`crates/pretzel-4-4/certificates/rank4-spread` imports the interval arithmetic
and the domination check of `certify.py` and records its hash, so a change to
`certify.py` also requires regenerating the rank-four certificate.
