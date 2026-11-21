# Paper

[pretzel.pdf](pretzel.pdf) is the paper that specifies the scheme implemented in
this repository:

**Pretzel: Compact Lattice Signatures from Module-LWE and Module-SIS**,
by Alberto Centelles Hidalgo, Justin Thaler and Markos Georghiades (108 pages).

The paper is licensed under the
[Creative Commons Attribution 4.0 International License](https://creativecommons.org/licenses/by/4.0/);
its text is in [LICENSE-CC-BY-4.0](LICENSE-CC-BY-4.0). The PDF itself carries
no licence statement; this file and the repository README are where the
licence is stated.
The code in this repository is licensed separately; see the
[repository README](../README.md#license).

SHA-256 of the file:
`b181671020d60fb891f52c6e90fd424b87f77a828e936a3418e707d3025a98d1`.

## How the code refers to it

- Section 4, "Pretzel Construction", defines key generation, signing,
  verification and the canonical signature encoding (Section 4.5).
- Appendix D, "Byte Formats, Sampling, and Encoding Certificates", is the
  byte-level specification: exact parameters (D.1), key generation and dither
  expansion (D.2), signing and verification (D.4), encoding (D.5). Comments
  and file names in the sources that say "Appendix D" refer to it, and
  `crates/pretzel-4-4/kat/pretzel-kat.txt` is its known-answer file for
  Pretzel-(4,4).
- Appendix H gives the parameters of Pretzel-(3,3), and Appendix I those of
  Pretzel-(5,5).

The signature and public-key sizes in the paper's tables (1160 and 1326 bytes
for Pretzel-(3,3), 1361 and 1742 for Pretzel-(4,4), 1908 and 2158 for
Pretzel-(5,5)) are the constants `SIGNATURE_BYTES` and `PUBLIC_KEY_BYTES` of
the three crates.

The timing figures are in Section 7 and in Appendices H.1 and I.4.
[bench/mldsa-comparison](../bench/mldsa-comparison) measures the same
operation rows against ML-DSA, on a hosted runner when its workflow is
started by hand.
