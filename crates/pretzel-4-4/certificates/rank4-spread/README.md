# Rank-four spread and row quality

From the repository root, run

```sh
python3 -B crates/pretzel-4-4/certificates/rank4-spread/certify_r4_spread.py --self-test
python3 -B crates/pretzel-4-4/certificates/rank4-spread/certify_r4_spread.py --check
```

Without `--check`, the second command regenerates `certificate_r4_spread.json`.
Both are pure Python (standard library only) and run in the
`reference-certificates` job of the workflow.

These programs carry out the numerical steps of the paper's lemma "Rank-four
spread and row quality" (Lemma D.3). The statement: the finite rank-four
reference row fails with probability less than $0.293$, so it passes with
probability above $0.707$, for every fixed dither and parity and for every
core satisfying the explicit condition $G$ below. In the independent uniform
expanded-matrix model, $\Pr[\neg G]<1.423\cdot10^{-37}$. The proof permits the
honest correlation between the public matrix and public vector. It does not
establish this exceptional probability for a fixed concrete SHAKE function.

The reported row-failure upper bound is $0.292944128348880$. The exact computed sum is below $0.292944128348877$. The checker rejects any total above the reported bound and any total at least $293/1000$. Checking $G$ cheaply remains open: the supplied exact reference check needs up to $16{,}110{,}321{,}664$ projection evaluations, and no core of a generated key was checked. No per-key check of $G$ runs in CI.

The programs read the tables, weights and caps of the crate.
`--check` compares the complete recomputed JSON, including source
hashes, with the committed output. The hashes cover exactly the parsed files:
`params.rs`, `params_tables.rs`, `rice_codec.rs` and `dither_frame.rs` of
`crates/pretzel-4-4/core/src`, and `reference_tables.rs` in this directory.
The programs in this directory and
`crates/pretzel-5-5/certificates/rank5-dither/certify.py`, whose interval
arithmetic and domination check they import, are also hashed. An edit to any
of these inputs requires regeneration and review; an edit to a source file
that is not parsed does not invalidate this certificate.

The finite CDF arrays in `reference_tables.rs` are proof inputs of
this certificate; key generation does not use them. The signer uses a different
finite implementation of its Gaussian and transport laws. Pointwise domination
is checked here; relating those laws to the paper's ideal experiment remains a
proof premise. The Rust test `row_certificate_signer_and_verifier_predicates`
compares the reference conjunction to the actual signer cap/capacity calls and
the verifier's decoded head and fused residual path on crafted boundary rows.
It exhausts scalar quantizer/recovery pairs. It does not prove the full native
program equivalent for all inputs, the sampler law, or the matrix-spread premise.

The availability statement concerns an **honestly expanded matrix** in the
**ideal uniform-matrix model**, and is **pointwise in the dither**. Key
generation draws no rows and never tests $G$; this certificate gives no
coupling bound between key generation and a rule that would test rows. The
lemma is used only for availability, specifically the bound on exhausting $512$
signing attempts; no security reduction uses it. Its exceptional-matrix
probability enters availability only.

## Exact experiment and quantifiers

Let $q=7681$, $n=256$, and $R_q=\mathbb F_q[X]/(X^{256}+1)$. Fix a public core $K$ with coefficient matrix $A_0\in R_q^{4\times4}$ and public vector $b\in R_q^4$. Its relation is $A_h=[-b\mid A_0]$, as implemented by `MatrixAh::apply_public` in `scheme.rs`. For output coefficient $(r,i)$ and SECRET input coefficient $(c,k)$, its multiplier is

$$a_{(r,i),(c,k)}=(-1)^{[k>i]}(A_0)_{r,c,(i-k)\bmod256}\pmod q.$$

The paper (Appendix D) specifies $x=A_hz_h+\delta$, the finite row law, and the ideal uniform-matrix model. It samples the matrix in spectral coordinates; its bijective inverse NTT gives exactly the coefficient-space uniform law used here. The scalar coefficient sampler also gives that uniform law in the corresponding independent-stream model. The theorem is about the mathematical coefficient matrix, independent of which equivalent representation holds it.

For **every** $K$ satisfying $G(K)$, **every** $\delta\in\mathbb F_q^{1024}$ and **every** prescribed $\beta\in\{0,1\}^{256}$, draw $2304$ independent uniform $32$-bit words. Decode the first $256$ by EVEN or ODD according to $\beta$, the next $1024$ by SECRET, and the final $1024$ by ERROR. Each CDF endpoint is exclusive. A suffix outside the last endpoint is a missing sample and fails; it is never redrawn. These are the exact finite source tables, not rounded Gaussian approximations.

Write the head as $h=(h_0,h_1,h_2,h_3,h_4)$ and define

$$x_r=-b_rh_0+\sum_{c=1}^4(A_0)_{r,c-1}h_c+\delta_r\pmod{X^{256}+1,q}.$$

For each coefficient let $u_i=\lfloor34((x_i+e_i)\bmod q)/q\rfloor$ and $r_i=\operatorname{center}_q(C(u_i)-x_i)$, using the exact alternating-center quantizer in the source. Let $F$ be the conjunction of:

* all samples exist;
* leading head magnitude at most $288$, other head magnitude at most $255$, residual magnitude at most $450$, and recovery of every label;
* head squared norm at most $1593^2=2537649$;
* residual squared norm at most $3068^2=9412624$;
* integer score $\sum W_{\rm HEAD}(|h_i|)+\sum W_{\rm RES}(|r_i|)\le30850912$;
* head Rice quotient sum at most $1088$, with shifts $3$ and $6$, and at most $50$ residual labels of local index at least $2$.

These are the limits of the 1361-byte signature format. The reference predicate's early head-score rejection is already included because all remaining score terms are nonnegative. The theorem is

$$\sup_{\delta,\beta}\Pr[\neg F\mid K,\delta,\beta]\le\epsilon=0.292944128348880<0.293\quad\text{for every }K\text{ with }G(K).$$

The probability is over fresh independent row words. Neither a deterministic claim about every SHAKE tape nor a statement about adaptively exposed row words would count. No randomness in the dither, independence of challenge bits, or independent residual coordinates is assumed.

## The explicit public-core condition

For distinct output coordinates $i,j$, form the $1024$ coefficient points

$$P_k=(a_{i,k},a_{j,k})\in\mathbb F_q^2.$$

For $v\in\mathbb F_q$, put $|v|_q=\min(v\bmod q,(-v)\bmod q)$. Define $G(K)$ to mean that for every such pair, every nonzero $(t,s)\in\mathbb F_q^2$, and every $u\in\{0,\ldots,3840\}$,

$$\#\{k:|t a_{i,k}+s a_{j,k}|_q=u\}\le48.$$

Geometrically, no pair of opposite parallel affine lines contains more than $48$ of the coefficient points, with multiplicity. At $u=0$ this is one line. The condition depends only on $A_0$, hence only on $K$, and is independent of $b$, the dither, parity, secret-key shell and row tapes. It neither implies nor is implied by invertibility. The theorem does not require invertibility.

It suffices to check projective directions $(1,s)$ and $(0,1)$. Rescaling a direction permutes the absolute bins. Simultaneously shifting two output coordinates negacyclically permutes input coordinates and changes individual point signs; it may also change a whole output-row sign. Absolute projection occupancy is invariant under all these operations and under exchanging the two rows. Thus a complete set of pair representatives is:

* same output polynomial: $(r,0),(r,d)$, with $r\in\{0,1,2,3\}$ and $1\le d\le128$, giving $512$ representatives;
* different output polynomials: $(r,0),(s,d)$, with $r<s$ and $0\le d<256$, giving $1536$ representatives.

There are $2048$ representatives in total. These symmetries are proved by the displayed negacyclic coefficient formula and checked exhaustively on small cores. Merely counting points on individual signed lines would not have this sign-invariance; the absolute-bin condition is deliberate.

## Spread lemma, including deletion of one head coordinate

Condition on successful samples. This retains independence of all coordinates, with each CDF law normalized by its own retained word count. Denote the normalized SECRET law by $\mu$. It is exactly symmetric, as verified from the tables. Its characteristic function is

$$\phi(t)=\sum_z\mu(z)\exp(2\pi i tz/q)=\sum_z\mu(z)\cos(2\pi tz/q).$$

The checker encloses all $3841$ absolute-frequency magnitudes of each of the four normalized CDF laws. For a nonzero multiplier $a$, multiplication by $a$ permutes nonzero frequencies, so $\max_{t\ne0}|\widehat\mu(ta)|$ is independent of $a$. For $a=0$ it is $1$. Outward bounds on the nonzero maxima are:

| CDF | Maximum upper bound | Frequency attaining the largest upper endpoint |
|---|---:|---:|
| EVEN | $0.999996211694193$ | $3840$ |
| ODD | $0.999996211694183$ | $3840$ |
| SECRET | $0.999287742209885$ | $1$ |
| ERROR | $0.998846514956495$ | $1$ |

Using just the SECRET maximum to the power $1024$ is too weak. The new ingredient is the occupation restriction on *all* frequencies simultaneously.

Let $B_1\ge B_2\ge\cdots$ be the sorted outward upper enclosures of $|\phi(v)|$ for absolute frequencies $v\in\{0,\ldots,3840\}$. With $G$, each frequency can occur at most $48$ times in a Fourier product for an output pair. After fixing any one SECRET coordinate, at least $1023$ independent SECRET coordinates remain, and the same occupation limit holds. Rearrangement therefore gives

$$\prod_{k\ne k_0}|\phi(t a_{i,k}+s a_{j,k})|
\le\left(\prod_{v=1}^{21}B_v^{48}\right)B_{22}^{15}
\le\eta=\frac{3087}{2^{160}}<2.113\cdot10^{-45}.$$

Without a deletion there are $1024$ factors; dropping any one factor, which is at most $1$, gives the same upper bound. Conditioning on the entire leading block makes $-bh_0+\delta$ an arbitrary fixed shift and introduces no other dependence. Fixing a SECRET coordinate contributes another fixed shift. Every nontrivial Fourier coefficient of either conditional output-pair law is therefore at most $\eta$ in magnitude.

Fourier inversion gives, for each point of $\mathbb F_q^2$, deviation from uniform at most $(q^2-1)\eta/q^2$. Summing the absolute deviations and dividing by two proves

$$d_{\rm TV}((x_i,x_j),U_q^{\otimes2})\le\tau=\frac{q^2-1}{2}\eta<6.231\cdot10^{-38}.$$

Marginalization gives the same bound for one coordinate. Mixing over the conditioned leading head preserves the bound. It also holds conditional on any single head coordinate: for a leading coordinate use mixtures of fixed leading blocks; for a SECRET coordinate use the deletion argument. Both endpoint dithers, and arbitrary mixtures of them, only change Fourier phases.

This proves the required weak dependence. It does not claim that the entire $1024$-coordinate context vector is near uniform.

## From spread to six failure contributions

For moment calculations only, set each capped statistic to zero when its coordinate exceeds the relevant cap. On the cap-pass event these statistics equal the row-predicate statistics. Missing words and cap failures are charged separately, without conditioning on passing caps. For a uniform independent context and a normalized ERROR draw, enumerate all $7681$ contexts and all quantizer labels with their exact error-word counts. Every residual within magnitude $450$ has a recoverable label; this finite geometry assertion is checked for all contexts and all labels, including zero-mass labels.

For a residual statistic $Y\in[0,B]$, let $\mu_Y$ and $v_Y$ be its mean and variance in that uniform-context reference law. Adding independent errors and applying a deterministic statistic cannot increase total variation. Hence actual marginal means differ by at most $B\tau$, marginal second moments by at most $B^2\tau$, and pair product moments by at most $B^2\tau$. It follows that

$$\mathbb E\sum_iY_i\le1024(\mu_Y+B\tau),\qquad
\operatorname{Var}\sum_iY_i\le1024v_Y+3\cdot1024^2B^2\tau.$$

For completeness, the variance correction comes from at most $3B^2\tau$ per marginal variance and per covariance: the raw second/product moment changes by at most $B^2\tau$, and the product of two marginal means by at most $2B^2\tau$.

Let $H_k$ be a capped head score, with $0\le H_k\le H_{\max}$. The deletion lemma gives $|\mathbb E[Y_i\mid h_k]-\mu_Y|\le B\tau$. Therefore

$$|\operatorname{Cov}(H_k,Y_i)|\le2H_{\max}B\tau.$$

The $1280$ head scores are independent, conditional on nonmissing draws and fixed parity. Add their variance and the cross-covariance correction $4\cdot1280\cdot1024H_{\max}B\tau$ to the residual score variance. This explicitly accounts for shared head coordinates; simply adding independent head and residual variances would be unjustified. Each leading mean and variance is bounded by the larger of its two parity-specific values, so mixed parity patterns are covered.

Apply one-sided Chebyshev (Cantelli) with the integer failure threshold $T+1$:

$$\Pr[Z\ge T+1]\le\frac{V}{V+(T+1-M)^2},\qquad \mathbb EZ\le M<T+1,\quad\operatorname{Var}Z\le V.$$

One direct proof is to apply Markov to $(Z-\mathbb EZ+c)^2$ on $Z-\mathbb EZ\ge a$, obtaining $(V+c^2)/(a+c)^2$, and choose $c=V/a$. Replacing the true mean and variance by the stated upper bounds only weakens the result.

| Quantity | Reference mean per residual coordinate | Reference variance per residual coordinate |
|---|---:|---:|
| Capped squared residual | $7702.772151458$ | $96959469.493003$ |
| Capped integer score | $15630.647328635$ | $400810006.629693$ |
| Capped local-index exception indicator | $0.005411715561920$ | $0.005382428896597$ |

These displayed values are upper-rounded summaries; the exact moment pairs in the JSON are used in every subtraction. The resulting score-sum mean upper bound is below $29331180.304$, and its variance upper bound is below $754072431650$. An estimate based on cell width alone excludes the independent error. The exact quantization error has second moment $32668639/7681=4253.175237599\ldots$; adding the ERROR contribution and applying the cap yields the reference residual moment above. The margin against the residual norm cap is positive but smaller than the cell-only heuristic suggests.

The head norm and head Rice encoding use independent-coordinate Chernoff bounds, keeping their original subprobability masses and intersecting head cap acceptance. For a rational base $b>1$, divide the product of capped moments by $b^{T+1}$. The selected bases are $10000320/10000000$ for the squared head norm and $11500/10000$ for the quotient sum. These bases are fixed rationals in the program; the bounds use outward $512$-bit arithmetic.

| Failure contribution | Computed upper enclosure |
|---|---:|
| Missing samples | $0.000153541564942$ |
| Coordinate caps and unrecoverable labels | $0.000026702880860$ |
| Head squared norm | $0.002986304974391$ |
| Residual squared norm | $0.040945084249347$ |
| Combined integer score | $0.246134510974904$ |
| Both encoding capacities | $0.002697983704435$ |
| Reported total bound | $0.292944128348880$ |

The six individually rounded contributions sum to $0.292944128348879$, below the reported total bound.

The missing-sample contribution is exactly $161/1048576$. The cap contribution is exactly $(102400+12288)/2^{32}=7/262144$: no leading tail words, $100$ SECRET tail words per coordinate, and at most $12$ residual-cap tail words per context and coordinate. Recovery adds zero on the residual-cap event. The encoding contribution combines a head quotient bound below $0.000037913424639$ with the residual exception-count Cantelli bound. There is no binomial assumption for the dependent exception indicators.

The finite subprobability atoms are also checked, using the exact source $\theta$, to be dominated pointwise by the full parity-conditioned/weight-specific discrete Gaussian atoms. The checker recomputes this with $512$-bit outward normalizers and geometric tails. Multiplication and the fixed successful-output predicate preserve domination. Thus the corresponding ideal product experiment also has success probability above $0.707055871651120>0.707$, under the same $K,\delta,\beta$ condition. This comparison uses the original unnormalized finite success mass, not its conditional-on-nonmissing normalization used in the Fourier calculation.

## Probability of the public-core condition

**Model:** the $4096$ coefficients of $A_0$ are independent and uniform in $\mathbb F_q$. The vector $b$ may be arbitrary or computed honestly as $A_0s_0+e$. The key-shell acceptance event depends on secret/error draws independent of the matrix, so it does not bias $A_0$. This is exactly the paper's ideal independent-matrix-stream model, not a uniformity assertion about a fixed seed-expanded SHAKE matrix.

For one cross-row representative and fixed projective direction, its $1024$ projections are independent uniform field elements: each uses a different coefficient from each of two independent matrix rows. Each absolute bin has probability at most $2/q$. A union over subsets of $49$ coordinates bounds the probability of a bin exceeding $48$ by $\binom{1024}{49}(2/q)^{49}$.

For a same-row representative with displacement $d$, the $256$ coefficient pairs in each input polynomial are the signed edges $k\leftrightarrow k+d$ on a cycle decomposition. Every cycle has even length $256/\gcd(256,d)$. At $d=128$, view the two directed edges as two parallel edges. Split alternate edges into two matchings. Across the four input polynomials each matching contains $512$ projections built from disjoint uniform coefficients. Each matching's projections are independent uniform for every nonzero direction; signs do not change this. The two matchings need not be independent. If an absolute bin contains at least $49$ points in their union, one matching contains at least $25$. Thus the probability is at most $2\binom{512}{25}(2/q)^{25}$.

Union over $(q+1)$ projective directions and $(q+1)/2$ bins, and over all pair representatives, gives

$$\Pr[\neg G]\le\frac{(q+1)^2}{2}\left(1024\binom{512}{25}(2/q)^{25}+1536\binom{1024}{49}(2/q)^{49}\right)
<1.423\cdot10^{-37}.$$

This is an exact rational computation. Independence between representatives, directions, bins or the two matchings is never asserted. The exceptional probability already covers all dithers and all parities simultaneously because $G$ does not depend on either. No additional union over dithers is needed.

## Arithmetic and adversarial audit

The trigonometric computation uses Machin's identity $\pi=16\arctan(1/5)-4\arctan(1/239)$ with alternating rational series enclosures. The identity follows from the tangent addition formula: $\tan(4\arctan(1/5))=120/119$ and subtracting $\arctan(1/239)$ gives tangent $1$ in the first quadrant. Cosine arguments are reduced to $[0,\pi]$ and evaluated through degree $94$ with signed outward $160$-bit operations; $(22/7)^{96}/96!<2^{-160}$ bounds the remainder. Symmetry eliminates imaginary parts exactly. Sorting upper endpoints and rounding the final Fourier product upward cannot understate it. The source-table symmetry itself is asserted.

The self-test checks exact toy pair distributions under all shifts, including conditioning on a head coordinate; checks the Fourier total-variation inequality and moment bounds; exhausts small cores to compare all output pairs with the representative reduction; checks a larger power-of-two half-period case; and independently checks uniform-context residual moments by error/quantization-error convolution. The exact rational, toy convolution and direct residual checks are also rerun. These checks support the proof but are not substitutes for the general lemmas above.

For a zero expanded core with $b=0$, $\delta=0$ gives $|r_i|\ge112$ for every successful draw, and so does the constant endpoint dither $\delta=q-1$. In both cases $1024\cdot112^2>3068^2$, giving failure probability $1$. These cores violate $G$. No concrete SHAKE seed realizing this matrix is asserted.

An identity $A_0$ is invertible, but after fixing the leading block each context coordinate remains a shifted SECRET sample with at most $545$ support points. Its marginal distance from uniform is at least $1-545/7681$. It also violates $G$. Sparse, repeated or proportional rows are not silently admitted by an invertibility test: exact linear dependence makes a zero projection bin of size $1024$, and sparse rows leave an oversized zero bin. Some structured dense matrices may pass; the proof then applies without needing a generic-randomness heuristic.
