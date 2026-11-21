//! Key generation, signing, and verification.

use crate::challenge;
use crate::encode;
// `Ctx` holds three of these tables.
#[allow(unused_imports)]
use crate::gauss::Cdt;
use crate::hashes::{self, Xof};
use crate::params::*;
use crate::params_tables::{W_HEAD, W_RES};
use crate::quantize;
use crate::ring::{self, Poly};
use crate::theta::ThetaCtx;
use crate::transport::{self, Vector, ERR, SEC};
use crate::{EntropySource, OsEntropy, SecretKey, SigningScratch};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Error {
    KeyFormat,
    SignFailed,
    SignatureLength,
    Decode,
    CapExceeded,
    FiberMismatch,
    ChallengeMismatch,
    RngFailure,
    KeygenFailed,
    DitherSetupFailed,
    TimingProtectionUnavailable,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            // Keygen and signing refuse to run without data-independent timing.
            Error::TimingProtectionUnavailable => f.write_str(
                "TimingProtectionUnavailable: constant-time CPU mode (FEAT_DIT) is unavailable; \
                 keygen and signing require Apple silicon on macOS 15.2 or later",
            ),
            _ => write!(f, "{self:?}"),
        }
    }
}
impl std::error::Error for Error {}

/// Shared precomputed context (heavy init; build once, reuse).
pub struct Ctx {
    pub(crate) theta: ThetaCtx,
    cdt_lead: Cdt,
    cdt_sec: Cdt,
    cdt_err: Cdt,
}

impl Ctx {
    /// Deterministic public table artifact for independent checking and pinning.
    #[doc(hidden)]
    pub fn write_parameter_snapshot(&self, out: &mut impl std::io::Write) -> std::io::Result<()> {
        writeln!(
            out,
            "LILT-PARAMETERS-v1\t{}",
            String::from_utf8_lossy(PROFILE_ID)
        )?;
        self.cdt_lead.write_snapshot("lead", out)?;
        self.cdt_sec.write_snapshot("secret", out)?;
        self.cdt_err.write_snapshot("error", out)?;
        for (i, w) in W_HEAD.iter().enumerate() {
            writeln!(out, "W\thead\t{i}\t{w}")?;
        }
        for (i, w) in W_RES.iter().enumerate() {
            writeln!(out, "W\tresidual\t{i}\t{w}")?;
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub fn new() -> Ctx {
        let theta = ThetaCtx::new();
        let cdt_lead = Cdt::new(&theta, PROPOSAL_W0, true);
        let cdt_sec = Cdt::new(&theta, WS, false);
        let cdt_err = Cdt::new(&theta, WE, false);
        Ctx {
            theta,
            cdt_lead,
            cdt_sec,
            cdt_err,
        }
    }
}

impl Default for Ctx {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod matrix_tests {
    use super::*;

    #[test]
    fn fused_matrix_matches_schoolbook_with_signed_inputs() {
        let mut state = 37u64;
        let mut next = || {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            ((state >> 32) % Q as u64) as i32
        };
        for case in 0..8 {
            let a0 = core::array::from_fn(|_| {
                core::array::from_fn(|_| Poly(core::array::from_fn(|_| next())))
            });
            let b = core::array::from_fn(|_| Poly(core::array::from_fn(|_| next())));
            let delta = core::array::from_fn(|_| Poly(core::array::from_fn(|_| next())));
            let z = core::array::from_fn(|i| match case {
                0 => 0,
                1 => i32::MAX,
                2 => i32::MIN,
                3 => {
                    if i % 2 == 0 {
                        Q - 1
                    } else {
                        1 - Q
                    }
                }
                _ => next() - Q / 2,
            });
            let matrix = MatrixAh::new(&a0, &b);
            let expected = core::array::from_fn(|r| {
                let mut sum = delta[r];
                for c in 0..=ELL {
                    let mut input = Poly::ZERO;
                    input.0.copy_from_slice(&z[c * N..(c + 1) * N]);
                    input.reduce();
                    let coefficient = if c == 0 {
                        Poly::ZERO.sub(&b[r])
                    } else {
                        a0[r][c - 1]
                    };
                    sum = sum.add(&ring::schoolbook(&coefficient, &input));
                }
                sum
            });
            assert_eq!(matrix.apply(&z, &delta), expected);
        }
    }
}

pub struct Keypair {
    pub pk: Vec<u8>,
    pub sk: SecretKey,
}
fn random64(rng: &mut impl EntropySource) -> Result<Zeroizing<[u8; 64]>, Error> {
    let mut out = Zeroizing::new([0u8; 64]);
    rng.fill(&mut out[..]).map_err(|_| Error::RngFailure)?;
    Ok(out)
}
fn random32(rng: &mut impl EntropySource) -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut b = Zeroizing::new([0u8; 32]);
    rng.fill(&mut b[..]).map_err(|_| Error::RngFailure)?;
    Ok(b)
}
pub fn keygen(ctx: &Ctx) -> Result<Keypair, Error> {
    keygen_with_entropy(ctx, &mut OsEntropy)
}

/// Custom entropy integration. The source MUST satisfy `EntropySource`'s contract.
pub fn keygen_with_entropy(_ctx: &Ctx, rng: &mut impl EntropySource) -> Result<Keypair, Error> {
    // First local: all entropy, private work, secret owners and, with the feature
    // `stack-wipe`, the stack scrub complete before restoring the caller's timing
    // state.
    #[cfg(target_os = "macos")]
    let _timing_state = crate::timing_state::Guard::enter()?;
    #[cfg(all(test, target_os = "macos"))]
    let mut traced_rng = crate::timing_state::test_support::KeygenEntropy(rng);
    #[cfg(all(test, target_os = "macos"))]
    let rng = &mut traced_rng;
    #[cfg(feature = "stack-wipe")]
    let _stack_scrub = crate::ct_erase::StackScrub::<{ crate::ct_erase::KEYGEN_SCRUB_WORDS }>;
    keygen_with_entropy_unscrubbed(_ctx, rng)
}

// The key-generation body. With the feature `stack-wipe` it is out of line, so
// that its frame lies below the frame that holds the scrub. Without the feature
// it is always inlined into its only caller, so the default build has one
// function.
#[cfg_attr(feature = "stack-wipe", inline(never))]
#[cfg_attr(not(feature = "stack-wipe"), inline(always))]
#[allow(unreachable_code)]
// Explicit returns keep mutually exclusive selector branches structurally aligned.
#[allow(clippy::needless_return)]
// Keep the independent public reference copy path explicit.
#[allow(clippy::map_clone)]
fn keygen_with_entropy_unscrubbed(
    _ctx: &Ctx,
    rng: &mut impl EntropySource,
) -> Result<Keypair, Error> {
    let seed_a = random32(rng)?;
    #[cfg(all(test, target_os = "macos"))]
    let seed_a = crate::timing_state::test_support::Traced::new(seed_a, "keygen-seed_a-drop");
    let prf = random32(rng)?;
    #[cfg(all(test, target_os = "macos"))]
    let prf = crate::timing_state::test_support::Traced::new(prf, "keygen-prf-drop");
    let a0_ntt = crate::direct_ntt_profile::PublicMatrixNtt::expand(&seed_a);
    // Operational shell-rejection cap, not a certified failure probability.
    for _ in 0..MAX_ATTEMPTS {
        let key_seed = random64(rng)?;
        #[cfg(all(test, target_os = "macos"))]
        crate::timing_state::test_support::checkpoint("keygen-private");
        let mut x = Xof::new(DOM_KEY, &[PROFILE_ID, &key_seed[..]]);
        let s0 = Zeroizing::new(core::array::from_fn::<_, ELL, _>(|_| x.poly_cbd1()));
        #[cfg(all(test, target_os = "macos"))]
        let s0 = crate::timing_state::test_support::Traced::new(s0, "keygen-s0-drop");
        let e = Zeroizing::new(core::array::from_fn::<_, M, _>(|_| x.poly_cbd1()));
        #[cfg(all(test, target_os = "macos"))]
        let e = crate::timing_state::test_support::Traced::new(e, "keygen-e-drop");
        // key shell on E(s): fixed-length accumulation over all (ELL + M) * N trits.
        let mut weighted_sq_norm = W0;
        for p in s0.iter() {
            for &c in &p.0 {
                weighted_sq_norm += WS * (c * c) as u64;
            }
        }
        for p in e.iter() {
            for &c in &p.0 {
                weighted_sq_norm += WE * (c * c) as u64;
            }
        }
        // The same predicate as one mask. The branch below is on the
        // discarded-key event only: a rejected (s0, e) is erased and never
        // reused, each candidate is drawn from fresh entropy, so the number
        // of rejections is a function of discarded independent draws and is
        // independent of the accepted key (same argument as the sampler's
        // public-threshold redraws). No other value of the candidate is
        // branched on before this point.
        {
            use crate::ct::ct_lt_u64;
            let reject =
                ct_lt_u64(weighted_sq_norm, SHELL_LO) | ct_lt_u64(SHELL_HI, weighted_sq_norm);
            if crate::ct::opaque_mask(reject) != 0 {
                continue;
            }
        }
        // b = A0 s0 + e
        let mut s0_ntt = Zeroizing::new(*s0);
        for p in s0_ntt.iter_mut() {
            p.reduce();
            ring::ntt(p);
        }
        let b: [Poly; M] = core::array::from_fn(|r| {
            #[cfg_attr(test, allow(unused_mut))]
            let mut acc = Zeroizing::new(Poly::ZERO);
            #[cfg(all(test, target_os = "macos"))]
            let mut acc = crate::timing_state::test_support::Traced::new(acc, "keygen-acc-drop");
            for c in 0..ELL {
                let a = a0_ntt.spectral_poly(r, c);
                let product = Zeroizing::new(ring::pointwise(&a, &s0_ntt[c]));
                *acc = acc.add(&product);
            }
            ring::intt(&mut acc);
            acc.add(&e[r])
        });
        // The public key stores b in the NTT domain; sampling and the coefficient-domain b above
        // do not depend on that.
        let spectral_b = crate::direct_ntt_profile::SpectralPublicB::from_coefficients(&b);
        let b = spectral_b.spectra();
        // encode
        let mut digits = Vec::with_capacity(M * N);
        for p in b.iter() {
            for &c in &p.0 {
                digits.push(c.rem_euclid(Q));
            }
        }
        let mut pk = Vec::with_capacity(PK_BYTES);
        pk.extend_from_slice(&seed_a[..]);
        pk.extend_from_slice(&encode::encode_b(&digits));
        let selected_seed = {
            // The public core is fixed; setup failure never resamples it.
            // One draw: the first candidate seed.
            // It is the last entropy request of key generation.
            let candidate_start = random32(rng)?;
            let encoded = crate::dither_setup::prepare(&pk, &candidate_start)?;
            let seed: [u8; 32] = encoded[CORE_PK_BYTES..].try_into().unwrap();
            pk = encoded.to_vec();
            seed
        };
        let pk_hash = hashes::shake256_32(&pk);
        #[cfg(all(test, target_os = "macos"))]
        crate::timing_state::test_support::checkpoint("keygen-pack");
        let mut sk = Zeroizing::new(Vec::with_capacity(SK_BYTES));
        sk.extend_from_slice(&seed_a[..]);
        let mut packed = Zeroizing::new([0u8; TRIT_BYTES]);
        encode::keygen_pack_trits(&s0, &e, &mut packed);
        sk.extend_from_slice(&packed[..]);
        sk.extend_from_slice(&prf[..]);
        sk.extend_from_slice(&pk_hash);
        sk.extend_from_slice(&selected_seed);
        let (pk, sk) = (
            crate::direct_ntt_profile::tag_public(&pk),
            crate::direct_ntt_profile::tag_secret(&sk),
        );
        return Ok(Keypair {
            pk,
            sk: SecretKey(crate::guarded_drop::GuardedDrop::new(sk)),
        });
    }
    Err(Error::KeygenFailed)
}

struct ParsedSk {
    #[cfg(test)]
    // Runtime correlated transport uses prepared spectra/Gram data only.
    // Keep the dense secret for direct transport and independent test oracles.
    s_flat: Vector,
    correlations: crate::correlation::Key,
    b_weighted_sq_norm: u64,
    prf: [u8; 32],
    pk: Vec<u8>,
}

impl Drop for ParsedSk {
    fn drop(&mut self) {
        #[cfg(all(test, target_os = "macos"))]
        crate::timing_state::test_support::observe("parsed-key-drop");
        self.prf.zeroize();
        self.b_weighted_sq_norm.zeroize();
        #[cfg(test)]
        self.s_flat.zeroize();
        #[cfg(all(test, target_os = "macos"))]
        crate::timing_state::test_support::observe_erasure("prepared-secret-erased", || {
            let erased = self.prf.iter().all(|&x| x == 0) && self.b_weighted_sq_norm == 0;
            let erased = erased && self.s_flat.iter().all(|&x| x == 0);
            erased
        });
        // The matrices and pk are public.
    }
}
impl ZeroizeOnDrop for ParsedSk {}

#[allow(unreachable_code)]
// Explicit returns keep mutually exclusive selector branches structurally aligned.
#[allow(clippy::needless_return)]
// Keep the explicit lane order and index schedule of the kernel and its oracle.
#[allow(clippy::needless_range_loop)]
fn parse_sk(sk: &[u8]) -> Result<(ParsedSk, MatrixAh), Error> {
    let sk = crate::direct_ntt_profile::secret_body(sk)?;
    if sk.len() != SK_BYTES {
        return Err(Error::KeyFormat);
    }
    let seed_a: [u8; 32] = sk[..32].try_into().unwrap();
    #[cfg_attr(test, allow(unused_mut))]
    let mut trits =
        Zeroizing::new(encode::unpack_trits(&sk[32..32 + TRIT_BYTES]).ok_or(Error::KeyFormat)?);
    #[cfg(all(test, target_os = "macos"))]
    let mut trits = crate::timing_state::test_support::Traced::new(trits, "parse-trits-drop");
    let prf = Zeroizing::new(<[u8; 32]>::try_from(&sk[32 + TRIT_BYTES..64 + TRIT_BYTES]).unwrap());
    #[cfg(all(test, target_os = "macos"))]
    let prf = crate::timing_state::test_support::Traced::new(prf, "parse-prf-drop");
    let pk_hash: [u8; 32] = sk[64 + TRIT_BYTES..96 + TRIT_BYTES].try_into().unwrap();
    let selected_seed: [u8; 32] = sk[CORE_SK_BYTES..SK_BYTES].try_into().unwrap();
    let a0_ntt = crate::direct_ntt_profile::PublicMatrixNtt::expand(&seed_a);
    #[cfg_attr(test, allow(unused_mut))]
    let mut s_flat = Zeroizing::new([0i32; DIM]);
    #[cfg(all(test, target_os = "macos"))]
    let mut s_flat = crate::timing_state::test_support::Traced::new(s_flat, "parse-s_flat-drop");
    s_flat[0] = 1;
    s_flat[SEC..].copy_from_slice(&trits);
    let b_weighted_sq_norm = transport::key_weighted_sq_norm(&s_flat);
    {
        use crate::ct::ct_lt_u64;
        let bad = ct_lt_u64(b_weighted_sq_norm, SHELL_LO) | ct_lt_u64(SHELL_HI, b_weighted_sq_norm);
        if crate::ct::opaque_mask(bad) != 0 {
            return Err(Error::KeyFormat);
        }
    }
    // Leading key polynomial is exactly 1,0,...,0: public metric shift.
    let b_weighted_sq_norm = b_weighted_sq_norm - W0 + PROPOSAL_W0;
    // Prepare public A0 transforms once, retain exactly those columns in
    // the final matrix, and use them for the secret-key hash check.
    let mut mat = MatrixAh {
        rows: a0_ntt.into_rows(),
    };
    #[cfg_attr(test, allow(unused_mut))]
    let mut cols = Zeroizing::new([crate::compact_ring::CompactPoly::ZERO; ELL + 1]);
    #[cfg(all(test, target_os = "macos"))]
    let mut cols = crate::timing_state::test_support::Traced::new(cols, "parse-cols-drop");
    for c in 0..ELL {
        cols[c + 1].forward_from_i32(&s_flat[SEC + c * N..SEC + (c + 1) * N]);
    }
    #[cfg_attr(test, allow(unused_mut))]
    let mut error_spectra = Zeroizing::new([crate::compact_ring::CompactPoly::ZERO; M]);
    #[cfg(all(test, target_os = "macos"))]
    let mut error_spectra =
        crate::timing_state::test_support::Traced::new(error_spectra, "parse-error-spectra-drop");
    for r in 0..M {
        error_spectra[r].forward_from_i32(&s_flat[ERR + r * N..ERR + (r + 1) * N]);
    }
    let spectral_b =
        crate::direct_ntt_profile::SpectralPublicB::from_relation(&mat.rows, &cols, &error_spectra);
    let encoded_b = spectral_b.spectra();
    // Reuse the decoded-trit allocation only after erasing all trits.
    trits.zeroize();
    let mut digits: Vec<i32> = std::mem::take(&mut *trits);
    digits.clear();
    for p in encoded_b {
        for &c in &p.0 {
            digits.push(c.rem_euclid(Q));
        }
    }
    let mut pk_bytes = Vec::with_capacity(PK_BYTES);
    pk_bytes.extend_from_slice(&seed_a);
    pk_bytes.extend_from_slice(&encode::encode_b(&digits));
    pk_bytes.extend_from_slice(&selected_seed);
    let recomputed_pk_hash = crate::shake2::common_prefix::public_digest(&pk_bytes);
    if recomputed_pk_hash != pk_hash {
        return Err(Error::KeyFormat);
    }
    #[cfg(all(test, target_os = "macos"))]
    crate::timing_state::test_support::checkpoint("parse-hash-ok");
    // Only after the public-key hash check succeeds, install -b spectra.
    spectral_b.install_negated(&mut mat.rows);
    Ok((
        ParsedSk {
            correlations: {
                {
                    crate::correlation::Key::from_prepared_spectra(&s_flat, &cols, &error_spectra)
                }
            },
            #[cfg(test)]
            s_flat: *s_flat,
            b_weighted_sq_norm,
            prf: *prf,
            pk: pk_bytes,
        },
        mat,
    ))
}

#[cfg(test)]
pub(crate) fn certificate_caps(head: &[i32], residual: &[i32]) -> (bool, bool) {
    (
        check_caps_ct(head, residual) == u64::MAX,
        check_caps(head, residual),
    )
}

#[cfg(test)]
#[allow(unreachable_code)]
// Explicit returns keep mutually exclusive selector branches structurally aligned.
#[allow(clippy::needless_return)]
fn check_caps(z_h: &[i32], r_e: &[i32]) -> bool {
    // One pass per block computing the infinity, Euclidean and Q20 terms
    // together; the predicate is the conjunction of the three caps.
    let mut euc_h = 0u64;
    let mut q20 = 0u64;
    for &v in z_h {
        let a = v.unsigned_abs();
        if a > CAP_INF_HEAD as u32 {
            return false;
        }
        euc_h += (a as u64) * (a as u64);
        q20 += W_HEAD[a as usize] as u64;
    }
    if euc_h > CAP_EUC2_HEAD {
        return false;
    }
    let mut euc_r = 0u64;
    for &v in r_e {
        let a = v.unsigned_abs();
        if a > CAP_INF_RES as u32 {
            return false;
        }
        euc_r += (a as u64) * (a as u64);
        q20 += W_RES[a as usize] as u64;
    }
    if euc_r > CAP_EUC2_RES {
        return false;
    }
    q20 <= CAP_Q20
}

/// Constant-time postfilter: same predicate as `check_caps`, but branch-free
/// and with fixed memory-access pattern. Every coefficient is accumulated
/// unconditionally; the secret-indexed Q20 weight lookups become masked scans
/// over the (public, cache-resident) W tables so the touched-line pattern is
/// independent of the coefficient magnitudes. Returns an all-ones/zero mask
/// (all-ones = pass); the single bit that an attempt passed or aborted is a
/// declared leak, but the reason and the coefficient values are not.
#[allow(unreachable_code)]
// Explicit returns keep mutually exclusive selector branches structurally aligned.
#[allow(clippy::needless_return)]
fn check_caps_ct(z_h: &[i32], r_e: &[i32]) -> u64 {
    {
        return crate::ct_caps_piecewise::check_caps(z_h, r_e);
    }
}

/// Run preparation, signing and owner destruction under one timing guard.
/// The constructor, signer and destructor guards are nested inside it.
pub(crate) fn with_signing_guard<T>(
    operation: impl FnOnce() -> Result<T, Error>,
) -> Result<T, Error> {
    #[cfg(target_os = "macos")]
    let _timing_state = crate::timing_state::Guard::enter()?;
    operation()
}

/// A parsed and validated public key.  Construction performs the canonical
/// radix-q decode, matrix expansion, and optional public SHAKE prefixes once; `verify_prepared`
/// then amortizes that cost across many verifications under the same key.
pub struct PreparedPk {
    mat: Box<MatrixAh>,
    static_delta: Box<[Poly; M]>,
    prefixes: hashes::PublicPrefixes,
}

/// Validate the public core and prepare its matrix.
// The common-prefix production path prepares directly; this is used by reference tests.
#[cfg(test)]
#[allow(unreachable_code)]
// Explicit returns keep mutually exclusive selector branches structurally aligned.
#[allow(clippy::needless_return)]
pub(crate) fn prepare_core_matrix(core: &[u8]) -> Result<MatrixAh, Error> {
    if core.len() != CORE_PK_BYTES {
        return Err(Error::KeyFormat);
    }
    let seed_a: [u8; 32] = core[..32].try_into().unwrap();
    {
        return MatrixAh::from_spectral_b_packed_public(&seed_a, &core[32..]);
    }
}

impl PreparedPk {
    #[allow(dead_code)]
    #[allow(unreachable_code)]
    // Explicit returns keep mutually exclusive selector branches structurally aligned.
    #[allow(clippy::needless_return)]
    pub fn new(pk: &[u8]) -> Result<PreparedPk, Error> {
        let pk = crate::direct_ntt_profile::public_body(pk)?;
        if pk.len() != PK_BYTES {
            return Err(Error::KeyFormat);
        }
        {
            // Validate every public coefficient before beginning any expansion.
            let mut mat = public_matrix_storage();
            crate::direct_ntt_profile::SpectralPublicB::decode_public_negated_into(
                &pk[32..CORE_PK_BYTES],
                &mut mat.rows,
            )?;
            let mut static_delta = Box::<[Poly; M]>::new_uninit();
            let owners = crate::direct_ntt_profile::PublicMatrixNttDestination::new(&mut mat.rows)
                .fill_common_prefix(pk, &mut static_delta)
                .map_err(|_| Error::KeyFormat)?;
            // SAFETY: successful fill_common_prefix writes all M*N i32 slots
            // directly into the repr(transparent) Poly array. On error or
            // unwind the partial MaybeUninit owner is discarded without reads.
            let static_delta = unsafe { static_delta.assume_init() };
            let prefixes = hashes::PublicPrefixes::from_owners(owners);
            return Ok(PreparedPk {
                mat,
                static_delta,
                prefixes,
            });
        }
    }
}

impl PreparedPk {
    #[allow(unreachable_code)]
    // Explicit returns keep mutually exclusive selector branches structurally aligned.
    #[allow(clippy::needless_return)]
    fn from_matrix(mat: MatrixAh, pk: &[u8]) -> Result<PreparedPk, Error> {
        if pk.len() != PK_BYTES {
            return Err(Error::KeyFormat);
        }
        let (static_delta, prefixes) = {
            let (flat, owners) =
                crate::dither_frame::expand_with_prefixes(pk).map_err(|_| Error::KeyFormat)?;
            let rows = core::array::from_fn(|r| Poly(core::array::from_fn(|i| flat[r * N + i])));
            (rows, hashes::PublicPrefixes::from_owners(owners))
        };
        Ok(PreparedPk {
            mat: Box::new(mat),
            static_delta: Box::new(static_delta),
            prefixes,
        })
    }
    // The constructor tests hand over the key bytes by value.
    #[cfg(test)]
    fn from_parts(mat: MatrixAh, pk: Vec<u8>) -> Result<PreparedPk, Error> {
        Self::from_matrix(mat, &pk)
    }
    /// Parsed canonical dither, borrowed without a per-call copy of the `[Poly; M]` array.
    /// Import validates the dither framing, not honest key generation.
    pub(crate) fn static_dither(&self) -> &[Poly; M] {
        &self.static_delta
    }
    fn message_rep(&self, context: &[u8], msg: &[u8]) -> [u8; 64] {
        {
            self.prefixes.message_rep(context, msg)
        }
    }
    fn challenge_bytes(&self, mu: &[u8; 64], rho: &[u8; SALT_BYTES], labels: &[u8]) -> [u8; 32] {
        {
            self.prefixes.challenge_bytes(mu, rho, labels)
        }
    }
}

/// A parsed secret key with all per-key precomputation done: the NTT-domain
/// relation matrix and the prepared public verifier. Amortizes the per-call
/// key processing when signing many messages under
/// one key.
pub struct PreparedSk {
    secret: crate::guarded_drop::GuardedDrop<Box<PreparedSecret>>,
    public_envelope: Vec<u8>,
    ppk: PreparedPk,
}

// Secret bytes stay in this allocation from guarded construction through
// guarded destruction. Moving PreparedSk moves only a pointer and public data.
struct PreparedSecret {
    key: ParsedSk,
    transport_prepared: crate::transport_queue::Prepared,
}

impl PreparedSk {
    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn secret_address(&self) -> usize {
        (&**self.secret as *const PreparedSecret) as usize
    }

    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn poison_secret_for_dit_test(&mut self) {
        self.secret.key.prf.fill(0xa5);
        self.secret.key.b_weighted_sq_norm = 7;
        self.secret.key.s_flat.fill(9);
        assert!(self.secret.key.prf.iter().all(|&x| x != 0));
    }

    #[allow(unreachable_code)]
    // Explicit returns keep mutually exclusive selector branches structurally aligned.
    #[allow(clippy::needless_return)]
    pub fn public_key(&self) -> &[u8] {
        {
            return &self.public_envelope;
        }
    }

    #[allow(dead_code)]
    /// Prepare and allocate secret state under DIT. The returned owner holds
    /// only a heap pointer and public fields, so later moves copy no secrets.
    pub fn new(sk: &[u8]) -> Result<PreparedSk, Error> {
        // First local: constructor temporaries and, with the feature `stack-wipe`,
        // the value-independent stack scrub retire before the caller's timing state
        // is restored.
        #[cfg(target_os = "macos")]
        let _timing_state = crate::timing_state::Guard::enter()?;
        #[cfg(feature = "stack-wipe")]
        let _stack_scrub = crate::ct_erase::StackScrub::<{ crate::ct_erase::PREPARE_SCRUB_WORDS }>;
        Self::new_unscrubbed(sk)
    }

    // The import body. With the feature `stack-wipe` it is out of line, so that its
    // frame lies below the frame that holds the scrub. Without the feature it is
    // always inlined into `new`, its only caller, so the default build has one
    // function.
    #[cfg_attr(feature = "stack-wipe", inline(never))]
    #[cfg_attr(not(feature = "stack-wipe"), inline(always))]
    fn new_unscrubbed(sk: &[u8]) -> Result<PreparedSk, Error> {
        #[cfg(all(test, target_os = "macos"))]
        crate::timing_state::test_support::observe("prepare-entry");
        let (key, mat) = parse_sk(sk)?;
        // The same matrix and hash the public verifier would derive from
        // pk_bytes: decode_b(encode_b(.)) is the identity on canonical digit
        // vectors, and parse_sk has already checked pk_hash against the
        // re-encoded public key bytes.
        // parse_sk already supplied the validated canonical matrix.
        let ppk = PreparedPk::from_matrix(mat, &key.pk)?;
        let transport_prepared = {
            crate::transport_queue::Prepared::new(key.b_weighted_sq_norm)
                .ok_or(Error::SignFailed)?
        };
        #[cfg(all(test, target_os = "macos"))]
        crate::timing_state::test_support::checkpoint("prepare-exit");
        Ok(PreparedSk {
            public_envelope: crate::direct_ntt_profile::tag_public(&key.pk),
            secret: crate::guarded_drop::GuardedDrop::new(Box::new(PreparedSecret {
                key,
                transport_prepared,
            })),
            ppk,
        })
    }
}

#[cfg(test)]
mod ct_tests {
    use super::*;

    #[test]
    // Keep the independent public reference copy path explicit.
    #[allow(clippy::map_clone)]
    fn check_caps_ct_matches_scalar() {
        let mut st = 0x1234_5678_9abc_def0u64;
        let mut rnd = move || {
            st ^= st << 13;
            st ^= st >> 7;
            st ^= st << 17;
            st
        };
        for t in 0..5000 {
            // mostly-in-range vectors, occasionally pushing a cap
            let scale_h = if t % 3 == 0 { 320 } else { 260 };
            let scale_r = if t % 4 == 0 { 470 } else { 400 };
            let z_h: Vec<i32> = (0..N + ELL * N)
                .map(|_| (rnd() % (2 * scale_h)) as i32 - scale_h as i32)
                .collect();
            let r_e: Vec<i32> = (0..M * N)
                .map(|_| (rnd() % (2 * scale_r)) as i32 - scale_r as i32)
                .collect();
            // clamp head/res to their table domains so scalar indexing is valid
            let z_h: Vec<i32> = z_h
                .iter()
                .map(|&v| v.clamp(-CAP_INF_HEAD, CAP_INF_HEAD))
                .collect();
            let r_e: Vec<i32> = r_e
                .iter()
                .map(|&v| v.clamp(-CAP_INF_RES, CAP_INF_RES))
                .collect();
            let scalar = check_caps(&z_h, &r_e);
            let ct = check_caps_ct(&z_h, &r_e) == u64::MAX;
            assert_eq!(scalar, ct, "caps mismatch at t={t}");
        }
    }

    #[test]
    fn check_caps_ct_inf_violation() {
        // a single over-cap coefficient must fail both, even when the masked
        // scan has no matching table entry for the out-of-range magnitude.
        let mut z_h = vec![0i32; N + ELL * N];
        let r_e = vec![0i32; M * N];
        z_h[7] = CAP_INF_HEAD + 5;
        assert!(!check_caps(&z_h, &r_e));
        assert_eq!(check_caps_ct(&z_h, &r_e), 0);
    }
}

#[cfg(test)]
mod public_fiber_tests {
    use super::*;
    #[test]
    fn bounded_congruence_including_failing_fibers() {
        for difference in -2 * Q + 1..2 * Q {
            let fast = difference == 0 || difference == Q || difference == -Q;
            assert_eq!(fast, difference.rem_euclid(Q) == 0);
            // Independent representatives and public dithers; the two
            // reductions must agree exactly, including false predicates.
            for delta in [0, 1, Q / 2, Q - 1] {
                for center in [0, 1, Q / 2, Q - 1] {
                    assert_eq!(
                        fast,
                        (difference + center - delta).rem_euclid(Q)
                            == (center - delta).rem_euclid(Q)
                    );
                }
            }
        }
    }
}

pub(crate) struct MatrixAh {
    rows: [[crate::compact_ring::CompactPoly; ELL + 1]; M],
}
impl MatrixAh {
    #[cfg(test)]
    fn from_spectral_b_packed_public(seed: &[u8; 32], bytes: &[u8]) -> Result<Self, Error> {
        let mut out = Self {
            rows: [[crate::compact_ring::CompactPoly::ZERO; ELL + 1]; M],
        };
        crate::direct_ntt_profile::SpectralPublicB::decode_negated_into(bytes, &mut out.rows)?;
        crate::direct_ntt_profile::PublicMatrixNttDestination::new(&mut out.rows)
            .fill_spectra_preserving_public_b(seed);
        Ok(out)
    }
    #[allow(dead_code)]
    fn from_direct_ntt_packed_public(seed: &[u8; 32], bytes: &[u8]) -> Result<Self, Error> {
        let mut out = Self {
            rows: [[crate::compact_ring::CompactPoly::ZERO; ELL + 1]; M],
        };
        // A rejected public prefix is discarded before spectral expansion or transforms.
        encode::decode_b_into(bytes, |i, x| {
            out.rows[i / N][0].0[i % N] = if x == 0 { 0 } else { (Q - x) as i16 }
        })
        .ok_or(Error::KeyFormat)?;
        crate::direct_ntt_profile::PublicMatrixNttDestination::new(&mut out.rows)
            .fill_spectra_preserving_public_b(seed);
        // A columns are already spectra: transform coefficient b only, exactly M times.
        for row in &mut out.rows {
            row[0].forward_canonical();
        }
        Ok(out)
    }
    #[allow(dead_code)]
    fn from_direct_ntt_public(seed: &[u8; 32], digits: &[i32]) -> Self {
        assert_eq!(digits.len(), M * N);
        assert!(digits.iter().all(|&x| (0..Q).contains(&x)));
        let mut out = Self {
            rows: [[crate::compact_ring::CompactPoly::ZERO; ELL + 1]; M],
        };
        crate::direct_ntt_profile::PublicMatrixNttDestination::new(&mut out.rows)
            .fill_from_seed(seed);
        for r in 0..M {
            for i in 0..N {
                let x = digits[r * N + i];
                out.rows[r][0].0[i] = if x == 0 { 0 } else { (Q - x) as i16 };
            }
            out.rows[r][0].forward_canonical();
        }
        out
    }
    #[allow(dead_code)]
    fn new(a0: &[[Poly; ELL]; M], b: &[Poly; M]) -> Self {
        use crate::compact_ring::CompactPoly;
        let rows = core::array::from_fn(|r| {
            core::array::from_fn(|c| {
                let mut out = CompactPoly::ZERO;
                if c == 0 {
                    // Preserve the signed negation expression and normalization.
                    let neg = Poly(core::array::from_fn(|i| (-b[r].0[i]).rem_euclid(Q)));
                    out.forward_from_i32(&neg.0);
                } else {
                    // Generic constructor callers may supply arbitrary i32 coefficients.
                    // Reuse normalization and the compact/scalar NTT dispatch.
                    out.forward_from_i32(&a0[r][c - 1].0);
                }
                out
            })
        });
        Self { rows }
    }
    #[cfg(test)]
    fn apply(&self, z: &Vector, delta: &[Poly; M]) -> [Poly; M] {
        {
            let mut cols = Zeroizing::new([crate::compact_ring::CompactPoly::ZERO; ELL + 1]);
            self.fill_compact(z, &mut cols);
            self.finish_compact(&cols, delta)
        }
    }
    #[allow(unreachable_code)]
    // Explicit returns keep mutually exclusive selector branches structurally aligned.
    #[allow(clippy::needless_return)]
    fn apply_noncore_bounded_into(&self, z: &Vector, delta: &[Poly; M], out: &mut [Poly; M]) {
        {
            let mut cols = Zeroizing::new([crate::compact_ring::CompactPoly::ZERO; ELL + 1]);
            for c in 0..=ELL {
                cols[c].forward_from_noncore_bounded(&z[c * N..(c + 1) * N]);
            }
            for r in 0..M {
                crate::compact_ring::dot_compact_into(&self.rows[r], &cols, &mut out[r]);
                ring::intt(&mut out[r]);
                crate::neon_mod_arith::add_canonical(&mut out[r].0, &delta[r].0);
            }
        }
    }
    fn fill_compact(&self, z: &[i32], cols: &mut [crate::compact_ring::CompactPoly; ELL + 1]) {
        for c in 0..=ELL {
            cols[c].forward_from_i32(&z[c * N..(c + 1) * N]);
        }
    }
    #[cfg(test)]
    fn finish_compact(
        &self,
        cols: &[crate::compact_ring::CompactPoly; ELL + 1],
        delta: &[Poly; M],
    ) -> [Poly; M] {
        core::array::from_fn(|r| {
            let mut a = crate::compact_ring::dot_compact(&self.rows[r], cols);
            ring::intt(&mut a);
            a.add_canonical(&delta[r])
        })
    }
    #[cfg(test)]
    #[inline(always)]
    fn apply_public(&self, z: &[i32; N + ELL * N], delta: &[Poly; M]) -> [Poly; M] {
        {
            let mut cols = [crate::compact_ring::CompactPoly::ZERO; ELL + 1];
            self.fill_compact(z, &mut cols);
            self.finish_compact(&cols, delta)
        }
    }
}

#[cfg(all(test, target_endian = "little"))]
mod matrix_reference_tests {
    use super::*;
    use crate::compact_ring::CompactPoly;
    #[test]
    fn private_commitment_all_rows_and_signed_ingress_are_canonical() {
        let mut state = 0x1779da42695bcc49u64;
        let mut next = || {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            (state >> 32) as u32
        };
        for trial in 0..64 {
            let rows: [[CompactPoly; ELL + 1]; M] = core::array::from_fn(|_| {
                core::array::from_fn(|_| {
                    CompactPoly(core::array::from_fn(|_| match trial {
                        0 => 0,
                        1 => (Q - 1) as i16,
                        _ => (next() % Q as u32) as i16,
                    }))
                })
            });
            let matrix = MatrixAh { rows };
            let old_rows = rows;
            let z: Vector = core::array::from_fn(|i| match trial % 8 {
                0 => 0,
                1 => i32::MIN,
                2 => i32::MAX,
                3 => {
                    if i % 2 == 0 {
                        Q - 1
                    } else {
                        1 - Q
                    }
                }
                4 => {
                    if i < N {
                        168
                    } else if i < 6 * N {
                        1149
                    } else {
                        1462
                    }
                }
                5 => {
                    if i % 2 == 0 {
                        32767
                    } else {
                        -32767
                    }
                }
                _ => next() as i32,
            });
            let delta: [Poly; M] = core::array::from_fn(|r| {
                Poly(core::array::from_fn(|i| match trial % 4 {
                    0 => 0,
                    1 => Q - 1,
                    2 => {
                        if (i + r) % 2 == 0 {
                            0
                        } else {
                            Q - 1
                        }
                    }
                    _ => (next() % Q as u32) as i32,
                }))
            });
            let old_z = z;
            let old_delta = delta;
            let actual = matrix.apply(&z, &delta);
            assert_eq!(matrix.rows, old_rows);
            assert_eq!(z, old_z);
            assert_eq!(delta, old_delta);
            for row in actual {
                assert!(row.0.iter().all(|&v| (0..Q).contains(&v)), "trial {trial}");
            }
        }
    }
}

#[path = "prepared_signer.rs"]
pub mod prepared_signer;

#[path = "public_matrix_product.rs"]
pub mod public_matrix_product;

// Native test fixture: honestly generated packed13 key, never a profile transcode.
#[cfg(test)]
#[allow(unreachable_code)]
// Explicit returns keep mutually exclusive selector branches structurally aligned.
#[allow(clippy::needless_return)]
pub(crate) fn packed13_screened_test_core(index: u64) -> Vec<u8> {
    #[cfg(target_os = "macos")]
    let _timing_state = crate::timing_state::Guard::enter().unwrap();
    struct Tape(crate::hashes::Xof);
    impl crate::entropy::EntropySource for Tape {
        fn fill(&mut self, out: &mut [u8]) -> Result<(), crate::entropy::EntropyError> {
            self.0.fill(out);
            Ok(())
        }
    }
    // This binding is consumed only by an alternate selector.
    #[allow(unused_variables)]
    let ctx = Ctx::new();
    let mut tape = Tape(crate::hashes::Xof::new(
        b"packed13-native-corpus-replacement-v1",
        &[&index.to_le_bytes()],
    ));
    let pair = keygen_with_entropy(&ctx, &mut tape).unwrap();
    PreparedPk::new(&pair.pk).unwrap();
    {
        return crate::direct_ntt_profile::public_body(&pair.pk).unwrap()[..CORE_PK_BYTES].to_vec();
    }
}

#[cfg(test)]
mod compact_matrix_ingress_tests {
    use super::*;
    use crate::compact_ring::CompactPoly;
    // Exact reference constructor, the differential oracle.
    fn parent(a0: &[[Poly; ELL]; M], b: &[Poly; M]) -> MatrixAh {
        let rows = core::array::from_fn(|r| {
            core::array::from_fn(|c| {
                let mut p = if c == 0 {
                    Poly(core::array::from_fn(|i| (-b[r].0[i]).rem_euclid(Q)))
                } else {
                    a0[r][c - 1]
                };
                p.reduce();
                ring::ntt(&mut p);
                CompactPoly::from_canonical(&p)
            })
        });
        MatrixAh { rows }
    }

    fn input(case: usize) -> ([[Poly; ELL]; M], [Poly; M]) {
        let mut state = 0x761aae3990u64.wrapping_add(case as u64);
        let mut next = || {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            (state >> 32) as i32
        };
        let a = core::array::from_fn(|r| {
            core::array::from_fn(|c| {
                Poly(core::array::from_fn(|i| match case {
                    0 => 0,
                    1 => Q - 1,
                    2 => i32::MIN,
                    3 => i32::MAX,
                    4 => {
                        if (i + c + r) % 2 == 0 {
                            Q - 1
                        } else {
                            1 - Q
                        }
                    }
                    _ => next(),
                }))
            })
        });
        // The unary minus in `parent` overflows for i32::MIN in checked builds. Do not
        // change that contract or silently introduce wrapping negation here.
        let b = core::array::from_fn(|r| {
            Poly(core::array::from_fn(|i| match case {
                0 => 0,
                1 => Q - 1,
                2 => -i32::MAX,
                3 => i32::MAX,
                4 => {
                    if (i + r) % 2 == 0 {
                        Q - 1
                    } else {
                        1 - Q
                    }
                }
                _ => {
                    let v = next();
                    if v == i32::MIN {
                        -i32::MAX
                    } else {
                        v
                    }
                }
            }))
        });
        (a, b)
    }
    #[test]
    // Keep the explicit lane order and index schedule of the kernel and its oracle.
    #[allow(clippy::needless_range_loop)]
    fn constructor_rows_match_parent_and_scalar_for_signed_inputs() {
        for case in 0..32 {
            let (a, b) = input(case);
            let old = parent(&a, &b);
            let new = MatrixAh::new(&a, &b);
            assert_eq!(new.rows, old.rows, "case={case}");
            for r in 0..M {
                for c in 0..=ELL {
                    let mut scalar = if c == 0 {
                        Poly(core::array::from_fn(|i| (-b[r].0[i]).rem_euclid(Q)))
                    } else {
                        a[r][c - 1]
                    };
                    scalar.reduce();
                    ring::ntt_scalar(&mut scalar);
                    assert_eq!(
                        new.rows[r][c],
                        CompactPoly::from_canonical(&scalar),
                        "case={case}, row={r}, col={c}"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod direct_canonical_matrix_tests {
    use super::*;
    #[test]
    fn direct_public_import_preserves_wire_errors_and_rows() {
        for case in [0i32, 1, Q - 1] {
            let seed = [case as u8; 32];
            let digits = vec![case; M * N];
            let mut core = seed.to_vec();
            core.extend_from_slice(&encode::encode_b(&digits));
            let actual = prepare_core_matrix(&core).unwrap();
            {
                let coefficient_digits: Vec<i32> = digits
                    .chunks_exact(N)
                    .flat_map(|chunk| {
                        let mut p = Poly::ZERO;
                        p.0.copy_from_slice(chunk);
                        ring::intt(&mut p);
                        p.0
                    })
                    .collect();
                assert_eq!(
                    actual.rows,
                    MatrixAh::from_direct_ntt_public(&seed, &coefficient_digits).rows
                );
            }
            assert!(prepare_core_matrix(&core[..core.len() - 1]).is_err());
            core.push(0);
            assert!(prepare_core_matrix(&core).is_err());
        }
        let mut invalid = vec![255u8; CORE_PK_BYTES];
        invalid[..32].fill(0);
        assert!(prepare_core_matrix(&invalid).is_err());
    }
}

#[cfg(test)]
mod direct_ntt_profile_tests {
    use super::*;
    #[test]
    // Keep the independent public reference copy path explicit.
    #[allow(clippy::map_clone)]
    fn direct_ntt_public_constructor_inverse_reference_and_malformed() {
        for case in 0..8u8 {
            let seed = [case; 32];
            let spectral = crate::direct_ntt_profile::PublicMatrixNtt::expand(&seed);
            let a = core::array::from_fn(|r| {
                core::array::from_fn(|c| {
                    let mut p = spectral.spectral_poly(r, c);
                    ring::intt(&mut p);
                    p
                })
            });
            let digits: Vec<i32> = (0..M * N)
                .map(|i| ((i * 173 + case as usize) % Q as usize) as i32)
                .collect();
            let b = core::array::from_fn(|r| Poly(core::array::from_fn(|i| digits[r * N + i])));
            assert_eq!(
                MatrixAh::from_direct_ntt_public(&seed, &digits).rows,
                MatrixAh::new(&a, &b).rows
            );
        }
        crate::direct_ntt_profile::without_expansion(|| {
            // Independently set one packed 13-bit coefficient to q; all others stay zero.
            for position in 0..M * N {
                let mut body = vec![0u8; PK_BYTES];
                for bit in 0..13 {
                    if ((Q as u32) >> bit) & 1 != 0 {
                        let offset = position * 13 + bit;
                        body[32 + offset / 8] |= 1u8 << (offset % 8);
                    }
                }
                let invalid = crate::direct_ntt_profile::tag_public(&body);
                assert!(
                    PreparedPk::new(&invalid).is_err(),
                    "noncanonical coefficient {}",
                    position
                );
            }
            let tagged = crate::direct_ntt_profile::tag_public(&vec![0; PK_BYTES]);
            let secret = crate::direct_ntt_profile::tag_secret(&vec![0; SK_BYTES]);
            for i in 0..14 {
                let mut bad = tagged.clone();
                bad[i] ^= 1;
                assert!(PreparedPk::new(&bad).is_err());
                let mut bad = secret.to_vec();
                bad[i] ^= 1;
                assert!(PreparedSk::new(&bad).is_err());
            }
            for len in [0, 1, 13, 14, 15, 14 + PK_BYTES - 1, 14 + PK_BYTES + 1] {
                let mut bad = tagged.clone();
                bad.resize(len, 0);
                assert!(PreparedPk::new(&bad).is_err());
            }
            for len in [0, 1, 13, 14, 15, 14 + SK_BYTES - 1, 14 + SK_BYTES + 1] {
                let mut bad = secret.to_vec();
                bad.resize(len, 0);
                assert!(PreparedSk::new(&bad).is_err());
            }
        });
        assert!(PreparedSk::new(&vec![0; SK_BYTES]).is_err());
        assert!(PreparedPk::new(&vec![0; PK_BYTES]).is_err());
    }
}

#[cfg(test)]
mod direct_ntt_packed_destination_tests {
    use super::*;
    #[test]
    // Keep the independent public reference copy path explicit.
    #[allow(clippy::map_clone)]
    fn packed_direct_ntt_rows_match_retained_digits_constructor() {
        for case in 0..16u8 {
            let seed = [case; 32];
            let digits: Vec<i32> = (0..M * N)
                .map(|i| match case {
                    0 => 0,
                    1 => 1,
                    2 => Q - 1,
                    _ => ((i * 173 + case as usize * 71) % Q as usize) as i32,
                })
                .collect();
            let bytes = encode::encode_b(&digits);
            assert_eq!(encode::decode_b(&bytes), Some(digits.clone()));
            assert_eq!(
                MatrixAh::from_direct_ntt_packed_public(&seed, &bytes)
                    .unwrap()
                    .rows,
                MatrixAh::from_direct_ntt_public(&seed, &digits).rows
            );
        }
    }
    #[test]
    fn malformed_packed_direct_ntt_never_expands_and_discards_prefix() {
        crate::direct_ntt_profile::without_expansion(|| {
            for len in [
                0,
                1,
                PK_B_BYTES - 1,
                PK_B_BYTES + 1,
                CORE_PK_BYTES,
                PK_BYTES,
                14 + PK_BYTES,
            ] {
                assert!(MatrixAh::from_direct_ntt_packed_public(&[7; 32], &vec![0; len]).is_err());
            }
            for position in [0, M * N / 2, M * N - 1] {
                for digit in Q..8192 {
                    let mut bytes = vec![0u8; PK_B_BYTES];
                    for bit in 0..13 {
                        if ((digit as u32) >> bit) & 1 != 0 {
                            let offset = position * 13 + bit;
                            bytes[offset / 8] |= 1u8 << (offset % 8);
                        }
                    }
                    let mut writes = 0usize;
                    assert!(encode::decode_b_into(&bytes, |i, x| {
                        assert_eq!(i, writes);
                        assert_eq!(x, 0);
                        writes += 1;
                    })
                    .is_none());
                    assert_eq!(writes, position);
                    assert!(MatrixAh::from_direct_ntt_packed_public(&[7; 32], &bytes).is_err());
                }
            }
        });
    }
}

#[cfg(test)]
mod spectral_public_b_tests {
    use super::*;
    #[test]
    // Keep the explicit lane order and index schedule of the kernel and its oracle.
    #[allow(clippy::needless_range_loop)]
    fn spectral_b_import_matches_coefficient_matrix_and_screen_relation() {
        for case in 0..8u8 {
            let seed = [case; 32];
            let b: [Poly; M] = core::array::from_fn(|r| {
                Poly(core::array::from_fn(|i| match case {
                    0 => 0,
                    1 => Q - 1,
                    _ => ((r * N + i) * 173 + case as usize) as i32 % Q,
                }))
            });
            let owner = crate::direct_ntt_profile::SpectralPublicB::from_coefficients(&b);
            let digits: Vec<i32> = owner.spectra().iter().flat_map(|p| p.0).collect();
            let mut core = seed.to_vec();
            core.extend_from_slice(&encode::encode_b(&digits));
            let actual = prepare_core_matrix(&core).unwrap();
            let coefficients: Vec<i32> = b.iter().flat_map(|p| p.0).collect();
            let reference = MatrixAh::from_direct_ntt_public(&seed, &coefficients);
            assert_eq!(actual.rows, reference.rows);
            for r in 0..M {
                let mut recovered = owner.spectra()[r];
                ring::intt(&mut recovered);
                assert_eq!(recovered, b[r]);
            }
            // Compare the public relation on the same coefficient heads.
            for mode in 0..4 {
                let head = core::array::from_fn(|i| match mode {
                    0 => 0,
                    1 => 1,
                    2 => -1,
                    _ => (i % 7) as i32 - 3,
                });
                assert_eq!(
                    actual.apply_public(&head, &[Poly::ZERO; M]),
                    reference.apply_public(&head, &[Poly::ZERO; M])
                );
            }
        }
    }
    #[test]
    fn spectral_b_all_positions_and_foreign_tags_reject_before_expansion() {
        crate::direct_ntt_profile::without_expansion(|| {
            for position in 0..M * N {
                let mut body = vec![0u8; PK_BYTES];
                for bit in 0..13 {
                    if ((Q as u32) >> bit) & 1 != 0 {
                        let offset = position * 13 + bit;
                        body[32 + offset / 8] |= 1u8 << (offset % 8);
                    }
                }
                assert!(PreparedPk::new(&crate::direct_ntt_profile::tag_public(&body)).is_err());
            }
            for old in [
                b"pretzel-nt13v1",
                b"pretzel-pk13v1",
                b"pretzel-nb13v1",
                b"pretzel-nt13v2",
            ] {
                let mut pk = old.to_vec();
                pk.extend_from_slice(&vec![0; PK_BYTES]);
                assert!(PreparedPk::new(&pk).is_err());
                let mut sk = old.to_vec();
                sk.extend_from_slice(&vec![0; SK_BYTES]);
                assert!(PreparedSk::new(&sk).is_err());
            }
        });
    }
}

#[cfg(test)]
mod common_public_preparation_tests {
    use super::*;
    #[test]
    fn common_public_malformed_never_expands_and_reused_matrix_matches() {
        let body = vec![0u8; PK_BYTES];
        let tagged = crate::direct_ntt_profile::tag_public(&body);
        for index in [0usize, M * N / 2 - 1, M * N - 1] {
            let mut bad = body.clone();
            let value = 7681u16;
            for bit in 0..13 {
                let k = 13 * index + bit;
                bad[32 + k / 8] |= (((value >> bit) & 1) as u8) << (k % 8);
            }
            let bad = crate::direct_ntt_profile::tag_public(&bad);
            crate::direct_ntt_profile::without_expansion(
                || assert!(PreparedPk::new(&bad).is_err()),
            );
        }
        for len in [0, 13, 14, 14 + PK_BYTES - 1, 14 + PK_BYTES + 1] {
            let mut bad = tagged.clone();
            bad.resize(len, 0);
            crate::direct_ntt_profile::without_expansion(
                || assert!(PreparedPk::new(&bad).is_err()),
            );
        }
        for i in 0..14 {
            let mut bad = tagged.clone();
            bad[i] ^= 1;
            crate::direct_ntt_profile::without_expansion(
                || assert!(PreparedPk::new(&bad).is_err()),
            );
        }
        for tag in [b"pretzel-nb13v2", b"pretzel-nt13v2"] {
            let mut bad = tagged.clone();
            bad[..14].copy_from_slice(tag);
            crate::direct_ntt_profile::without_expansion(
                || assert!(PreparedPk::new(&bad).is_err()),
            );
        }
        for case in 0..4u8 {
            let mut body = body.clone();
            body[..32].fill(case);
            body[CORE_PK_BYTES..].fill(case.wrapping_add(5));
            let wire = crate::direct_ntt_profile::tag_public(&body);
            let fused = PreparedPk::new(&wire).unwrap();
            let core = prepare_core_matrix(&body[..CORE_PK_BYTES]).unwrap();
            let reused = PreparedPk::from_parts(core, body).unwrap();
            for r in 0..M {
                for c in 0..=ELL {
                    assert_eq!(fused.mat.rows[r][c].0, reused.mat.rows[r][c].0);
                }
                assert_eq!(fused.static_delta[r].0, reused.static_delta[r].0);
            }
            assert_eq!(
                fused.message_rep(b"ctx", b"msg"),
                reused.message_rep(b"ctx", b"msg")
            );
        }
    }
}

#[path = "verifier.rs"]
pub mod verifier;

// The preparation test compiled into this crate from the Pretzel-(4,4) backend by `#[path]`
// calls the verifier by its name in that crate.
#[cfg(test)]
mod rice_verify {
    pub(super) use super::verifier::PreparedVerifier as PreparedRice;
}

#[cfg(test)]
include!("keyprep_tests.rs");

#[cfg(test)]
#[path = "../../pretzel-4-4/core/src/prepk_direct_tests.rs"]
mod prepk_direct_tests;

#[cfg(test)]
#[path = "../../pretzel-4-4/core/src/public_matrix_prepared_tests.rs"]
mod matrix_sampler_preparation_tests;

// Public preparation fills the final allocation instead of returning a large
// stack matrix. The borrowed sampler requires initialized coefficient storage.
fn public_matrix_storage() -> Box<MatrixAh> {
    let mut mat = Box::<MatrixAh>::new_uninit();
    // SAFETY: under this configuration MatrixAh contains only nested arrays
    // of CompactPoly, whose only field is an i16 coefficient array. Zero
    // is valid for every field. This writes the whole allocation before any
    // reference or initialized Box is formed, and no partial value can escape.
    unsafe {
        mat.as_mut_ptr().write_bytes(0, 1);
        mat.assume_init()
    }
}

#[cfg(test)]
#[path = "../../pretzel-4-4/core/src/public_preparation_wire_tests.rs"]
mod preparation_wire_tests;

#[cfg(test)]
fn sign_for_preparation_test(
    ctx: &Ctx,
    sk: &PreparedSk,
    context: &[u8],
    message: &[u8],
    _entropy: &mut impl EntropySource,
    scratch: &mut SigningScratch,
) -> Result<(Vec<u8>, u32), Error> {
    prepared_signer::sign_prepared_with_scratch(ctx, sk, scratch, context, message)
}
