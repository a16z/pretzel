//! Key generation, signing, and verification.

use crate::challenge;
use crate::encode;
use crate::gauss::Cdt;

use crate::hashes::{self, Xof};
use crate::params::*;
use crate::params_tables::{W_HEAD, W_RES};
use crate::quantize;
use crate::randomness::AttemptRandomness;
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

macro_rules! stage {
    ($i:expr, $e:expr) => {
        $e
    };
}

/// Shared precomputed context (heavy init; build once, reuse).
pub struct Ctx {
    pub theta: ThetaCtx,
    cdt_lead: Cdt,
    cdt_sec: Cdt,
    cdt_err: Cdt,
}

impl Ctx {
    /// Deterministic public table artifact for independent checking and pinning.
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
            let mut written = [Poly::ZERO; M];
            matrix.apply_into(&z, &delta, &mut written);
            assert_eq!(written, expected);
        }
    }
}

pub struct Keypair {
    pub pk: Vec<u8>,
    pub sk: SecretKey,
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
    #[cfg(all(any(target_os = "linux", target_os = "macos"), target_arch = "aarch64"))]
    let _timing_state = crate::timing_state::Guard::enter()?;
    // Created after the timing guard so the scrub completes before DIT restores.
    #[cfg(feature = "stack-wipe")]
    let _stack_scrub = crate::ct_erase::StackScrub::<{ crate::ct_erase::KEYGEN_SCRUB_WORDS }>;
    keygen_inner(rng)
}

// Both entry families retain their timing guard above this body, and with the
// feature `stack-wipe` their scrub guard. With the feature the body is kept out
// of line so the scrub can overlay its retired frame on return or unwind, after
// the private owners drop and before timing state is restored. Without the
// feature it carries no inlining attribute.
// Key generation uses no context tables; eager/lazy initialization stays with
// the caller's context type.
#[cfg_attr(feature = "stack-wipe", inline(never))]
fn keygen_inner(rng: &mut impl EntropySource) -> Result<Keypair, Error> {
    #[cfg(all(
        any(target_os = "linux", target_os = "macos"),
        target_arch = "aarch64",
        test
    ))]
    let mut traced_rng = crate::timing_state::test_support::KeygenEntropy(rng);
    #[cfg(all(
        any(target_os = "linux", target_os = "macos"),
        target_arch = "aarch64",
        test
    ))]
    let rng = &mut traced_rng;
    let seed_a = random32(rng)?;
    #[cfg(all(
        any(target_os = "linux", target_os = "macos"),
        target_arch = "aarch64",
        test
    ))]
    let seed_a = crate::timing_state::test_support::Traced::new(seed_a, "keygen-seed_a-drop");
    let prf = random32(rng)?;
    #[cfg(all(
        any(target_os = "linux", target_os = "macos"),
        target_arch = "aarch64",
        test
    ))]
    let prf = crate::timing_state::test_support::Traced::new(prf, "keygen-prf-drop");
    let a0_ntt = crate::direct_ntt_profile::PublicMatrixNtt::expand(&seed_a);
    // Operational shell-rejection cap, not a certified failure probability.
    for _ in 0..MAX_ATTEMPTS {
        let key_seed = random32(rng)?;
        #[cfg(all(
            any(target_os = "linux", target_os = "macos"),
            target_arch = "aarch64",
            test
        ))]
        crate::timing_state::test_support::checkpoint("keygen-private");
        let mut x = Xof::new(DOM_KEY, &[&key_seed[..]]);
        let s0 = Zeroizing::new(core::array::from_fn::<_, ELL, _>(|_| x.poly_cbd1()));
        #[cfg(all(
            any(target_os = "linux", target_os = "macos"),
            target_arch = "aarch64",
            test
        ))]
        let s0 = crate::timing_state::test_support::Traced::new(s0, "keygen-s0-drop");
        let e = Zeroizing::new(core::array::from_fn::<_, M, _>(|_| x.poly_cbd1()));
        #[cfg(all(
            any(target_os = "linux", target_os = "macos"),
            target_arch = "aarch64",
            test
        ))]
        let e = crate::timing_state::test_support::Traced::new(e, "keygen-e-drop");
        // key shell on E(s): fixed-length accumulation over all 2048 trits.
        let mut energy = W0;
        for p in s0.iter() {
            for &c in &p.0 {
                energy += WS * (c * c) as u64;
            }
        }
        for p in e.iter() {
            for &c in &p.0 {
                energy += WE * (c * c) as u64;
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
            let reject = ct_lt_u64(energy, SHELL_LO) | ct_lt_u64(SHELL_HI, energy);
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
        // The secret-derived sum A0 s0 is built in place in a zeroizing owner,
        // one coefficient at a time; only b = A0 s0 + e is released.
        let b: [Poly; M] = core::array::from_fn(|r| {
            #[cfg_attr(test, allow(unused_mut))]
            let mut acc = Zeroizing::new(Poly::ZERO);
            #[cfg(all(
                any(target_os = "linux", target_os = "macos"),
                target_arch = "aarch64",
                test
            ))]
            let mut acc = crate::timing_state::test_support::Traced::new(acc, "keygen-acc-drop");
            for c in 0..ELL {
                let a = a0_ntt.spectral_poly(r, c);
                ring::add_pointwise_assign(&mut acc, &a, &s0_ntt[c]);
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
            // The core key is fixed. Expansion exhaustion returns without retrying it.
            // One draw: the first candidate seed. It is the last entropy request.
            let candidate_start = random32(rng)?;
            let encoded = crate::key_setup::prepare(&pk, &candidate_start)?;
            let seed: [u8; 32] = encoded[CORE_PK_BYTES..].try_into().unwrap();
            pk = encoded.to_vec();
            seed
        };
        let pk_hash = hashes::shake256_32(&pk);
        #[cfg(all(
            any(target_os = "linux", target_os = "macos"),
            target_arch = "aarch64",
            test
        ))]
        crate::timing_state::test_support::checkpoint("keygen-pack");
        let mut sk = Zeroizing::new(Vec::with_capacity(SK_BYTES));
        sk.extend_from_slice(&seed_a[..]);
        let mut packed = Zeroizing::new([0u8; 512]);
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
    interval: crate::ct_interval_transport::Prepared,
    // The signer never builds the sparse view: its construction branches on
    // every trit and allocates secret-length index lists.
    #[cfg(test)]
    // Runtime correlated transport uses prepared spectra/Gram data only.
    // Keep the dense secret for direct transport and independent test oracles.
    s_flat: Vector,
    correlations: crate::correlation::Key,
    b_energy: u64,
    prf: [u8; 32],
    pk: Vec<u8>,
}

impl Drop for ParsedSk {
    fn drop(&mut self) {
        #[cfg(all(
            any(target_os = "linux", target_os = "macos"),
            target_arch = "aarch64",
            test
        ))]
        crate::timing_state::test_support::observe("parsed-key-drop");
        self.prf.zeroize();
        self.b_energy.zeroize();
        #[cfg(test)]
        self.s_flat.zeroize();
        #[cfg(all(
            any(target_os = "linux", target_os = "macos"),
            target_arch = "aarch64",
            test
        ))]
        crate::timing_state::test_support::observe_erasure("prepared-secret-erased", || {
            let erased = self.prf.iter().all(|&x| x == 0) && self.b_energy == 0;
            let erased = erased && self.s_flat.iter().all(|&x| x == 0);
            erased
        });
        // The matrices and pk are public.
    }
}
impl ZeroizeOnDrop for ParsedSk {}

fn parse_sk(sk: &[u8]) -> Result<(ParsedSk, MatrixAh), Error> {
    let sk = crate::direct_ntt_profile::secret_body(sk)?;
    if sk.len() != SK_BYTES {
        return Err(Error::KeyFormat);
    }
    let seed_a: [u8; 32] = sk[..32].try_into().unwrap();
    #[cfg_attr(test, allow(unused_mut))]
    let mut trits = Zeroizing::new(encode::unpack_trits(&sk[32..544]).ok_or(Error::KeyFormat)?);
    #[cfg(all(
        test,
        any(target_os = "linux", target_os = "macos"),
        target_arch = "aarch64"
    ))]
    let mut trits = crate::timing_state::test_support::Traced::new(trits, "parse-trits-drop");
    let prf = Zeroizing::new(<[u8; 32]>::try_from(&sk[544..576]).unwrap());
    #[cfg(all(
        any(target_os = "linux", target_os = "macos"),
        target_arch = "aarch64",
        test
    ))]
    let prf = crate::timing_state::test_support::Traced::new(prf, "parse-prf-drop");
    let pk_hash: [u8; 32] = sk[576..608].try_into().unwrap();
    let selected_seed: [u8; 32] = sk[CORE_SK_BYTES..SK_BYTES].try_into().unwrap();
    let a0_ntt = crate::direct_ntt_profile::PublicMatrixNtt::expand(&seed_a);
    #[cfg_attr(test, allow(unused_mut))]
    let mut s_flat = Zeroizing::new([0i32; DIM]);
    #[cfg(all(
        any(target_os = "linux", target_os = "macos"),
        target_arch = "aarch64",
        test
    ))]
    let mut s_flat = crate::timing_state::test_support::Traced::new(s_flat, "parse-s_flat-drop");
    s_flat[0] = 1;
    s_flat[SEC..].copy_from_slice(&trits);
    let b_energy = transport::key_energy(&s_flat);
    // Key-format validity: constant outcome (in shell) for every honest key.
    {
        use crate::ct::ct_lt_u64;
        let bad = ct_lt_u64(b_energy, SHELL_LO) | ct_lt_u64(SHELL_HI, b_energy);
        if crate::ct::opaque_mask(bad) != 0 {
            return Err(Error::KeyFormat);
        }
    }
    // Leading key polynomial is exactly 1,0,...,0: public metric shift.
    let b_energy = b_energy - W0 + PROPOSAL_W0;
    // Prepare public A0 transforms once, retain exactly those columns in
    // the final matrix, and use them for the secret-key hash check.
    let mut mat = MatrixAh {
        rows: a0_ntt.into_rows(),
    };
    #[cfg_attr(test, allow(unused_mut))]
    let mut cols = Zeroizing::new([crate::compact_ring::CompactPoly::ZERO; ELL + 1]);
    #[cfg(all(
        any(target_os = "linux", target_os = "macos"),
        target_arch = "aarch64",
        test
    ))]
    let mut cols = crate::timing_state::test_support::Traced::new(cols, "parse-cols-drop");
    for c in 0..ELL {
        cols[c + 1].forward_from_i32(&s_flat[SEC + c * N..SEC + (c + 1) * N]);
    }
    #[cfg_attr(test, allow(unused_mut))]
    let mut error_spectra = Zeroizing::new([crate::compact_ring::CompactPoly::ZERO; M]);
    #[cfg(all(
        test,
        any(target_os = "linux", target_os = "macos"),
        target_arch = "aarch64"
    ))]
    let mut error_spectra =
        crate::timing_state::test_support::Traced::new(error_spectra, "parse-error-spectra-drop");
    for r in 0..M {
        error_spectra[r].forward_from_i32(&s_flat[ERR + r * N..ERR + (r + 1) * N]);
    }
    // Column zero is zero here. Four nonzero products obey the same five-term
    // accumulator bound; no Montgomery factor or coefficient order changes.
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
    #[cfg(all(
        any(target_os = "linux", target_os = "macos"),
        target_arch = "aarch64",
        test
    ))]
    crate::timing_state::test_support::checkpoint("parse-hash-ok");
    // Only after the public-key hash check succeeds, install -b spectra.
    spectral_b.install_negated(&mut mat.rows);
    Ok((
        ParsedSk {
            interval: crate::ct_interval_transport::Prepared::new(b_energy),
            correlations: {
                crate::correlation::Key::from_prepared_spectra(&s_flat, &cols, &error_spectra)
            },
            #[cfg(test)]
            s_flat: *s_flat,
            b_energy,
            prf: *prf,
            pk: pk_bytes,
        },
        mat,
    ))
}

/// Test-only reference of the postfilter cap checks on (z_h, r_e).
#[cfg(test)]
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
fn check_caps_ct(z_h: &[i32], r_e: &[i32]) -> u64 {
    crate::ct_lookup::check_caps(z_h, r_e)
}

/// Run preparation, signing and owner destruction under one timing guard.
/// The constructor, signer and destructor guards are nested inside it.
pub(crate) fn with_signing_guard<T>(
    operation: impl FnOnce() -> Result<T, Error>,
) -> Result<T, Error> {
    #[cfg(all(any(target_os = "linux", target_os = "macos"), target_arch = "aarch64"))]
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

/// Canonical core validation only; the value retains nothing.
pub(crate) struct PreparedCorePk;
impl PreparedCorePk {
    pub(crate) fn new(core: &[u8]) -> Result<Self, Error> {
        if core.len() != CORE_PK_BYTES {
            return Err(Error::KeyFormat);
        }
        encode::decode_b_into(&core[32..], |_, _| {}).ok_or(Error::KeyFormat)?;
        Ok(Self)
    }
}

impl PreparedPk {
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
            let prefixes = hashes::PublicPrefixes::from_scheduled(pk.to_vec(), owners);
            Ok(PreparedPk {
                mat,
                static_delta,
                prefixes,
            })
        }
    }
}

impl PreparedPk {
    fn from_parts(mat: MatrixAh, pk: Vec<u8>) -> Result<PreparedPk, Error> {
        if pk.len() != PK_BYTES {
            return Err(Error::KeyFormat);
        }
        let (static_delta, prefixes) = {
            let (flat, owners) =
                crate::dither_frame::expand_with_prefixes(&pk).map_err(|_| Error::KeyFormat)?;
            let rows = core::array::from_fn(|r| Poly(core::array::from_fn(|i| flat[r * N + i])));
            (rows, hashes::PublicPrefixes::from_scheduled(pk, owners))
        };
        Ok(PreparedPk {
            mat: Box::new(mat),
            static_delta: Box::new(static_delta),
            prefixes,
        })
    }
    /// Parsed canonical dither, borrowed without a per-call copy of the `[Poly; M]` array.
    /// Parsing does not certify the spread property of an imported key's matrix.
    pub(crate) fn static_dither(&self) -> &[Poly; M] {
        &self.static_delta
    }
    fn message_rep(&self, context: &[u8], msg: &[u8]) -> [u8; 64] {
        self.prefixes.message_rep(context, msg)
    }
    fn challenge_bytes(&self, mu: &[u8; 64], rho: &[u8; SALT_BYTES], labels: &[u8]) -> [u8; 32] {
        self.prefixes.challenge_bytes(mu, rho, labels)
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
    prefixes: crate::randomness::StreamPrefixes,
}

impl PreparedSk {
    #[cfg(all(
        any(target_os = "linux", target_os = "macos"),
        target_arch = "aarch64",
        test
    ))]
    pub(crate) fn secret_address(&self) -> usize {
        (&**self.secret as *const PreparedSecret) as usize
    }

    #[cfg(all(
        any(target_os = "linux", target_os = "macos"),
        target_arch = "aarch64",
        test
    ))]
    pub(crate) fn poison_secret_for_dit_test(&mut self) {
        self.secret.key.prf.fill(0xa5);
        self.secret.key.b_energy = 7;
        self.secret.key.s_flat.fill(9);
        assert!(self.secret.key.prf.iter().all(|&x| x != 0));
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_envelope
    }

    /// Prepare and allocate secret state under DIT. The returned owner holds
    /// only a heap pointer and public fields, so later moves copy no secrets.
    pub fn new(sk: &[u8]) -> Result<PreparedSk, Error> {
        // Enter before even parsing the envelope. Declared first so every local
        // secret, constructor-error cleanup and, with the feature `stack-wipe`, the
        // stack scrub finish before DIT is restored. When the guard cannot be
        // entered the function returns here, before any private work and without a
        // scrub.
        #[cfg(all(any(target_os = "linux", target_os = "macos"), target_arch = "aarch64"))]
        let _timing_state = crate::timing_state::Guard::enter()?;
        // Only with the feature `stack-wipe`. Declared second, so it is dropped
        // first: on return, on a key-format error and on unwinding it zeroes 393216
        // bytes of stack below this frame, where the frames of the import body and
        // of everything it calls lay. Not erased: registers, this frame, the frames
        // of its callers and anything deeper than the extent.
        #[cfg(feature = "stack-wipe")]
        let _stack_scrub = crate::ct_erase::StackScrub::<{ crate::ct_erase::IMPORT_SCRUB_WORDS }>;
        Self::new_unscrubbed(sk)
    }

    // The import body. With the feature `stack-wipe` it is out of line: an inlined
    // copy would put this frame, which holds copies of the parsed key, inside the
    // frame that holds the scrub, where it is not erased. Without the feature it
    // is always inlined into `new`, its only caller, so the default build has one
    // function.
    #[cfg_attr(feature = "stack-wipe", inline(never))]
    #[cfg_attr(not(feature = "stack-wipe"), inline(always))]
    fn new_unscrubbed(sk: &[u8]) -> Result<PreparedSk, Error> {
        #[cfg(all(
            any(target_os = "linux", target_os = "macos"),
            target_arch = "aarch64",
            test
        ))]
        crate::timing_state::test_support::observe("prepare-entry");
        let (key, mat) = parse_sk(sk)?;
        // The same matrix and hash the public verifier would derive from
        // pk_bytes: decode_b(encode_b(.)) is the identity on canonical digit
        // vectors, and parse_sk has already checked pk_hash against the
        // re-encoded public key bytes.
        let ppk = PreparedPk::from_parts(mat, key.pk.clone())?;
        let prefixes = crate::randomness::StreamPrefixes::new(&key.prf, &key.pk);
        #[cfg(all(
            any(target_os = "linux", target_os = "macos"),
            target_arch = "aarch64",
            test
        ))]
        crate::timing_state::test_support::checkpoint("prepare-exit");
        Ok(PreparedSk {
            public_envelope: crate::direct_ntt_profile::tag_public(&key.pk),
            secret: crate::guarded_drop::GuardedDrop::new(Box::new(PreparedSecret {
                key,
                prefixes,
            })),
            ppk,
        })
    }
}

#[cfg(test)]
mod ct_tests {
    use super::*;

    #[test]
    fn context_and_prepared_secret_key_are_send_and_sync() {
        fn send_sync<T: Send + Sync>() {}
        send_sync::<Ctx>();
        send_sync::<PreparedSk>();
    }

    #[test]
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

struct MatrixAh {
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
    #[cfg(test)]
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
        // A columns are already spectra: transform coefficient b only, exactly M=4 times.
        for row in &mut out.rows {
            row[0].forward_canonical();
        }
        Ok(out)
    }
    #[cfg(test)]
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
    #[cfg(test)]
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
    fn apply_into(&self, z: &Vector, delta: &[Poly; M], out: &mut [Poly; M]) {
        {
            let mut cols = Zeroizing::new([crate::compact_ring::CompactPoly::ZERO; ELL + 1]);
            self.fill_compact(z, &mut cols);
            for r in 0..M {
                crate::compact_ring::dot_compact_into(&self.rows[r], &cols, &mut out[r]);
                ring::intt(&mut out[r]);
                for i in 0..N {
                    debug_assert!((0..Q).contains(&out[r].0[i]) && (0..Q).contains(&delta[r].0[i]));
                    let x = out[r].0[i] + delta[r].0[i];
                    out[r].0[i] = x - Q * i32::from(x >= Q);
                }
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
    fn matrix_finish_reference(
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

#[cfg(all(all(target_arch = "aarch64", target_endian = "little"), test))]
mod matrix_reference_tests {
    use super::*;
    use crate::compact_ring::CompactPoly;
    #[test]
    fn private_commitment_all_rows_and_signed_ingress_match_original() {
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
                        154
                    } else if i < 5 * N {
                        1064
                    } else {
                        1355
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
            let mut cols = Zeroizing::new([CompactPoly::ZERO; ELL + 1]);
            matrix.fill_compact(&z, &mut cols);
            let expected = matrix.matrix_finish_reference(&cols, &delta);
            let actual = matrix.apply(&z, &delta);
            assert_eq!(actual, expected, "trial {trial}");
            // `matrix_finish_reference` has the body of the routine under
            // test, so the comparison above cannot detect a wrong product.
            // The schoolbook product of the coefficient forms can.
            let schoolbook: [Poly; M] = core::array::from_fn(|r| {
                let mut sum = delta[r];
                for c in 0..=ELL {
                    let mut input = Poly::ZERO;
                    input.0.copy_from_slice(&z[c * N..(c + 1) * N]);
                    input.reduce();
                    let mut coefficient = Poly::ZERO;
                    for i in 0..N {
                        coefficient.0[i] = i32::from(old_rows[r][c].0[i]);
                    }
                    ring::intt(&mut coefficient);
                    coefficient.reduce();
                    sum = sum.add(&ring::schoolbook(&coefficient, &input));
                }
                sum
            });
            assert_eq!(actual, schoolbook, "trial {trial}, schoolbook");
            let mut written = [Poly::ZERO; M];
            matrix.apply_into(&z, &delta, &mut written);
            assert_eq!(written, schoolbook, "trial {trial}, caller-owned output");
            assert_eq!(matrix.rows, old_rows);
            assert_eq!(z, old_z);
            assert_eq!(delta, old_delta);
            for row in actual {
                assert!(row.0.iter().all(|&v| (0..Q).contains(&v)));
            }
        }
    }
}

#[cfg(test)]
mod keygen_contract_tests {
    use super::*;
    use crate::EntropyError;
    struct Tape {
        x: Xof,
        calls: Vec<usize>,
    }
    impl Tape {
        fn new(seed: u8) -> Self {
            Self {
                x: Xof::new(b"phase880-keygen-contract", &[&[seed]]),
                calls: Vec::new(),
            }
        }
    }
    impl EntropySource for Tape {
        fn fill(&mut self, out: &mut [u8]) -> Result<(), EntropyError> {
            self.calls.push(out.len());
            self.x.fill(out);
            Ok(())
        }
    }
    #[test]
    fn setup_entropy_failure_does_not_retry_core() {
        #[cfg(all(any(target_os = "linux", target_os = "macos"), target_arch = "aarch64"))]
        let _timing_state = crate::timing_state::Guard::enter().unwrap();
        let ctx = Ctx::new();
        let mut baseline = Tape::new(0);
        keygen_with_entropy(&ctx, &mut baseline).unwrap();
        struct FailAfter {
            tape: Tape,
            limit: usize,
            calls: usize,
        }
        impl EntropySource for FailAfter {
            fn fill(&mut self, out: &mut [u8]) -> Result<(), EntropyError> {
                self.calls += 1;
                if self.calls > self.limit {
                    Err(EntropyError)
                } else {
                    self.tape.fill(out)
                }
            }
        }
        // The last request of key generation is the first dither seed; its failure is not retried.
        let keygen_ctx = keygen_context::KeygenCtx::new();
        let limit = baseline.calls.len() - 1;
        for keygen_only in [false, true] {
            let run = |rng: &mut FailAfter| {
                if keygen_only {
                    keygen_context::keygen_with_entropy(&keygen_ctx, rng)
                } else {
                    keygen_with_entropy(&ctx, rng)
                }
            };
            let mut rng = FailAfter {
                tape: Tape::new(0),
                limit,
                calls: 0,
            };
            assert!(matches!(run(&mut rng), Err(Error::RngFailure)));
            assert_eq!(rng.calls, limit + 1);
            // Control: one more permitted request suffices, and no other is made.
            let mut rng = FailAfter {
                tape: Tape::new(0),
                limit: limit + 1,
                calls: 0,
            };
            run(&mut rng).unwrap();
            assert_eq!(rng.calls, limit + 1);
        }
    }
}

#[path = "prepared_signer.rs"]
pub mod prepared_signer;

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
    #[test]
    fn constructor_application_matches_parent_for_seeded_public_matrices() {
        for case in 0..16u8 {
            let seed = core::array::from_fn(|i| case.wrapping_mul(37).wrapping_add(i as u8));
            let a = hashes::expand_a0(&seed);
            let b = core::array::from_fn(|r| {
                Poly(core::array::from_fn(|i| {
                    ((i * 173 + r * 997 + case as usize) % Q as usize) as i32
                }))
            });
            let old = parent(&a, &b);
            let new = MatrixAh::new(&a, &b);
            assert_eq!(new.rows, old.rows);
            let delta = core::array::from_fn(|r| {
                Poly(core::array::from_fn(|i| {
                    ((i * 73 + r * 39) % Q as usize) as i32
                }))
            });
            for mode in 0..4 {
                let z = core::array::from_fn(|i| match mode {
                    0 => 0,
                    1 => i32::MIN,
                    2 => i32::MAX,
                    _ => (i as i32 * 19) - 12000,
                });
                assert_eq!(new.apply(&z, &delta), old.apply(&z, &delta));
            }
        }
    }
}

#[cfg(test)]
mod direct_canonical_matrix_tests {
    use super::*;
    #[test]
    fn public_rows_match_independent_scalar_ntt() {
        for case in 0..32u8 {
            let seed = core::array::from_fn(|i| case.wrapping_mul(37).wrapping_add(i as u8));
            let digits: Vec<i32> = (0..M * N)
                .map(|i| match case {
                    0 => 0,
                    1 => Q - 1,
                    _ => ((i * 31 + case as usize * 97) % Q as usize) as i32,
                })
                .collect();
            let a = hashes::expand_a0(&seed);
            let b = core::array::from_fn(|r| Poly(core::array::from_fn(|i| digits[r * N + i])));
            let old = MatrixAh::new(&a, &b);
            let scalar_a = hashes::expand_a0_scalar(&seed);
            for r in 0..M {
                for c in 0..=ELL {
                    let mut p = if c == 0 {
                        Poly(core::array::from_fn(|i| (-digits[r * N + i]).rem_euclid(Q)))
                    } else {
                        scalar_a[r][c - 1]
                    };
                    crate::ring::ntt_scalar(&mut p);
                    assert_eq!(
                        old.rows[r][c],
                        crate::compact_ring::CompactPoly::from_canonical(&p)
                    );
                }
            }
        }
    }
    #[test]
    fn direct_public_import_preserves_wire_errors_and_rows() {
        for case in [0i32, 1, Q - 1] {
            let seed = [case as u8; 32];
            let digits = vec![case; M * N];
            let mut core = seed.to_vec();
            core.extend_from_slice(&encode::encode_b(&digits));
            PreparedCorePk::new(&core).unwrap();
            let actual = MatrixAh::from_spectral_b_packed_public(&seed, &core[32..]).unwrap();
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
            assert!(PreparedCorePk::new(&core[..core.len() - 1]).is_err());
            core.push(0);
            assert!(PreparedCorePk::new(&core).is_err());
        }
        let mut invalid = vec![255u8; CORE_PK_BYTES];
        invalid[..32].fill(0);
        assert!(PreparedCorePk::new(&invalid).is_err());
    }
}

#[cfg(test)]
mod direct_ntt_profile_tests {
    use super::*;
    #[test]
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
            for len in [0, 1, 13, 14, 15, 1741, 1743] {
                let mut bad = tagged.clone();
                bad.resize(len, 0);
                assert!(PreparedPk::new(&bad).is_err());
            }
            for len in [0, 1, 13, 14, 15, 653, 655] {
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
            for len in [0, 1, 1663, 1665, 1696, 1728, 1742] {
                assert!(MatrixAh::from_direct_ntt_packed_public(&[7; 32], &vec![0; len]).is_err());
            }
            for position in [0, M * N / 2, M * N - 1] {
                for digit in Q..8192 {
                    let mut bytes = vec![0u8; 1664];
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
    fn spectral_b_import_matches_coefficient_matrix_and_public_relation() {
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
            PreparedCorePk::new(&core).unwrap();
            let actual = MatrixAh::from_spectral_b_packed_public(&seed, &core[32..]).unwrap();
            let coefficients: Vec<i32> = b.iter().flat_map(|p| p.0).collect();
            let reference = MatrixAh::from_direct_ntt_public(&seed, &coefficients);
            assert_eq!(actual.rows, reference.rows);
            for r in 0..M {
                let mut recovered = owner.spectra()[r];
                ring::intt(&mut recovered);
                assert_eq!(recovered, b[r]);
            }
            // Compare the public relation used by verification on coefficient heads.
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
    #[test]
    fn spectral_b_wire_reconstruction_preserves_coefficient_secret_validation() {
        #[cfg(all(any(target_os = "linux", target_os = "macos"), target_arch = "aarch64"))]
        let _timing_state = crate::timing_state::Guard::enter().unwrap();
        struct Tape(Xof);
        impl EntropySource for Tape {
            fn fill(&mut self, out: &mut [u8]) -> Result<(), crate::EntropyError> {
                self.0.fill(out);
                Ok(())
            }
        }
        let ctx = Ctx::new();
        let mut tape = Tape(Xof::new(b"spectral-b-key-test-v1", &[]));
        let pair = keygen_with_entropy(&ctx, &mut tape).unwrap();
        let sk = PreparedSk::new(&pair.sk).unwrap();
        let pk = PreparedPk::new(&pair.pk).unwrap();
        assert_eq!(sk.public_key(), pair.pk.as_slice());
        assert_eq!(sk.ppk.mat.rows, pk.mat.rows);
        let secret = crate::direct_ntt_profile::secret_body(&pair.sk).unwrap();
        let body = crate::direct_ntt_profile::public_body(&pair.pk).unwrap();
        assert_eq!(&secret[576..608], &hashes::shake256_32(body));
        // Two-bit trit encoding rejects code3; zero trits violate the shell.
        let mut bad = pair.sk.to_vec();
        bad[14 + 32] = 255;
        assert!(PreparedSk::new(&bad).is_err());
        let mut bad = pair.sk.to_vec();
        bad[14 + 32..14 + 544].fill(0);
        assert!(PreparedSk::new(&bad).is_err());
        let mut bad = pair.sk.to_vec();
        bad[14 + 576] ^= 1;
        assert!(PreparedSk::new(&bad).is_err());
    }
}

#[cfg(test)]
mod common_public_preparation_tests {
    use super::*;
    #[test]
    fn common_public_malformed_never_expands_and_reused_matrix_matches() {
        let body = vec![0u8; PK_BYTES];
        let tagged = crate::direct_ntt_profile::tag_public(&body);
        for index in [0usize, 511, 1023] {
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
        for len in [0, 13, 14, 1741, 1743] {
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
            PreparedCorePk::new(&body[..CORE_PK_BYTES]).unwrap();
            let mat = MatrixAh::from_spectral_b_packed_public(
                body[..32].try_into().unwrap(),
                &body[32..CORE_PK_BYTES],
            )
            .unwrap();
            let reused = PreparedPk::from_parts(mat, body).unwrap();
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

#[path = "rice_verify.rs"]
pub mod rice_verify;

#[path = "keygen_context.rs"]
pub mod keygen_context;

#[cfg(all(test, target_arch = "aarch64"))]
include!("keyprep_tests.rs");

// The shared constructor tests name the core-matrix route the way Pretzel-(5,5) does.
#[cfg(test)]
fn prepare_core_matrix(core: &[u8]) -> Result<MatrixAh, Error> {
    PreparedCorePk::new(core)?;
    MatrixAh::from_spectral_b_packed_public(core[..32].try_into().unwrap(), &core[32..])
}
#[cfg(test)]
#[path = "prepk_direct_tests.rs"]
mod prepk_direct_tests;

#[cfg(test)]
#[path = "public_matrix_prepared_tests.rs"]
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
#[path = "public_preparation_wire_tests.rs"]
mod preparation_wire_tests;

#[cfg(test)]
fn sign_for_preparation_test(
    ctx: &Ctx,
    sk: &PreparedSk,
    context: &[u8],
    message: &[u8],
    entropy: &mut impl EntropySource,
    scratch: &mut SigningScratch,
) -> Result<(Vec<u8>, u32), Error> {
    prepared_signer::sign_rice_prepared_using_scratch(ctx, sk, context, message, entropy, scratch)
}
