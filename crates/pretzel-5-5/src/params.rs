// Parameters of Pretzel-(5,5); the paper gives them in Appendix I.1.

/// Modulus.
pub const Q: i32 = 7681;
/// Ring degree.
pub const N: usize = 256;
/// Module shape (ell, m).
pub const ELL: usize = 5;
pub const M: usize = 5;
/// Total coordinates of a full response: leading + secret + error blocks.
pub const DIM: usize = N + ELL * N + M * N; // 2816

/// Weighted squared norm weights (616/s_i)^2 for s = (4, 44, 56). These s_i were the widths
/// under an earlier base, e^{-1/(2 * 616^2)}; the theta below has -1/ln(theta) of about
/// 1113071.17, not 758912.
pub const W0: u64 = 23716;
pub const WS: u64 = 196;
pub const WE: u64 = 121;
/// Proposal metric only. W0 and SHELL_* keep the accepted key law.
pub const PROPOSAL_W0: u64 = 9216;
pub const PROPOSAL_SHELL_LO: u64 = SHELL_LO - W0 + PROPOSAL_W0;
pub const PROPOSAL_SHELL_HI: u64 = SHELL_HI - W0 + PROPOSAL_W0;
const _: () = assert!(PROPOSAL_SHELL_LO == 131557 && PROPOSAL_SHELL_HI == 292635);

/// Lower key-shell cutoff (keygen restarts below it, like the upper cap).
pub const SHELL_LO: u64 = 146_057;
pub const SHELL_HI: u64 = 307_135;
/// Dot bound: initial leading cap 168 plus at most 128 unit-key rotations.
/// For integer key coefficients |s_i| <= s_i^2; base major cap 1462 plus 128 Gram updates
/// gives 1590 times the major key weighted squared norm.
pub const SHELL_DOT_BOUND: u64 = PROPOSAL_W0 * 296 + 1590 * (SHELL_HI - W0);
const _: () = assert!(SHELL_DOT_BOUND == 453364146 && SHELL_DOT_BOUND < (1 << 31));

/// Quantizer levels.
pub const LQ: i32 = 64;

/// Generic coefficient caps of the signer: the bounds of its cap test and of the score tables.
/// The paper states them and the format limits below; the two layers are kept apart.
pub const CAP_INF_HEAD: i32 = 288;
pub const CAP_INF_RES: i32 = 451;
/// Limits of the signature format: what the encoding carries and the verifier accepts (the first
/// 256 head coefficients, the other head coefficients, the residuals). The paper states them.
pub const FORMAT_HEAD_LIMIT_LEAD: i32 = 95;
pub const FORMAT_HEAD_LIMIT: i32 = 288;
pub const FORMAT_RES_LIMIT: i32 = 450;
const _: () = assert!(FORMAT_HEAD_LIMIT_LEAD <= FORMAT_HEAD_LIMIT);
const _: () = assert!(FORMAT_HEAD_LIMIT <= CAP_INF_HEAD);
const _: () = assert!(FORMAT_RES_LIMIT <= CAP_INF_RES);
/// Squared Euclidean caps.
pub const CAP_EUC2_HEAD: u64 = 2150 * 2150;
pub const CAP_EUC2_RES: u64 = 3170 * 3170;
/// Q20 secant cap.
pub const CAP_Q20: u64 = 40_741_973;

pub const ENV_NUM: u64 = 65_586;
pub const ENV_DEN: u64 = 65_536;

/// theta numerator, little-endian u64 limbs of the specified dyadic constant
/// 0xfffff0ed5689f6203b3b1e5aa8bcd882b98cacf9f483e3c156cfb663778c15fb
/// (paper, Appendix I.1).
pub const THETA_NUM_LIMBS: [u64; 4] = [
    0x56cfb663778c15fb,
    0xb98cacf9f483e3c1,
    0x3b3b1e5aa8bcd882,
    0xfffff0ed5689f620,
];

/// Signature field sizes. Labels are encoded inside the response field.
pub const RESP_FIELD_BYTES: usize = crate::signature_codec::HEAD_BYTES;
pub const HINT_FIELD_BYTES: usize = crate::signature_codec::HINT_BYTES;
pub const SIG_BYTES: usize = crate::signature_codec::SIGNATURE_BYTES;

/// Salt length.
pub const SALT_BYTES: usize = 32;
pub const PK_B_BYTES: usize = M * N * 13 / 8; // 2080; no padding bits
pub const CORE_PK_BYTES: usize = 32 + PK_B_BYTES; // 2112
pub const PK_BYTES: usize = CORE_PK_BYTES + 32; // dither seed
pub const TRIT_COUNT: usize = (ELL + M) * N;
pub const TRIT_BYTES: usize = TRIT_COUNT / 4;
pub const CORE_SK_BYTES: usize = 32 + TRIT_BYTES + 32 + 32; // seed_A + trits + prf + augmented pk hash
pub const SK_BYTES: usize = CORE_SK_BYTES + 32; // public dither seed

/// Signing gives up after this many attempts, and key generation after this many
/// key candidates (paper, Appendix I.1).
pub const MAX_ATTEMPTS: u32 = 512;

pub const PROFILE_ID: &[u8] = crate::dither_frame::PROFILE;

/// Domain separators (all XOF parts are u64-length-prefixed). The names are historical.
/// `DOM_KEY`, `DOM_MSG` and `DOM_CHAL` enter key derivation, the message hash and the challenge
/// hash: changing one changes keys or signatures. `DOM_SALT`, the three `DOM_MASK_*`,
/// `DOM_TRANSPORT` and `DOM_DUMMY` have no user in this crate.
pub const DOM_MATRIX: &[u8] = b"LILT-AC-3:matrix";
pub const DOM_KEY: &[u8] = b"LILT-AC-3:key";
pub const DOM_MSG: &[u8] = b"LILT-AC-3:msg";
pub const DOM_DITH: &[u8] = b"LILT-DITH-v2";
pub const DOM_CHAL: &[u8] = b"LILT-AC-3:chal";
pub const DOM_SALT: &[u8] = b"LILT-AC-3:salt";
pub const DOM_ATTEMPT: &[u8] = b"LILT-AC-3:attempt";
pub const DOM_MASK_LEAD: &[u8] = b"LILT-RQ40-LM-1:mask-lead";
pub const DOM_MASK_SEC: &[u8] = b"LILT-RQ40-LM-1:mask-secret";
pub const DOM_MASK_ERR: &[u8] = b"LILT-RQ40-LM-1:mask-error";
pub const DOM_TRANSPORT: &[u8] = b"LILT-AC-3:transport";
pub const DOM_DUMMY: &[u8] = b"LILT-AC-3:dummy";

/// Not used by this crate, which has no `mask-norm-check` feature. The figures below are
/// those of Pretzel-(4,4) (2304 coordinates); this parameter set has 2816 coordinates.
/// Mask weighted squared norm bounds for the `mask-norm-check` hardening. E(y) has mean
/// 874266619 under the ideal truncated discrete mask law (2304 coordinates,
/// weights 23716 / 196 / 121, dyadic theta, CDT supports).
/// log2 `Pr[E < LO]` <= -171.28
/// and log2 `Pr[E > HI]` <= -171.02, i.e. at most 2^-170 per tail per attempt.
/// The check conditions the mask law by that removed mass; over at most 512
/// attempts per call and 2^32 calls the additive replacement term is at most
/// 2^-128. Transfer to the
/// implemented mask-or-abort law adds the per-attempt Gaussian implementation
/// distance (below 2^-296). Coverage is limited to the weighted squared norm band: the
/// zero mask and every constant mask of absolute value at most 9 are rejected,
/// a constant mask of even value 12 (weighted squared norm 921010176) is not; honest masks
/// fall outside the band with the tiny but positive probability above.
pub const MASK_WEIGHTED_SQ_NORM_LO: u64 = 535_000_000;
pub const MASK_WEIGHTED_SQ_NORM_HI: u64 = 1_333_000_000;

/// Exported key envelope sizes; PK_BYTES/SK_BYTES remain canonical body sizes.
pub const PUBLIC_KEY_WIRE_BYTES: usize = 14 + PK_BYTES;
pub const SECRET_KEY_WIRE_BYTES: usize = 14 + SK_BYTES;
