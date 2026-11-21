//! Mathematical parameters of Pretzel-(3,3).
//! `PROFILE_ID` below is the format identifier `dither_frame::PROFILE`.

/// Modulus.
pub const Q: i32 = 7681;
/// Ring degree.
pub const N: usize = 256;
/// Module shape (ell, m).
pub const ELL: usize = 3;
pub const M: usize = 3;
/// Total coordinates of a full response: leading + secret + error blocks.
pub const DIM: usize = N + ELL * N + M * N; // 1792

/// Energy weights (616/s_i)^2 for s = (4, 44, 56). The theta below has -1/ln(theta) of about
/// 834803.25, not 2 * 616^2 = 758912, so the s_i are not the widths of the sampled law.
pub const W0: u64 = 23716;
pub const WS: u64 = 196;
pub const WE: u64 = 121;
/// Proposal metric only. W0 and SHELL_* keep the accepted key law.
pub const PROPOSAL_W0: u64 = 9216;
pub const PROPOSAL_SHELL_LO: u64 = SHELL_LO - W0 + PROPOSAL_W0;
pub const PROPOSAL_SHELL_HI: u64 = SHELL_HI - W0 + PROPOSAL_W0;
const _: () = assert!(PROPOSAL_SHELL_LO == 80343 && PROPOSAL_SHELL_HI == 181545);

/// Lower key-shell cutoff (keygen restarts below it, like the upper cap).
pub const SHELL_LO: u64 = 94_843;
pub const SHELL_HI: u64 = 196_045;
/// Bound on the weighted inner products of the mask with the rotated key. Only test code
/// reads it: the test oracle of `correlation.rs` requires `P > 2 * SHELL_DOT_BOUND` and
/// asserts the bound.
/// 282 is 154, the largest leading value in the sampler's table, plus 128 updates
/// (tested in `ct_rarequeue.rs`); the signer of this crate has 72 slots, so at most 72
/// updates occur and the bound is valid but not tight.
/// 1483 is 1355 + 128, where 1355 is the largest error value
/// in the tables under the theta below; the secret table ends at 1064. Each update moves a
/// coordinate by at most 1. The product bounds the inner product for every key in the
/// shell: the leading polynomial of a key is 1, which gives the first term, and for a
/// ternary key the weighted count of nonzero coefficients above the leading weight, 196
/// for each secret one and 121 for each error one, is at most `SHELL_HI - W0`.
/// The signer holds less than the table values: it samples through alias and tree tables
/// built from the 192-bit prefixes of the table bounds, produces a value only for a draw
/// strictly inside the cell between two consecutive prefixes, and aborts the attempt on a
/// draw on a cell boundary. So it emits at most 108 (leading), 739 (secret) and 937
/// (error), and an aborted attempt holds at most 744 and 946.
pub const SHELL_DOT_BOUND: u64 = PROPOSAL_W0 * 282 + 1483 * (SHELL_HI - W0);
const _: () = assert!(SHELL_DOT_BOUND == 258162819 && SHELL_DOT_BOUND < (1 << 31));

/// Quantizer levels.
pub const LQ: i32 = 34;

/// Generic coefficient caps of the signer: the bounds of its cap test and of the score tables.
/// The paper states them and the format limits below; the two layers are kept apart.
pub const CAP_INF_HEAD: i32 = 288;
pub const CAP_INF_RES: i32 = 451;
/// Limits of the signature format: what the encoding carries and the verifier accepts (leading
/// head polynomial, other head coefficients, residual). The paper states them.
pub const FORMAT_HEAD_LIMIT_LEAD: i32 = 31;
pub const FORMAT_HEAD_LIMIT: i32 = 255;
pub const FORMAT_RES_LIMIT: i32 = 450;
const _: () = assert!(FORMAT_HEAD_LIMIT_LEAD <= CAP_INF_HEAD);
const _: () = assert!(FORMAT_HEAD_LIMIT <= CAP_INF_HEAD);
const _: () = assert!(FORMAT_RES_LIMIT <= CAP_INF_RES);
/// Squared Euclidean caps.
pub const CAP_EUC2_HEAD: u64 = 1593 * 1593;
pub const CAP_EUC2_RES: u64 = 3068 * 3068;
/// Q20 secant cap.
pub const CAP_Q20: u64 = 30_850_912;
/// Hint alphabet bound.
pub const HINT_MAX: i32 = 3;

pub const ENV_NUM: u64 = 65_544;
pub const ENV_DEN: u64 = 65_536;

/// theta numerator, little-endian u64 limbs of the specified dyadic constant
/// 0xffffebe71e0d482af9a42878e0fbcb58f7663bf7f0afda571e6a48849f6572a5
/// (paper, Appendix H.1; the same base as Pretzel-(4,4)).
pub const THETA_NUM_LIMBS: [u64; 4] = [
    0x1e6a48849f6572a5,
    0xf7663bf7f0afda57,
    0xf9a42878e0fbcb58,
    0xffffebe71e0d482a,
];

/// Wire sizes.
pub const SALT_BYTES: usize = 32;
pub const RESP_FIELD_BYTES: usize = 1174;
pub const HINT_FIELD_BYTES: usize = 113;
// 1319: the salt and the two fields of the entropy coder. Signatures have
// `SIGNATURE_BYTES` (1160) bytes.
pub const SIG_BYTES: usize = SALT_BYTES + RESP_FIELD_BYTES + HINT_FIELD_BYTES;
pub const PK_B_BYTES: usize = M * N * 13 / 8; // 1248; no padding bits
pub const CORE_PK_BYTES: usize = 32 + PK_B_BYTES; // 1280
pub const PK_BYTES: usize = CORE_PK_BYTES + 32; // selected dither seed
pub const TRIT_COUNT: usize = (ELL + M) * N;
pub const TRIT_BYTES: usize = TRIT_COUNT / 4;
pub const CORE_SK_BYTES: usize = 32 + TRIT_BYTES + 32 + 32; // seed_A + trits + prf + augmented pk hash
pub const SK_BYTES: usize = CORE_SK_BYTES + 32; // selected public dither seed

/// Signing gives up after this many attempts (paper, Appendix H.1).
pub const MAX_ATTEMPTS: u32 = 512;

pub const PROFILE_ID: &[u8] = crate::dither_frame::PROFILE;

/// Domain separators (all XOF parts are u64-length-prefixed).
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

/// Exported key envelope sizes; PK_BYTES/SK_BYTES remain canonical body sizes.
pub const PUBLIC_KEY_WIRE_BYTES: usize = 14 + PK_BYTES;
pub const SECRET_KEY_WIRE_BYTES: usize = 14 + SK_BYTES;
