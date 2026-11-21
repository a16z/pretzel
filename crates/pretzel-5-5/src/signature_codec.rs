//! 1908-byte absolute-label field codec.
//!
//! Private admission has fixed loop bounds and addresses. Encoding is called
//! only after that admission, under the accepted-packet premise.
//! Public verification decodes the released bytes; the signer does not verify
//! its output before release.
//! Nothing here establishes constant-time behaviour or erasure of the compiled code.

pub const HEAD_BYTES: usize = 1876;
pub const HINT_BYTES: usize = 0;
pub const SIGNATURE_BYTES: usize = 32 + HEAD_BYTES;
pub const HEAD_COEFFICIENTS: usize = 1536;
pub const LABELS: usize = 1280;
pub const HEAD_EXCEPTIONS: usize = 40;
pub const LABEL_EXCEPTIONS: usize = 16;
const Q: i32 = 7681;
const MIDDLE: usize = 192;
const HEAD_COUNT: usize = 1472;
const HEAD_RECORDS: usize = 1473;
const LOCAL_LOW: usize = 1533;
const LOCAL_COUNT: usize = 1853;
const LOCAL_RECORDS: usize = 1854;

// Identity value barrier.
// SAFETY: comment-only assembly leaves its initialized register unchanged;
// it accesses no memory/stack and preserves flags. Deliberately not pure.
#[inline(always)]
fn opaque_mask(mut value: u64) -> u64 {
    // SAFETY: The AArch64 gate of build.rs selects a supported register class. Comment-only asm preserves the
    // initialized inout value, memory, stack and flags; all register effects are declared.
    unsafe {
        core::arch::asm!("/* {value} */",value=inout(reg)value,options(nomem,nostack,preserves_flags));
    }
    value
}

// Public const center, used by public recovery. private_index recomputes it
// with barriered indicators.

const fn center(label: i32) -> i32 {
    120 * label + 60 + (((label != 0) & (label % 2 == 0)) as i32)
}

// Private arithmetic rank map, without a private table lookup.
// Every private predicate is barriered at its producer before composition.
#[inline(always)]
#[cfg(test)]
// Keep the explicit wire width conversion shared with reference variants.
#[allow(clippy::useless_conversion)]
fn private_index(label: i32, residual: i32) -> u32 {
    let private_center = 120 * label
        + 60
        + ((opaque_mask(u64::from(label != 0)) & opaque_mask(u64::from(label % 2 == 0))) as i32);
    let reflected = private_center - 2 * residual;
    let below = opaque_mask(u64::from(reflected < 0)) as i32;
    let above = opaque_mask(u64::from(reflected >= Q)) as i32;
    let endpoint = reflected + Q * (below - above);
    let shifted = endpoint + 59;
    let count = shifted / 120;
    let correction = (opaque_mask(u64::from(count > 1))
        & opaque_mask(u64::from((count & 1) != 0))
        & opaque_mask(u64::from(shifted == 120 * count))) as i32;
    let prefix = count - correction + 64 * (above - below);
    let negative = opaque_mask(((residual >> 31) & 1) as u64) as i32;
    ((2 * negative - 1) * (prefix - label) - negative) as u32
}

/// Fixed-range private admission. Only the final mask controls caller abort.
/// Every private comparison is an opaque 0/1 indicator before composition.
/// The caller owns and retires `local` on rejection, error and unwind.
/// Norms, secant, parity and challenge checks remain caller responsibilities.
#[cfg(test)]
// Keep the explicit wire width conversion shared with reference variants.
#[allow(clippy::useless_conversion)]
fn capacity_mask_scalar(
    head: &[i32],
    labels: &[i32; LABELS],
    residual: &[i32; LABELS],
    local: &mut [i32; LABELS],
) -> u64 {
    assert_eq!(head.len(), HEAD_COEFFICIENTS);
    let mut failed = 0u64;
    let mut head_count = 0usize;
    let mut local_count = 0usize;
    for (i, &value) in head.iter().enumerate() {
        let (cap, half) = if i < 256 { (95, 32) } else { (288, 128) };
        failed |= opaque_mask(u64::from(value.unsigned_abs() > cap));
        head_count += (opaque_mask(u64::from(value < -half))
            | opaque_mask(u64::from(value >= half))) as usize;
    }
    for i in 0..LABELS {
        let valid = opaque_mask(u64::from(labels[i] >= 0))
            & opaque_mask(u64::from(labels[i] < 64))
            & opaque_mask(u64::from(residual[i].unsigned_abs() <= 450));
        failed |= valid ^ 1;
        let mask = opaque_mask(0u64.wrapping_sub(valid)) as i32;
        let rank = private_index(labels[i] & mask, residual[i] & mask);
        local[i] = rank as i32;
        failed |= opaque_mask(u64::from(rank >= 8));
        local_count += opaque_mask(u64::from(rank >= 4)) as usize;
    }
    failed |= opaque_mask(u64::from(head_count > HEAD_EXCEPTIONS));
    failed |= opaque_mask(u64::from(local_count > LABEL_EXCEPTIONS));
    opaque_mask(0u64.wrapping_sub(1 - failed))
}

// Width and bit positions are public. The largest field width is 12.
// Keep the explicit wire width conversion shared with reference variants.
#[allow(clippy::useless_conversion)]
fn read_field(bytes: &[u8], bit: usize, width: usize) -> u32 {
    let at = bit / 8;
    let shift = bit % 8;
    let mut value = u32::from(bytes[at]) >> shift;
    if shift + width > 8 {
        value |= u32::from(bytes[at + 1]) << (8 - shift);
    }
    if shift + width > 16 {
        value |= u32::from(bytes[at + 2]) << (16 - shift);
    }
    value & ((1 << width) - 1)
}

fn write_field(bytes: &mut [u8], bit: usize, width: usize, value: u32) {
    let at = bit / 8;
    let shift = bit % 8;
    let value = (value & ((1 << width) - 1)) << shift;
    bytes[at] |= value as u8;
    if shift + width > 8 {
        bytes[at + 1] |= (value >> 8) as u8;
    }
    if shift + width > 16 {
        bytes[at + 2] |= (value >> 16) as u8;
    }
}

/// Encode only after the private admission and abort decision.
/// Packing uses value-dependent branches and addresses after admission.
/// There are no value-dependent asserts or failure returns. Bounded append
/// guards also keep invalid component-test inputs inside the output owner.
#[cfg(test)]
// Keep the explicit wire width conversion shared with reference variants.
#[allow(clippy::useless_conversion)]
pub(crate) fn encode_admitted_scalar(
    head: &[i32],
    local: &[i32; LABELS],
    response: &mut [u8],
    hint: &mut [u8],
) {
    assert_eq!(head.len(), HEAD_COEFFICIENTS);
    assert_eq!(response.len(), HEAD_BYTES);
    assert!(hint.is_empty());
    response.fill(0);
    pack_lows(head, local, response);
    let mut count = 0usize;
    for (i, &value) in head.iter().enumerate() {
        let half = if i < 256 { 32 } else { 128 };
        if i < 256 {
        } else {
            response[MIDDLE + i - 256] = value as u8;
        }
        if (value < -half) | (value >= half) {
            if count < HEAD_EXCEPTIONS {
                let record = (i as u32) | (u32::from(value >= half) << 11);
                write_field(response, 8 * HEAD_RECORDS + 12 * count, 12, record);
            }
            count += 1;
        }
    }
    response[HEAD_COUNT] = count as u8;
    count = 0;
    for (i, &rank) in local.iter().enumerate() {
        if rank >= 4 {
            if count < LABEL_EXCEPTIONS {
                write_field(response, 8 * LOCAL_RECORDS + 11 * count, 11, i as u32);
            }
            count += 1;
        }
    }
    response[LOCAL_COUNT] = count as u8;
}

/// Encodes an admitted packet; forwards to `encode_admitted_aux`.
pub(crate) fn encode_admitted(
    head: &[i32],
    local: &[i32; LABELS],
    response: &mut [u8],
    hint: &mut [u8],
) {
    encode_admitted_aux(head, local, response, hint);
}

const LOCAL_LOW_TABLE: [[u8; 4]; 256] = {
    let mut table = [[0; 4]; 256];
    let mut i = 0;
    while i < 256 {
        let mut j = 0;
        while j < 4 {
            table[i][j] = ((i >> (2 * j)) & 3) as u8;
            j += 1;
        }
        i += 1;
    }
    table
};

/// Parse public fields. Context-specific missing ranks are rejected later by
/// public recovery, after the caller recomputes the full context.
/// Wrong length or oversized counts leave both outputs unchanged. Other
/// errors retain writes made before the first failing record or cap check.
// Keep the explicit wire width conversion shared with reference variants.
#[allow(clippy::useless_conversion)]
// Preserve the accepted four-field extraction schedule.
#[allow(clippy::needless_range_loop)]
pub(crate) fn decode_fields(
    bytes: &[u8],
    head: &mut [i32; HEAD_COEFFICIENTS],
    local: &mut [u8; LABELS],
) -> Result<(), ()> {
    if bytes.len() != HEAD_BYTES {
        return Err(());
    }
    let head_count = usize::from(bytes[HEAD_COUNT]);
    let local_count = usize::from(bytes[LOCAL_COUNT]);
    if head_count > HEAD_EXCEPTIONS || local_count > LABEL_EXCEPTIONS {
        return Err(());
    }
    // Four signed six-bit values occupy exactly three bytes, no overread.
    for (input, output) in bytes[..192]
        .chunks_exact(3)
        .zip(head[..256].chunks_exact_mut(4))
    {
        let word = u32::from(input[0]) | (u32::from(input[1]) << 8) | (u32::from(input[2]) << 16);
        for j in 0..4 {
            output[j] = ((((word >> (6 * j)) & 63) as i32) ^ 32) - 32;
        }
    }
    for i in 0..1280 {
        head[256 + i] = i32::from(bytes[MIDDLE + i] as i8);
    }
    let mut previous = None;
    for slot in 0..HEAD_EXCEPTIONS {
        let record = read_field(bytes, 8 * HEAD_RECORDS + 12 * slot, 12);
        if slot >= head_count {
            if record != 0 {
                return Err(());
            }
            continue;
        }
        let position = (record & 2047) as usize;
        if position >= HEAD_COEFFICIENTS || previous.is_some_and(|p| position <= p) {
            return Err(());
        }
        let (step, cap) = if position < 256 {
            (64, crate::params::FORMAT_HEAD_LIMIT_LEAD as u32)
        } else {
            (256, crate::params::FORMAT_HEAD_LIMIT as u32)
        };
        let correction = if record & 2048 != 0 { step } else { -step };
        let corrected = head[position] + correction;
        if corrected.unsigned_abs() > cap {
            return Err(());
        }
        head[position] = corrected;
        previous = Some(position);
    }
    // Uncorrected low values already satisfy their caps. A unique correction
    // moves outside the low range, so there is no second encoding of a value.
    for (byte, output) in bytes[LOCAL_LOW..LOCAL_COUNT]
        .iter()
        .zip(local.chunks_exact_mut(4))
    {
        output.copy_from_slice(&LOCAL_LOW_TABLE[usize::from(*byte)]);
    }
    previous = None;
    for slot in 0..LABEL_EXCEPTIONS {
        let position = read_field(bytes, 8 * LOCAL_RECORDS + 11 * slot, 11) as usize;
        if slot >= local_count {
            if position != 0 {
                return Err(());
            }
            continue;
        }
        if position >= LABELS || previous.is_some_and(|p| position <= p) {
            return Err(());
        }
        local[position] += 4;
        previous = Some(position);
    }
    Ok(())
}

pub(crate) struct DecodedHead<'a>(&'a [i32; HEAD_COEFFICIENTS]);
impl DecodedHead<'_> {
    pub(crate) fn values(&self) -> &[i32; HEAD_COEFFICIENTS] {
        self.0
    }

    pub(crate) fn write_canonical_column(&self, column: usize, out: &mut [i16; 256]) {
        assert!(column < 6);
        for (i, value) in out.iter_mut().enumerate() {
            let x = self.0[column * 256 + i];
            *value = (x + ((x >> 31) & Q)) as i16;
        }
    }
}
// `public_response_ntt.rs`, compiled into this crate from the Pretzel-(4,4) backend by `#[path]`,
// calls the decoded head by its name in that crate.
pub(crate) use self::DecodedHead as DecodedRiceHead;

pub(crate) struct DecodedLocalPlanes([[u8; 256]; 5]);
impl DecodedLocalPlanes {
    pub(crate) fn row(&self, row: usize) -> &[u8; 256] {
        &self.0[row]
    }
}

pub(crate) fn decode_fields_borrowed<'a>(
    bytes: &[u8],
    head: &'a mut [i32; HEAD_COEFFICIENTS],
) -> Result<(DecodedHead<'a>, DecodedLocalPlanes), ()> {
    let mut rows = DecodedLocalPlanes([[0; 256]; 5]);
    let local: &mut [u8; LABELS] = rows.0.as_flattened_mut().try_into().unwrap();
    decode_fields(bytes, head, local)?;
    let decoded = DecodedHead(head);
    Ok((decoded, rows))
}

// Input is the difference of two canonical residues.
#[inline(always)]
const fn centered(value: i32) -> i32 {
    value + Q * ((value < -3840) as i32) - Q * ((value > 3840) as i32)
}

// Public lookup only. Each entry packs an absolute label and its residual
// magnitude. A missing eighth local label has the sentinel 0xffff.

const fn public_table() -> [[u16; 8]; Q as usize] {
    let mut table = [[u16::MAX; 8]; Q as usize];
    let mut x = 0;
    while x < Q {
        let base = (64 * x) / Q;
        let r = center(base) - x;
        let mut left = (base - ((r >= 0) as i32)) & 63;
        let mut right = (left + 1) & 63;
        let mut i = 0;
        while i < 8 {
            let a = centered(center(left) - x);
            let b = centered(center(right) - x);
            // Equal distances prefer the negative residual.
            let (label, residual) = if -a <= b {
                let label = left;
                left = (left - 1) & 63;
                (label, a)
            } else {
                let label = right;
                right = (right + 1) & 63;
                (label, b)
            };
            let magnitude = residual.unsigned_abs();
            if magnitude <= crate::params::FORMAT_RES_LIMIT as u32 {
                table[x as usize][i] = (label as u16) | ((magnitude as u16) << 6);
            }
            i += 1;
        }
        x += 1;
    }
    table
}
static PUBLIC_RECOVERY: [[u16; 8]; Q as usize] = public_table();

// Keep the explicit wire width conversion shared with reference variants.
#[allow(clippy::useless_conversion)]
pub(crate) fn recover(x: i32, index: u8) -> Result<(u8, i32), ()> {
    if !(0..Q).contains(&x) || index >= 8 {
        return Err(());
    }
    let entry = PUBLIC_RECOVERY[x as usize][usize::from(index)];
    if entry == u16::MAX {
        return Err(());
    }
    let label = (entry & 63) as u8;
    Ok((label, centered(center(i32::from(label)) - x)))
}

#[path = "public_recovery_table.rs"]
mod public_recovery;
pub(crate) use public_recovery::{recover8 as public_recover8, Tables as PublicRecoveryTables};

#[cfg(test)]
#[path = "signature_codec_tests.rs"]
mod tests;

#[path = "admission_neon.rs"]
mod admission_neon;
pub(crate) fn capacity_mask(
    head: &[i32],
    labels: &[i32; LABELS],
    residual: &[i32; LABELS],
    local: &mut [i32; LABELS],
) -> u64 {
    {
        {
            // SAFETY: The AArch64 gate of build.rs supplies baseline NEON. The callee asserts the head
            // length and takes fixed LABELS-sized arrays for labels, residual and exclusive local
            // output; it masks invalid lane values before rank arithmetic.
            unsafe { admission_neon::capacity_mask_aux_i16(head, labels, residual, local) }
        }
    }
}

#[cfg(test)]
// Keep the explicit wire width conversion shared with reference variants.
#[allow(clippy::useless_conversion)]
pub(crate) fn encode_admitted_reference(
    head: &[i32],
    local: &[i32; LABELS],
    response: &mut [u8],
    hint: &mut [u8],
) {
    assert_eq!(head.len(), HEAD_COEFFICIENTS);
    assert_eq!(response.len(), HEAD_BYTES);
    assert!(hint.is_empty());
    response.fill(0);
    let mut count = 0usize;
    for (i, &value) in head.iter().enumerate() {
        let half = if i < 256 { 32 } else { 128 };
        if i < 256 {
            write_field(response, 6 * i, 6, value as u32);
        } else {
            response[MIDDLE + i - 256] = value as u8;
        }
        if (value < -half) | (value >= half) {
            if count < HEAD_EXCEPTIONS {
                let record = (i as u32) | (u32::from(value >= half) << 11);
                write_field(response, 8 * HEAD_RECORDS + 12 * count, 12, record);
            }
            count += 1;
        }
    }
    response[HEAD_COUNT] = count as u8;
    count = 0;
    for (i, &rank) in local.iter().enumerate() {
        write_field(response, 8 * LOCAL_LOW + 2 * i, 2, rank as u32);
        if rank >= 4 {
            if count < LABEL_EXCEPTIONS {
                write_field(response, 8 * LOCAL_RECORDS + 11 * count, 11, i as u32);
            }
            count += 1;
        }
    }
    response[LOCAL_COUNT] = count as u8;
}

#[cfg(test)]
#[inline(always)]
fn pack_four6(v: &[i32]) -> [u8; 3] {
    let bits = (v[0] as u32 & 63)
        | ((v[1] as u32 & 63) << 6)
        | ((v[2] as u32 & 63) << 12)
        | ((v[3] as u32 & 63) << 18);
    [bits as u8, (bits >> 8) as u8, (bits >> 16) as u8]
}

#[cfg(test)]
#[inline(always)]
fn pack_four2(v: &[i32]) -> u8 {
    ((v[0] as u32 & 3)
        | ((v[1] as u32 & 3) << 2)
        | ((v[2] as u32 & 3) << 4)
        | ((v[3] as u32 & 3) << 6)) as u8
}

#[cfg(test)]
fn pack_lows(head: &[i32], local: &[i32; LABELS], response: &mut [u8]) {
    for (values, bytes) in head[..256]
        .chunks_exact(4)
        .zip(response[..MIDDLE].chunks_exact_mut(3))
    {
        bytes.copy_from_slice(&pack_four6(values));
    }
    for (values, byte) in local
        .chunks_exact(4)
        .zip(&mut response[LOCAL_LOW..LOCAL_COUNT])
    {
        *byte = pack_four2(values);
    }
}

#[cfg(test)]
mod noncore_codec_tests {
    use super::*;
    #[test]
    fn exhaustive_six_bit_and_two_bit_groups() {
        for bits in 0u32..(1 << 24) {
            let values = core::array::from_fn::<_, 4, _>(|i| ((bits >> (6 * i)) & 63) as i32);
            let mut old = [0u8; 3];
            for (i, &v) in values.iter().enumerate() {
                write_field(&mut old, 6 * i, 6, v as u32);
            }
            assert_eq!(pack_four6(&values), old);
        }
        for bits in 0u32..256 {
            let values = core::array::from_fn::<_, 4, _>(|i| ((bits >> (2 * i)) & 3) as i32);
            let mut old = [0u8];
            for (i, &v) in values.iter().enumerate() {
                write_field(&mut old, 2 * i, 2, v as u32);
            }
            assert_eq!(pack_four2(&values), old[0]);
        }
    }

    #[test]
    fn full_packets_match_scalar_for_counts_boundaries_and_signed_inputs() {
        let mut seed = 0x2136987abcdu64;
        for trial in 0..2048 {
            let mut head = [0i32; HEAD_COEFFICIENTS];
            let mut local = [0i32; LABELS];
            for (i, x) in head.iter_mut().enumerate() {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                let half = if i < 256 { 32 } else { 128 };
                *x = (seed >> 32) as i32 % half;
            }
            for (i, x) in head.iter_mut().take(trial % 43).enumerate() {
                *x = [-95, -32, 32, 95][(trial + i) % 4];
            }
            for (i, x) in head[256..].iter_mut().take(trial % 43).enumerate() {
                *x = [-288, -128, 128, 288][(trial + i) % 4];
            }
            for (i, x) in local.iter_mut().enumerate() {
                *x = ((i + trial) & 3) as i32;
            }
            for x in local.iter_mut().take(trial % 19) {
                *x += 4;
            }
            if trial % 17 == 0 {
                head[0] = i32::MIN;
                head[255] = i32::MAX;
                local[0] = i32::MIN;
                local[LABELS - 1] = i32::MAX;
            }
            let mut got = [0xa5; HEAD_BYTES];
            let mut old = [0x5a; HEAD_BYTES];
            encode_admitted(&head, &local, &mut got, &mut []);
            encode_admitted_reference(&head, &local, &mut old, &mut []);
            assert_eq!(got, old, "packet {trial}");
        }
    }
}

// Admitted-field encoder with exactly the bytes of `encode_admitted_scalar`
// for every input, including invalid component inputs. It runs at the same
// point as the scalar encoder: after the private admission and abort
// decision, on the fields that are then released (accepted-packet premise).
// Its value-dependent branches are one 16-lane screen per block and the
// original per-coefficient predicate inside flagged blocks only.

// Keep the explicit wire width conversion shared with reference variants.
#[allow(clippy::useless_conversion)]
fn encode_admitted_aux(head: &[i32], local: &[i32; LABELS], response: &mut [u8], hint: &mut [u8]) {
    assert_eq!(head.len(), HEAD_COEFFICIENTS);
    assert_eq!(response.len(), HEAD_BYTES);
    assert!(hint.is_empty());
    response.fill(0);
    // Four six-bit low fields per three bytes (bits 0..1536 of the response).
    for (values, bytes) in head[..256]
        .chunks_exact(4)
        .zip(response[..MIDDLE].chunks_exact_mut(3))
    {
        let bits = (values[0] as u32 & 63)
            | ((values[1] as u32 & 63) << 6)
            | ((values[2] as u32 & 63) << 12)
            | ((values[3] as u32 & 63) << 18);
        bytes[0] = bits as u8;
        bytes[1] = (bits >> 8) as u8;
        bytes[2] = (bits >> 16) as u8;
    }
    aux_middle_bytes(&head[256..], &mut response[MIDDLE..HEAD_COUNT]);
    // Head exception records in index order; only the first 40 are written.
    let mut count = 0usize;
    for block in 0..HEAD_COEFFICIENTS / 16 {
        let at = 16 * block;
        let half = if at < 256 { 32 } else { 128 };
        let values = &head[at..at + 16];
        if !aux_any_outside(values, half) {
            continue;
        }
        for (j, &value) in values.iter().enumerate() {
            if (value < -half) | (value >= half) {
                if count < HEAD_EXCEPTIONS {
                    let record = ((at + j) as u32) | (u32::from(value >= half) << 11);
                    write_field(response, 8 * HEAD_RECORDS + 12 * count, 12, record);
                }
                count += 1;
            }
        }
    }
    response[HEAD_COUNT] = count as u8;
    aux_rank_bytes(local, &mut response[LOCAL_LOW..LOCAL_COUNT]);
    count = 0;
    for block in 0..LABELS / 16 {
        let at = 16 * block;
        let ranks = &local[at..at + 16];
        if !aux_any_at_least_four(ranks) {
            continue;
        }
        for (j, &rank) in ranks.iter().enumerate() {
            if rank >= 4 {
                if count < LABEL_EXCEPTIONS {
                    write_field(
                        response,
                        8 * LOCAL_RECORDS + 11 * count,
                        11,
                        (at + j) as u32,
                    );
                }
                count += 1;
            }
        }
    }
    response[LOCAL_COUNT] = count as u8;
}

// `value as u8` for 1280 coefficients.
fn aux_middle_bytes(values: &[i32], out: &mut [u8]) {
    use core::arch::aarch64::*;
    assert_eq!(values.len(), 1280);
    assert_eq!(out.len(), 1280);
    for i in (0..1280).step_by(16) {
        // SAFETY: i + 16 <= 1280 for both slices; NEON is baseline on AArch64.
        unsafe {
            let p = values.as_ptr().add(i).cast::<u32>();
            let a = vmovn_u32(vld1q_u32(p));
            let b = vmovn_u32(vld1q_u32(p.add(4)));
            let c = vmovn_u32(vld1q_u32(p.add(8)));
            let d = vmovn_u32(vld1q_u32(p.add(12)));
            let lo = vmovn_u16(vcombine_u16(a, b));
            let hi = vmovn_u16(vcombine_u16(c, d));
            vst1q_u8(out.as_mut_ptr().add(i), vcombine_u8(lo, hi));
        }
    }
}

// True iff some value satisfies (value < -half) | (value >= half). For every
// i32 this equals value.wrapping_add(half) as u32 >= 2 * half; the screen has
// no false negatives, and flagged blocks re-test the original predicate.
fn aux_any_outside(values: &[i32], half: i32) -> bool {
    use core::arch::aarch64::*;
    assert_eq!(values.len(), 16);
    // SAFETY: The AArch64 gate of build.rs supplies baseline NEON. values.len()==16 is asserted, so the four
    // four-word loads at offsets 0,4,8,12 are in bounds. i32 and u32 have identical alignment and all
    // bit patterns are valid.
    unsafe {
        let p = values.as_ptr().cast::<u32>();
        let h = vdupq_n_u32(half as u32);
        let w = vdupq_n_u32(2 * half as u32);
        let mut any = vcgeq_u32(vaddq_u32(vld1q_u32(p), h), w);
        any = vorrq_u32(any, vcgeq_u32(vaddq_u32(vld1q_u32(p.add(4)), h), w));
        any = vorrq_u32(any, vcgeq_u32(vaddq_u32(vld1q_u32(p.add(8)), h), w));
        any = vorrq_u32(any, vcgeq_u32(vaddq_u32(vld1q_u32(p.add(12)), h), w));
        vmaxvq_u32(any) != 0
    }
}

fn aux_any_at_least_four(ranks: &[i32]) -> bool {
    use core::arch::aarch64::*;
    assert_eq!(ranks.len(), 16);
    // SAFETY: The AArch64 gate of build.rs supplies baseline NEON. ranks.len()==16 is asserted; the four four-word
    // loads at offsets 0,4,8,12 stay in the shared initialized slice.
    unsafe {
        let p = ranks.as_ptr();
        let f = vdupq_n_s32(4);
        let mut any = vcgeq_s32(vld1q_s32(p), f);
        any = vorrq_u32(any, vcgeq_s32(vld1q_s32(p.add(4)), f));
        any = vorrq_u32(any, vcgeq_s32(vld1q_s32(p.add(8)), f));
        any = vorrq_u32(any, vcgeq_s32(vld1q_s32(p.add(12)), f));
        vmaxvq_u32(any) != 0
    }
}

// out[k] = (r[4k] & 3) | (r[4k+1] & 3) << 2 | (r[4k+2] & 3) << 4 | (r[4k+3] & 3) << 6.
// Per u32 lane w = b0 | b1 << 8 | b2 << 16 | b3 << 24 with b in 0..4:
// t = w | w >> 6 places b1 at bit 2 and b3 at bit 18, u = t | t >> 12 places
// b2 at bit 4 and b3 at bit 6; bits 4..7 of t are clear, so the low byte of u
// is exactly the packed byte.
fn aux_rank_bytes(local: &[i32; LABELS], out: &mut [u8]) {
    use core::arch::aarch64::*;
    assert_eq!(out.len(), LABELS / 4);
    for g in 0..LABELS / 32 {
        // SAFETY: The AArch64 gate of build.rs supplies baseline NEON. LABELS=1280 is divisible by 32 and
        // out.len()==LABELS/4 is asserted. Each iteration reads 32 initialized i32 ranks and writes
        // eight bytes into the disjoint exclusive output.
        unsafe {
            let p = local.as_ptr().add(32 * g).cast::<u32>();
            let three = vdupq_n_u8(3);
            let mut words = [vdupq_n_u32(0); 2];
            for (half, word) in words.iter_mut().enumerate() {
                let q = p.add(16 * half);
                let a = vmovn_u32(vld1q_u32(q));
                let b = vmovn_u32(vld1q_u32(q.add(4)));
                let c = vmovn_u32(vld1q_u32(q.add(8)));
                let d = vmovn_u32(vld1q_u32(q.add(12)));
                let bytes =
                    vcombine_u8(vmovn_u16(vcombine_u16(a, b)), vmovn_u16(vcombine_u16(c, d)));
                let w = vreinterpretq_u32_u8(vandq_u8(bytes, three));
                let t = vorrq_u32(w, vshrq_n_u32::<6>(w));
                *word = vorrq_u32(t, vshrq_n_u32::<12>(t));
            }
            let packed = vmovn_u16(vcombine_u16(vmovn_u32(words[0]), vmovn_u32(words[1])));
            vst1_u8(out.as_mut_ptr().add(8 * g), packed);
        }
    }
}

#[cfg(test)]
mod aux_encoder_tests {
    use super::*;

    fn both(head: &[i32; HEAD_COEFFICIENTS], local: &[i32; LABELS]) {
        let mut got = [0xa5u8; HEAD_BYTES];
        let mut old = [0x5au8; HEAD_BYTES];
        encode_admitted_aux(head, local, &mut got, &mut []);
        encode_admitted_scalar(head, local, &mut old, &mut []);
        assert_eq!(got, old);
        // `encode_admitted` forwards to `encode_admitted_aux`.
        let mut entry = [0x3cu8; HEAD_BYTES];
        encode_admitted(head, local, &mut entry, &mut []);
        assert_eq!(entry, old);
    }

    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u32 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (self.0 >> 32) as u32
        }
    }

    #[test]
    fn random_admitted_like_packets_match_scalar() {
        let mut g = Lcg(0xa1a1_2026_1026);
        for trial in 0..4096usize {
            let mut head = [0i32; HEAD_COEFFICIENTS];
            let mut local = [0i32; LABELS];
            for (i, x) in head.iter_mut().enumerate() {
                let (cap, half) = if i < 256 { (95, 32) } else { (288, 128) };
                let r = g.next();
                // Mostly inside, with roughly 1.4 percent exceptions.
                *x = if r.is_multiple_of(71) {
                    (r as i32 >> 8).rem_euclid(2 * cap + 1) - cap
                } else {
                    (r as i32 >> 8).rem_euclid(2 * half) - half
                };
            }
            for x in local.iter_mut() {
                let r = g.next();
                *x = if r.is_multiple_of(700) {
                    4 + (r >> 16) as i32 % 4
                } else {
                    (r >> 16) as i32 % 4
                };
            }
            if trial.is_multiple_of(7) {
                for x in head.iter_mut().take(trial % 64) {
                    *x = -*x - 1;
                }
            }
            both(&head, &local);
        }
    }

    #[test]
    fn arbitrary_i32_inputs_counts_and_wraps_match_scalar() {
        let mut g = Lcg(0xa1_ffff);
        for trial in 0..2048usize {
            let mut head = [0i32; HEAD_COEFFICIENTS];
            let mut local = [0i32; LABELS];
            for x in head.iter_mut() {
                *x = g.next() as i32 >> (g.next() % 32);
            }
            for x in local.iter_mut() {
                *x = g.next() as i32 >> (g.next() % 32);
            }
            if trial.is_multiple_of(5) {
                head[0] = i32::MIN;
                head[255] = i32::MAX;
                head[256] = i32::MIN;
                head[1535] = i32::MAX;
                local[0] = i32::MIN;
                local[LABELS - 1] = i32::MAX;
            }
            both(&head, &local);
        }
        // Every coefficient an exception (count 1536 wraps to 0) and every rank too (1280 wraps to 0).
        for value in [-129, -96, -33, 32, 95, 128, 288, i32::MIN, i32::MAX] {
            both(&[value; HEAD_COEFFICIENTS], &[7; LABELS]);
            both(&[value; HEAD_COEFFICIENTS], &[i32::MAX; LABELS]);
        }
        // Negative ranks are not exceptions; all-zero and all-boundary packets.
        both(&[0; HEAD_COEFFICIENTS], &[-1; LABELS]);
        both(&[31; HEAD_COEFFICIENTS], &[3; LABELS]);
        both(&[-32; HEAD_COEFFICIENTS], &[4; LABELS]);
    }

    #[test]
    fn single_exception_at_every_position_and_boundary() {
        for i in 0..HEAD_COEFFICIENTS {
            let half = if i < 256 { 32 } else { 128 };
            for value in [-half - 1, -half, half - 1, half] {
                let mut head = [1i32; HEAD_COEFFICIENTS];
                head[i] = value;
                both(&head, &[0; LABELS]);
            }
        }
        for i in 0..LABELS {
            for rank in [3, 4, 7, 8, -4] {
                let mut local = [1i32; LABELS];
                local[i] = rank;
                both(&[0; HEAD_COEFFICIENTS], &local);
            }
        }
    }

    #[test]
    fn screens_and_packers_are_exact() {
        for half in [32, 128] {
            for base in [
                i32::MIN,
                i32::MIN + half,
                -half - 2,
                -half - 1,
                -half,
                -1,
                0,
                half - 1,
                half,
                i32::MAX - half,
                i32::MAX - half + 1,
                i32::MAX - 15,
            ] {
                let values: [i32; 16] = core::array::from_fn(|k| base.wrapping_add(k as i32));
                let expect = values.iter().any(|&v| (v < -half) | (v >= half));
                assert_eq!(aux_any_outside(&values, half), expect, "{half} {base}");
            }
        }
        for bits in 0u32..256 {
            let mut local = [0i32; LABELS];
            for (i, x) in local.iter_mut().enumerate() {
                let k = (i + bits as usize) % 4;
                *x = ((bits >> (2 * k)) & 3) as i32 | ((i as i32) << 2);
            }
            let mut got = [0u8; LABELS / 4];
            aux_rank_bytes(&local, &mut got);
            for (k, r) in local.chunks_exact(4).enumerate() {
                let want =
                    ((r[0] & 3) | ((r[1] & 3) << 2) | ((r[2] & 3) << 4) | ((r[3] & 3) << 6)) as u8;
                assert_eq!(got[k], want);
            }
        }
    }
}

// Scalar oracle, absent from every production build.
#[cfg(test)]
// Keep the oracle's explicit wire-width conversion.
#[allow(clippy::useless_conversion)]
pub(crate) fn decode_fields_reference(
    bytes: &[u8],
    head: &mut [i32; HEAD_COEFFICIENTS],
    local: &mut [u8; LABELS],
) -> Result<(), ()> {
    if bytes.len() != HEAD_BYTES {
        return Err(());
    }
    let head_count = usize::from(bytes[HEAD_COUNT]);
    let local_count = usize::from(bytes[LOCAL_COUNT]);
    if head_count > HEAD_EXCEPTIONS || local_count > LABEL_EXCEPTIONS {
        return Err(());
    }
    for (i, value) in head[..256].iter_mut().enumerate() {
        let low = read_field(bytes, 6 * i, 6) as i32;
        *value = (low ^ 32) - 32;
    }
    for i in 0..1280 {
        head[256 + i] = i32::from(bytes[MIDDLE + i] as i8);
    }
    let mut previous = None;
    for slot in 0..HEAD_EXCEPTIONS {
        let record = read_field(bytes, 8 * HEAD_RECORDS + 12 * slot, 12);
        if slot >= head_count {
            if record != 0 {
                return Err(());
            }
            continue;
        }
        let position = (record & 2047) as usize;
        if position >= HEAD_COEFFICIENTS || previous.is_some_and(|p| position <= p) {
            return Err(());
        }
        let (step, cap) = if position < 256 { (64, 95) } else { (256, 288) };
        let correction = if record & 2048 != 0 { step } else { -step };
        let corrected = head[position] + correction;
        if corrected.unsigned_abs() > cap {
            return Err(());
        }
        head[position] = corrected;
        previous = Some(position);
    }
    // Uncorrected low values already satisfy their caps. A unique correction
    // moves outside the low range, so there is no second encoding of a value.
    for (i, value) in local.iter_mut().enumerate() {
        *value = (bytes[LOCAL_LOW + i / 4] >> (2 * (i % 4))) & 3;
    }
    previous = None;
    for slot in 0..LABEL_EXCEPTIONS {
        let position = read_field(bytes, 8 * LOCAL_RECORDS + 11 * slot, 11) as usize;
        if slot >= local_count {
            if position != 0 {
                return Err(());
            }
            continue;
        }
        if position >= LABELS || previous.is_some_and(|p| position <= p) {
            return Err(());
        }
        local[position] += 4;
        previous = Some(position);
    }
    Ok(())
}

#[cfg(test)]
mod hash_decode_tests {
    use super::*;
    fn compare(bytes: &[u8]) {
        let mut a = [0x12345678; HEAD_COEFFICIENTS];
        let mut b = a;
        let mut x = [0xa5; LABELS];
        let mut y = x;
        assert_eq!(
            decode_fields_reference(bytes, &mut a, &mut x),
            decode_fields(bytes, &mut b, &mut y)
        );
        assert_eq!(a, b, "partial head writes");
        assert_eq!(x, y, "partial local writes");
    }
    #[test]
    fn decode_random_and_adversarial() {
        let mut state = 0x123456789abcdefu64;
        for trial in 0..20000 {
            let mut packet = [0u8; HEAD_BYTES];
            for byte in &mut packet {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = state as u8;
            }
            if trial % 3 == 0 {
                packet[HEAD_COUNT] %= 41;
                packet[LOCAL_COUNT] %= 17;
            }
            if trial % 3 == 1 {
                packet[HEAD_COUNT] = 0;
                packet[LOCAL_COUNT] = 0;
                packet[HEAD_RECORDS..LOCAL_LOW].fill(0);
                packet[LOCAL_RECORDS..].fill(0);
            }
            compare(&packet);
        }
        let zero = [0u8; HEAD_BYTES];
        compare(&zero);
        compare(&[255; HEAD_BYTES]);
        for length in 0..HEAD_BYTES {
            compare(&zero[..length]);
        }
        compare(&[0; HEAD_BYTES + 1]);
        // Every encoded bit, including unused records, length/count boundaries.
        for bit in 0..HEAD_BYTES * 8 {
            let mut p = zero;
            p[bit / 8] ^= 1 << (bit % 8);
            compare(&p);
        }
        for position in 0..2048 {
            for sign in [0, 2048] {
                let mut p = zero;
                p[HEAD_COUNT] = 1;
                write_field(&mut p, 8 * HEAD_RECORDS, 12, position | sign);
                compare(&p);
            }
        }
        for position in 0..2048 {
            let mut p = zero;
            p[LOCAL_COUNT] = 1;
            write_field(&mut p, 8 * LOCAL_RECORDS, 11, position);
            compare(&p);
        }
    }
}

#[cfg(test)]
#[path = "secant_domain_tests.rs"]
mod secant_domain_tests;
