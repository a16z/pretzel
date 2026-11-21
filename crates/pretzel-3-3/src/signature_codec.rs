// Canonical rank-3 compact head and residual indices.
// Variable-work encoding is only for already irrevocably admitted responses.
pub const HEAD_BYTES: usize = 981;
pub const HINT_BYTES: usize = 147;
pub const SIGNATURE_BYTES: usize = 32 + HEAD_BYTES + HINT_BYTES;
pub const EXCEPTIONS: usize = 40;
#[path = "sparse_codec.rs"]
mod sparse;
fn read(bytes: &[u8], at: usize, width: usize) -> u32 {
    let shift = at % 8;
    let mut v = u32::from(bytes[at / 8]) >> shift;
    if shift + width > 8 {
        v |= u32::from(bytes[at / 8 + 1]) << (8 - shift);
    }
    v & ((1 << width) - 1)
}
#[cfg(test)]
fn write(bytes: &mut [u8], at: usize, width: usize, v: u32) {
    let shift = at % 8;
    let v = v & ((1 << width) - 1);
    bytes[at / 8] |= (v << shift) as u8;
    if shift + width > 8 {
        bytes[at / 8 + 1] |= (v >> (8 - shift)) as u8;
    }
}
fn zeros(bytes: &[u8], start: usize) -> bool {
    let byte = start / 8;
    let shift = start % 8;
    if byte >= bytes.len() {
        return true;
    }
    if bytes[byte] >> shift != 0 {
        return false;
    }
    bytes[byte + 1..].iter().all(|&v| v == 0)
}
const fn mod34(v: i32) -> i32 {
    v + 34 * ((v < 0) as i32) - 34 * ((v >= 34) as i32)
}
const fn centered(v: i32) -> i32 {
    v + 7681 * ((v < -3840) as i32) - 7681 * ((v > 3840) as i32)
}
const fn center(j: i32) -> i32 {
    let j = j as u32;
    let t = 3 * j / 34;
    let jump = 3 * (j + 1) / 34 - t;
    (226 * j - t + 112 + (1 - jump) * ((j - t) & 1)) as i32
}
const fn local_labels(x: i32) -> [i32; 4] {
    let j = (34 * (x as u32) / 7681) as i32;
    let dl = centered(x - center(mod34(j - 1)));
    let dr = centered(center(mod34(j + 1)) - x);
    let s = 1 - 2 * ((dl <= dr) as i32);
    [j, mod34(j + s), mod34(j - s), mod34(j + 2 * s)]
}
#[cfg(test)]
pub(crate) fn public_local_index(x: i32, u: i32) -> Option<u8> {
    if !(0..7681).contains(&x) || !(0..34).contains(&u) {
        return None;
    }
    local_labels(x)
        .iter()
        .position(|&label| label == u)
        .map(|i| i as u8)
}
#[path = "capacity_neon.rs"]
mod capacity_neon;
/// Fixed source schedule, no secret-indexed tables or early exits. Compiler
/// branch/address inspection is required. Inputs come from native
/// postfilters: canonical labels and centered residuals, even on failed attempts.
pub(crate) fn capacity_mask(
    head: &[i32],
    labels: &[i32; 768],
    residual: &[i32; 768],
    local: &mut [i32; 768],
) -> u64 {
    assert_eq!(head.len(), 1024);
    let mut failed = 0u64;
    let mut quotient = 0u64;
    let mut exceptions = 0u64;
    for (i, &v) in head.iter().enumerate() {
        let cap = if i < 256 {
            crate::params::FORMAT_HEAD_LIMIT_LEAD as u32
        } else {
            crate::params::FORMAT_HEAD_LIMIT as u32
        };
        failed |= 0u64.wrapping_sub(u64::from(v.unsigned_abs() > cap));
        quotient += u64::from((i >= 256) & ((v < -128) | (v > 127)));
    }
    {
        // SAFETY: the capacity kernel requires NEON only, which is in the baseline of every target
        // this crate builds for (`build.rs` asserts little-endian AArch64). Its arguments are
        // references to 768-element arrays, the exact extent it reads and writes.
        let (bad, count) = unsafe { capacity_neon::scan(labels, residual, local) };
        failed |= bad;
        exceptions += count;
    }
    failed |= 0u64.wrapping_sub(u64::from(
        (quotient > 16) | (exceptions > EXCEPTIONS as u64),
    ));
    !failed
}
pub(crate) fn decode_head_scalar(response: &[u8], head: &mut [i32; 1024]) -> Result<(), ()> {
    sparse::decode_head(response, head)
}
pub(crate) fn decode_local(hint: &[u8], local: &mut [u8; 768]) -> Result<(), ()> {
    sparse::decode_local(hint, local)
}
const fn public_contexts() -> [[u8; 4]; 7681] {
    let mut table = [[0; 4]; 7681];
    let mut x = 0;
    while x < 7681 {
        let labels = local_labels(x as i32);
        let mut k = 0;
        while k < 4 {
            table[x][k] = labels[k] as u8;
            k += 1;
        }
        x += 1;
    }
    table
}
const fn public_centers() -> [i32; 34] {
    let mut a = [0; 34];
    let mut j = 0;
    while j < 34 {
        a[j] = center(j as i32);
        j += 1;
    }
    a
}
static PUBLIC_CENTERS: [i32; 34] = public_centers();
static PUBLIC_CONTEXTS: [[u8; 4]; 7681] = public_contexts();
pub(crate) fn recover(x: i32, k: u8) -> Result<(u8, i32), ()> {
    if !(0..7681).contains(&x) || k > 3 {
        return Err(());
    }
    let u = PUBLIC_CONTEXTS[x as usize][k as usize];
    let r = centered(PUBLIC_CENTERS[u as usize] - x);
    if r.unsigned_abs() > crate::params::FORMAT_RES_LIMIT as u32 {
        return Err(());
    }
    Ok((u, r))
}

#[path = "public_recovery.rs"]
mod public_recovery;
pub(crate) use public_recovery::{recover8 as public_recover8, Tables as PublicRecoveryTables};

/// Successful compact decoding proves every leading coefficient is in [-288,288]
/// and every remaining head coefficient in [-255,255]. Fields are private.
pub(crate) struct DecodedHead<'a>(&'a [i32; 1024]);
pub(crate) fn decode_head_borrowed<'a>(
    bytes: &[u8],
    head: &'a mut [i32; 1024],
) -> Result<DecodedHead<'a>, ()> {
    decode_head(bytes, head)?;
    Ok(DecodedHead(head))
}
impl DecodedHead<'_> {
    pub(crate) fn values(&self) -> &[i32; 1024] {
        self.0
    }
    #[cfg(test)]
    pub(crate) fn write_canonical_column(&self, column: usize, out: &mut [i16; 256]) {
        assert!(column < 4);
        for i in 0..256 {
            let x = self.0[column * 256 + i];
            out[i] = (x + ((x >> 31) & 7681)) as i16;
        }
    }
}

pub(crate) fn decode_head(response: &[u8], head: &mut [i32; 1024]) -> Result<(), ()> {
    decode_head_scalar(response, head)
}

#[cfg(test)]
pub(crate) fn encode_admitted(
    head: &[i32],
    local: &[i32; 768],
    response: &mut [u8],
    hint: &mut [u8],
) {
    sparse::encode(head, local, response, hint)
}

/// Public canonical local indices in two bit planes per matrix row.
pub(crate) struct DecodedLocalPlanes([[u8; 64]; 3]);
impl DecodedLocalPlanes {
    pub(crate) fn row(&self, row: usize) -> &[u8; 64] {
        &self.0[row]
    }
}
pub(crate) fn decode_local_planes(hint: &[u8]) -> Result<DecodedLocalPlanes, ()> {
    if hint.len() != HINT_BYTES {
        return Err(());
    }
    // Low planes come directly from the packet; only sparse high planes start at zero.
    let mut rows: [[u8; 64]; 3] = core::array::from_fn(|row| {
        core::array::from_fn(|i| if i < 32 { hint[row * 32 + i] } else { 0 })
    });
    let count = hint[96] as usize;
    if count > EXCEPTIONS {
        return Err(());
    }
    let mut previous = None;
    {
        if !zeros(&hint[97..], count * 10) {
            return Err(());
        }
        for i in 0..count {
            let at = read(&hint[97..], 10 * i, 10) as usize;
            if at >= 768 || previous.is_some_and(|old| at <= old) {
                return Err(());
            }
            rows[at / 256][32 + (at % 256) / 8] |= 1 << (at % 8);
            previous = Some(at);
        }
    }
    Ok(DecodedLocalPlanes(rows))
}
#[cfg(test)]
mod plane_tests {
    use super::*;
    #[test]
    fn compare_flat_decoder() {
        let mut state = 17u64;
        for case in 0..100000 {
            let mut hint = [0u8; HINT_BYTES];
            for b in &mut hint {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *b = state as u8;
            }
            if case % 3 == 0 {
                hint[96..].fill(0);
            }
            let mut flat = [0; 768];
            let expected = decode_local(&hint, &mut flat);
            let actual = decode_local_planes(&hint);
            assert_eq!(expected.is_ok(), actual.is_ok());
            if let Ok(planes) = actual {
                for i in 0..768 {
                    let row = planes.row(i / 256);
                    let value = ((row[(i % 256) / 8] >> (i % 8)) & 1)
                        + 2 * ((row[32 + (i % 256) / 8] >> (i % 8)) & 1);
                    assert_eq!(flat[i], value);
                }
            }
        }
    }
}
