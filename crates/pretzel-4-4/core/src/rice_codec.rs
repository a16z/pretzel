// Canonical rank-4 compact head and residual indices.
// Variable-work encoding is only for already irrevocably admitted responses.
pub const HEAD_BYTES: usize = 1160;
pub const HINT_BYTES: usize = 169;
pub const SIGNATURE_BYTES: usize = 32 + HEAD_BYTES + HINT_BYTES;
pub const EXCEPTIONS: usize = 50;
const SPLIT: usize = 4;
const LOW_BYTES: usize = (EXCEPTIONS * SPLIT + 7) / 8;
const HIGH_BITS: usize = (1023 >> SPLIT) + EXCEPTIONS;
const HIGH_BYTES: usize = (HIGH_BITS + 7) / 8;
const _: () = assert!(HINT_BYTES == 128 + 1 + LOW_BYTES + HIGH_BYTES);
fn zigzag(v: i32) -> u32 {
    ((v as u32) << 1) ^ ((v >> 31) as u32)
}
#[cfg(any(test, not(target_arch = "aarch64")))]
fn unzigzag(v: u32) -> i32 {
    ((v >> 1) as i32) ^ -((v & 1) as i32)
}
#[cfg(any(test, not(all(target_arch = "aarch64", target_endian = "little"))))]
fn bit(bytes: &[u8], at: usize) -> u32 {
    u32::from((bytes[at / 8] >> (at % 8)) & 1)
}
fn read(bytes: &[u8], at: usize, width: usize) -> u32 {
    let shift = at % 8;
    let mut v = u32::from(bytes[at / 8]) >> shift;
    if shift + width > 8 {
        v |= u32::from(bytes[at / 8 + 1]) << (8 - shift);
    }
    v & ((1 << width) - 1)
}
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
struct Ones<'a> {
    bytes: &'a [u8],
    next: usize,
    base: usize,
    word: u64,
}
impl<'a> Ones<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            next: 0,
            base: 0,
            word: 0,
        }
    }
    fn next(&mut self) -> Option<usize> {
        while self.word == 0 {
            if self.next == self.bytes.len() {
                return None;
            }
            let count = (self.bytes.len() - self.next).min(8);
            let mut word = [0; 8];
            word[..count].copy_from_slice(&self.bytes[self.next..self.next + count]);
            self.base = 8 * self.next;
            self.next += count;
            self.word = u64::from_le_bytes(word);
        }
        let at = self.base + self.word.trailing_zeros() as usize;
        self.word &= self.word - 1;
        Some(at)
    }
}
#[cfg(any(test, not(target_arch = "aarch64")))]
const fn mod34(v: i32) -> i32 {
    v + 34 * ((v < 0) as i32) - 34 * ((v >= 34) as i32)
}
#[cfg(any(test, not(all(target_arch = "aarch64", target_endian = "little"))))]
const fn centered(v: i32) -> i32 {
    v + 7681 * ((v < -3840) as i32) - 7681 * ((v > 3840) as i32)
}
const fn center(j: i32) -> i32 {
    let j = j as u32;
    let t = 3 * j / 34;
    let jump = 3 * (j + 1) / 34 - t;
    (226 * j - t + 112 + (1 - jump) * ((j - t) & 1)) as i32
}
#[cfg(any(test, not(target_arch = "aarch64")))]
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
/// Fixed source schedule, no secret-indexed tables or early exits. Compiler
/// branch/address inspection is required. Inputs come from native
/// postfilters: canonical labels and centered residuals, even on failed attempts.
pub(crate) fn capacity_mask(
    head: &[i32],
    labels: &[i32; 1024],
    residual: &[i32; 1024],
    local: &mut [i32; 1024],
) -> u64 {
    assert_eq!(head.len(), 1280);
    let mut failed = 0u64;
    let mut quotient = 0u64;
    let mut exceptions = 0u64;
    for (i, &v) in head.iter().enumerate() {
        let cap = if i < 256 {
            crate::params::FORMAT_HEAD_LIMIT_LEAD as u32
        } else {
            crate::params::FORMAT_HEAD_LIMIT as u32
        };
        let k = if i < 256 { 3 } else { 6 };
        failed |= 0u64.wrapping_sub(u64::from(v.unsigned_abs() > cap));
        quotient += u64::from(zigzag(v) >> k);
    }
    #[cfg(target_arch = "aarch64")]
    {
        let(bad,count)=
 // SAFETY: The AArch64 cfg supplies NEON. labels, residual and local are typed 1024-element
 // arrays with exclusive local access; capacity8::scan accesses only those extents and uses
 // register table lookups for all values.
 unsafe{capacity8::scan(labels,residual,local)};
        failed |= bad;
        exceptions += count;
    }
    failed |= 0u64.wrapping_sub(u64::from(
        (quotient > 1088) | (exceptions > EXCEPTIONS as u64),
    ));
    !failed
}
/// Total on the capacity_mask-admitted domain. Buffers are preallocated before
/// candidate evaluation; this routine has no fallible allocation or rejection.
#[cfg(test)]
pub(crate) fn encode_admitted_scalar(
    head: &[i32],
    local: &[i32; 1024],
    response: &mut [u8],
    hint: &mut [u8],
) {
    assert_eq!(head.len(), 1280);
    assert_eq!(response.len(), HEAD_BYTES);
    assert_eq!(hint.len(), HINT_BYTES);
    response.fill(0);
    hint.fill(0);
    let (lo, unary) = response.split_at_mut(864);
    let mut lowpos = 0;
    let mut position = 0;
    for (i, &v) in head.iter().enumerate() {
        let width = if i < 256 { 3 } else { 6 };
        let value = zigzag(v);
        write(lo, lowpos, width, value);
        lowpos += width;
        position += (value >> width) as usize;
        unary[position / 8] |= 1 << (position % 8);
        position += 1;
    }
    let (primary, ef) = hint.split_at_mut(128);
    let (count, rest) = ef.split_at_mut(1);
    let (low, high) = rest.split_at_mut(LOW_BYTES);
    let mut used = 0;
    for (i, &k) in local.iter().enumerate() {
        primary[i / 8] |= ((k & 1) as u8) << (i % 8);
        if k >= 2 {
            write(low, used * SPLIT, SPLIT, i as u32);
            let b = (i >> SPLIT) + used;
            high[b / 8] |= 1 << (b % 8);
            used += 1;
        }
    }
    count[0] = used as u8;
}
#[cfg(any(test, not(target_arch = "aarch64")))]
pub(crate) fn decode_head_scalar(response: &[u8], head: &mut [i32; 1280]) -> Result<(), ()> {
    if response.len() != HEAD_BYTES {
        return Err(());
    }
    let (lo, unary) = response.split_at(864);
    let mut ones = Ones::new(unary);
    let mut position = 0;
    let mut lowpos = 0;
    let mut sum = 0;
    for (i, v) in head.iter_mut().enumerate() {
        let delimiter = ones.next().ok_or(())?;
        let q = delimiter - position;
        position = delimiter + 1;
        sum += q;
        let k = if i < 256 { 3 } else { 6 };
        *v = unzigzag(((q as u32) << k) | read(lo, lowpos, k));
        lowpos += k;
        let cap = if i < 256 {
            crate::params::FORMAT_HEAD_LIMIT_LEAD as u32
        } else {
            crate::params::FORMAT_HEAD_LIMIT as u32
        };
        if v.unsigned_abs() > cap {
            return Err(());
        }
    }
    if sum > 1088 || ones.next().is_some() {
        return Err(());
    }
    Ok(())
}
#[cfg(test)]
pub(crate) fn decode_local(hint: &[u8], local: &mut [u8; 1024]) -> Result<(), ()> {
    if hint.len() != HINT_BYTES {
        return Err(());
    }
    for (i, k) in local.iter_mut().enumerate() {
        *k = bit(hint, i) as u8;
    }
    let count = hint[128] as usize;
    if count > EXCEPTIONS {
        return Err(());
    }
    let low = &hint[129..129 + LOW_BYTES];
    let high = &hint[129 + LOW_BYTES..];
    if !zeros(low, count * SPLIT) || !zeros(high, HIGH_BITS) {
        return Err(());
    }
    let mut ones = Ones::new(high);
    let mut previous = None;
    for i in 0..count {
        let p = ones.next().ok_or(())?;
        if p < i {
            return Err(());
        }
        let at = ((p - i) << SPLIT) | read(low, i * SPLIT, SPLIT) as usize;
        if at >= 1024 || previous.is_some_and(|old| at <= old) {
            return Err(());
        }
        local[at] += 2;
        previous = Some(at);
    }
    if ones.next().is_some() {
        return Err(());
    }
    Ok(())
}
#[cfg(test)]
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
#[cfg(test)]
const fn public_centers() -> [i32; 34] {
    let mut a = [0; 34];
    let mut j = 0;
    while j < 34 {
        a[j] = center(j as i32);
        j += 1;
    }
    a
}
#[cfg(test)]
static PUBLIC_CENTERS: [i32; 34] = public_centers();
#[cfg(test)]
static PUBLIC_CONTEXTS: [[u8; 4]; 7681] = public_contexts();
#[cfg(test)]
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

#[cfg(target_arch = "aarch64")]
#[path = "rice_public_recovery.rs"]
mod public_recovery;
#[cfg(target_arch = "aarch64")]
pub(crate) use public_recovery::{recover8 as public_recover8, Tables as PublicRecoveryTables};

/// Successful compact decoding proves every leading coefficient is in [-288,288]
/// and every remaining head coefficient in [-255,255]. Fields are private.
pub(crate) struct DecodedRiceHead<'a>(&'a [i32; 1280]);

pub(crate) fn decode_head_borrowed<'a>(
    bytes: &[u8],
    head: &'a mut [i32; 1280],
) -> Result<DecodedRiceHead<'a>, ()> {
    decode_head(bytes, head)?;
    Ok(DecodedRiceHead(head))
}

impl DecodedRiceHead<'_> {
    pub(crate) fn values(&self) -> &[i32; 1280] {
        self.0
    }
    #[cfg(any(test, not(target_arch = "aarch64")))]
    pub(crate) fn write_canonical_column(&self, column: usize, out: &mut [i16; 256]) {
        assert!(column < 5);
        for i in 0..256 {
            let x = self.0[column * 256 + i];
            out[i] = (x + ((x >> 31) & 7681)) as i16;
        }
    }
}

#[cfg(target_arch = "aarch64")]
#[path = "rice_decode_neon.rs"]
mod decode_neon;
pub(crate) fn decode_head(response: &[u8], head: &mut [i32; 1280]) -> Result<(), ()> {
    #[cfg(target_arch = "aarch64")]
    {
        decode_neon::decode(response, head)
    }
}

#[path = "rice_fast_pack.rs"]
mod fast_pack;
pub(crate) fn encode_admitted(
    head: &[i32],
    local: &[i32; 1024],
    response: &mut [u8],
    hint: &mut [u8],
) {
    fast_pack::encode(head, local, response, hint);
}

#[cfg(target_arch = "aarch64")]
#[path = "rice_capacity8.rs"]
mod capacity8;

/// Public canonical local indices in two bit planes per matrix row.
pub(crate) struct DecodedLocalPlanes([[u8; 64]; 4]);

impl DecodedLocalPlanes {
    pub(crate) fn row(&self, row: usize) -> &[u8; 64] {
        &self.0[row]
    }
}

pub(crate) fn decode_local_planes(hint: &[u8]) -> Result<DecodedLocalPlanes, ()> {
    if hint.len() != HINT_BYTES {
        return Err(());
    }
    let mut rows = [[0u8; 64]; 4];
    for row in 0..4 {
        rows[row][..32].copy_from_slice(&hint[row * 32..(row + 1) * 32]);
    }
    let count = hint[128] as usize;
    if count > EXCEPTIONS {
        return Err(());
    }
    let mut previous = None;
    {
        let low = &hint[129..129 + LOW_BYTES];
        let high = &hint[129 + LOW_BYTES..];
        if !zeros(low, count * SPLIT) || !zeros(high, HIGH_BITS) {
            return Err(());
        }
        let mut ones = Ones::new(high);
        for i in 0..count {
            let p = ones.next().ok_or(())?;
            if p < i {
                return Err(());
            }
            let at = ((p - i) << SPLIT) | read(low, i * SPLIT, SPLIT) as usize;
            if at >= 1024 || previous.is_some_and(|old| at <= old) {
                return Err(());
            }
            rows[at / 256][32 + (at % 256) / 8] |= 1 << (at % 8);
            previous = Some(at);
        }
        if ones.next().is_some() {
            return Err(());
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
                hint[128..].fill(0);
            }
            let mut flat = [0; 1024];
            let expected = decode_local(&hint, &mut flat);
            let actual = decode_local_planes(&hint);
            assert_eq!(expected.is_ok(), actual.is_ok());
            if let Ok(planes) = actual {
                for i in 0..1024 {
                    let row = planes.row(i / 256);
                    let value = ((row[(i % 256) / 8] >> (i % 8)) & 1)
                        + 2 * ((row[32 + (i % 256) / 8] >> (i % 8)) & 1);
                    assert_eq!(flat[i], value);
                }
            }
        }
    }
}
