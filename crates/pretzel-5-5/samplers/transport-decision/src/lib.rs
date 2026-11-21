//! Fine arithmetic decisions used by the high-precision transport component.
//! This component alone establishes no emitted-code constant-time or erasure claim.
//! Slot coin contract: 128 independent fresh six-limb 384-bit words (6144 bytes).
//! Coarse/geometric users must share each corresponding coin, never redraw after selection.
// Index loops stay explicit in fixed-time arithmetic so that the access pattern is visible to review.
#![allow(clippy::needless_range_loop)]
// The derivative table stays a `const`: a `static` would change how the table is emitted and referenced.
#![allow(clippy::large_const_arrays)]
mod tables;
use tables::{DERIVATIVES, POWERS};
pub type Word = [u64; 6];
#[repr(C)]
pub struct Prepared {
    b: u64,
    coefficients: [Word; 58],
}
// Identity value barrier.
// SAFETY: comment-only assembly leaves its initialized register unchanged;
// it accesses no memory/stack and preserves flags. Deliberately not pure.
#[inline(always)]
fn opaque_mask(mut value: u64) -> u64 {
    // SAFETY: the template is an assembler comment, so no instruction is emitted. The only operand
    // is a general-purpose register holding an initialized u64; no memory, stack or flag is
    // touched, as the options state. No CPU feature, length or alignment is involved.
    unsafe {
        core::arch::asm!("/* {value} */",value=inout(reg)value,options(nomem,nostack,preserves_flags));
    }
    value
}
#[inline(always)]
fn select(m: u64, a: u64, b: u64) -> u64 {
    let m = opaque_mask(m);
    b ^ ((a ^ b) & m)
}
fn mul(a: &[u64], b: &[u64]) -> [u64; 13] {
    let mut z = [0u64; 13];
    for i in 0..a.len() {
        let mut carry = 0u128;
        for j in 0..b.len() {
            let v = (a[i] as u128) * (b[j] as u128) + (z[i + j] as u128) + carry;
            z[i + j] = v as u64;
            carry = v >> 64;
        }
        z[i + b.len()] = carry as u64;
    }
    z
}
fn add(a: &mut [u64], b: &[u64]) {
    let mut carry = 0u128;
    for i in 0..a.len() {
        carry += (a[i] as u128) + (b[i] as u128);
        a[i] = carry as u64;
        carry >>= 64;
    }
}
fn subtract(a: &[u64], b: &[u64]) -> [u64; 7] {
    let mut z = [0; 7];
    let mut borrow = 0u64;
    for i in 0..a.len() {
        let (v, b1) = a[i].overflowing_sub(b[i]);
        let (v, b2) = v.overflowing_sub(borrow);
        z[i] = v;
        borrow = opaque_mask(b1 as u64) | opaque_mask(b2 as u64);
    }
    z
}
// The public row index, never the secret norm, determines the bit schedule.
const fn power_bounds() -> [(usize, usize); 46] {
    let mut bounds = [(0, 0); 46];
    let mut row = 0;
    while row < 46 {
        let j = row as u64 + 1;
        let square = j * j;
        bounds[row] = (
            square.trailing_zeros() as usize,
            (64 - (292635 * square).leading_zeros()) as usize,
        );
        row += 1;
    }
    bounds
}
const POWER_BOUNDS: [(usize, usize); 46] = power_bounds();

fn power(n: u64, row: usize) -> Word {
    let mut a = [0u64; 6];
    let mut found = 0u64;
    let (first, end) = POWER_BOUNDS[row];
    for bit in first..end {
        let p = mul(&a, &POWERS[bit]);
        let on = opaque_mask(0u64.wrapping_sub((n >> bit) & 1));
        for i in 0..6 {
            let candidate = select(found, p[i + 6], POWERS[bit][i]);
            a[i] = select(on, candidate, a[i]);
        }
        found |= on;
    }
    a
}
pub fn prepare(b: u64) -> Option<Prepared> {
    if !(131557..=292635).contains(&b) {
        return None;
    }
    let mut acc = [[0u64; 7]; 58];
    acc[0][6] = 1;
    for j in 1..=46 {
        let p = power(b * j * j, j as usize - 1);
        for k in 0..58 {
            let product = mul(&DERIVATIVES[j as usize - 1][k], &p);
            let mut term = [0u64; 7];
            let mut carry = 0;
            for i in 0..7 {
                term[i] = (product[i + 6] << 1) | carry;
                carry = product[i + 6] >> 63;
            }
            if j & 1 == 1 {
                acc[k] = subtract(&acc[k], &term);
            } else {
                add(&mut acc[k], &term);
            }
        }
    }
    let mut coefficients = [[0u64; 6]; 58];
    for k in 0..58 {
        let mut rounding = [0u64; 7];
        rounding[0] = 1 << 60;
        add(&mut acc[k], &rounding);
        for i in 0..6 {
            coefficients[k][i] = (acc[k][i] >> 61) | (acc[k][i + 1] << 3);
        }
    }
    Some(Prepared { b, coefficients })
}
/// Signed floor(h*V/2^64) via sign-extended 448-bit product, then signed 384 addition.
pub fn evaluate(p: &Prepared, t: u64) -> Option<Word> {
    if opaque_mask(u64::from(t > p.b)) != 0 {
        return None;
    }
    let v = (t * t) << 27;
    let mut h = p.coefficients[57];
    for k in (0..57).rev() {
        horner_step(&mut h, v, &p.coefficients[k]);
    }
    Some(h)
}
fn div65586(a: &Word) -> Word {
    let mut q = [0u64; 6];
    let mut rem = 0u64;
    for digit in (0..12).rev() {
        let shift = (digit % 2) * 32;
        let limb = (a[digit / 2] >> shift) & 0xffffffff;
        let value = (rem << 32) | limb;
        let quotient = value / 65586;
        rem = value - quotient * 65586;
        q[digit / 2] |= quotient << shift;
    }
    q
}
/// Inside -B<=a<B uses guarded correction; outside uses separately exact rational grid 1/M.
pub fn threshold(p: &Prepared, a: i64) -> Word {
    let t = a.unsigned_abs();
    let clipped = select(
        opaque_mask(0u64.wrapping_sub(opaque_mask((t > p.b) as u64))),
        p.b,
        t,
    );
    let mut h = evaluate(p, clipped).expect("clipped range");
    let inside = opaque_mask(
        0u64.wrapping_sub(opaque_mask((t < p.b) as u64) | opaque_mask((a == -(p.b as i64)) as u64)),
    );
    for i in 0..6 {
        h[i] &= inside;
    }
    let mut guard = [0; 6];
    guard[0] = 8 & inside;
    add(&mut h, &guard);
    let mut q = [0u64; 6];
    q[5] = 8; // 2^323.
    let difference = subtract(&q, &h);
    let mut numerator = [0; 6];
    let mut carry = 0;
    for i in 0..6 {
        numerator[i] = (difference[i] << 16) | carry;
        carry = difference[i] >> 48;
    }
    // numerator = (2^323 - h) * 2^16; its quotient by 65586 is returned without saturation.
    div65586(&numerator)
}
pub fn decide(p: &Prepared, a: i64, raw384: &Word) -> bool {
    let k = threshold(p, a);
    let mut coin = [0u64; 6];
    for i in 0..5 {
        coin[i] = (raw384[i] >> 61) | (raw384[i + 1] << 3);
    }
    coin[5] = raw384[5] >> 61;
    let mut borrow = 0;
    for i in 0..6 {
        let (v, b1) = coin[i].overflowing_sub(k[i]);
        let (_, b2) = v.overflowing_sub(borrow);
        borrow = opaque_mask(b1 as u64) | opaque_mask(b2 as u64);
    }
    borrow != 0
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invalid_shell_rejected() {
        assert!(prepare(131556).is_none());
        assert!(prepare(131557).is_some());
        assert!(prepare(292635).is_some());
        assert!(prepare(292636).is_none());
    }
    #[test]
    fn endpoint_and_same_coin() {
        let p = prepare(131557).unwrap();
        let q = threshold(&p, 131557);
        assert_eq!(q, threshold(&p, 131558));
        assert!(decide(&p, -131557, &[0; 6]));
        assert!(!decide(&p, -131557, &[u64::MAX; 6]));
    }
}

const _: () = assert!(core::mem::size_of::<Prepared>() == 2792);
const _: () = assert!(core::mem::align_of::<Prepared>() == 8);

#[cfg(test)]
mod division_tests {
    use super::*;
    fn reference(a: &Word) -> Word {
        let mut q = [0u64; 6];
        let mut rem = 0u64;
        for bit in (0..384).rev() {
            rem = (rem << 1) | ((a[bit / 64] >> (bit % 64)) & 1);
            let take = (rem >= 65586) as u64;
            rem = rem.wrapping_sub(65586 & 0u64.wrapping_sub(take));
            q[bit / 64] |= take << (bit % 64);
        }
        q
    }

    #[test]
    fn quotient_matches_bitwise() {
        let mut state = 65586u64;
        for trial in 0..10000 {
            let mut a = [0; 6];
            for v in &mut a {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *v = state;
            }
            if trial == 0 {
                a = [0; 6];
            }
            if trial == 1 {
                a = [u64::MAX; 6];
            }
            assert_eq!(div65586(&a), reference(&a));
        }
    }
}

#[cfg(test)]
mod fixture_vectors {
    use super::*;
    fn word(bytes: &[u8]) -> Word {
        core::array::from_fn(|i| u64::from_le_bytes(bytes[8 * i..8 * i + 8].try_into().unwrap()))
    }
    #[test]
    fn bigint_coefficients_thresholds_and_same_coin_boundaries() {
        let data = include_bytes!("decision-fixtures.bin");
        let mut at = 0;
        let mut profiles = 0;
        while at < data.len() {
            let b = u64::from_le_bytes(data[at..at + 8].try_into().unwrap());
            at += 8;
            let p = prepare(b).unwrap();
            for k in 0..58 {
                let want = word(&data[at..at + 48]);
                at += 48;
                assert_eq!(p.coefficients[k], want, "b {} coefficient {}", b, k);
            }
            let count = u32::from_le_bytes(data[at..at + 4].try_into().unwrap());
            at += 4;
            for _ in 0..count {
                let a = i64::from_le_bytes(data[at..at + 8].try_into().unwrap());
                at += 8;
                let want = word(&data[at..at + 48]);
                at += 48;
                assert_eq!(threshold(&p, a), want, "b {} a {}", b, a);
                for delta in [-1i32, 0, 1] {
                    let mut k = want;
                    if delta < 0 {
                        let mut borrow = 1u64;
                        for v in &mut k {
                            let (x, b) = v.overflowing_sub(borrow);
                            *v = x;
                            borrow = b as u64;
                        }
                    } else if delta > 0 {
                        let mut carry = 1u64;
                        for v in &mut k {
                            let (x, c) = v.overflowing_add(carry);
                            *v = x;
                            carry = c as u64;
                        }
                    }
                    let mut raw = [0; 6];
                    let mut carry = 0;
                    for i in 0..6 {
                        raw[i] = (k[i] << 61) | carry;
                        carry = k[i] >> 3;
                    }
                    for low in [0, (1u64 << 61) - 1] {
                        raw[0] = (raw[0] & !((1u64 << 61) - 1)) | low;
                        assert_eq!(decide(&p, a, &raw), delta < 0);
                    }
                }
            }
            profiles += 1;
        }
        assert_eq!(profiles, 8);
    }
}

include!("horner384.rs");
