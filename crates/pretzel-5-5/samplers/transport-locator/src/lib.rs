// Index loops stay explicit in fixed-time arithmetic so that the access pattern is visible to review.
#![allow(clippy::needless_range_loop)]
mod tables;
#[derive(Debug, PartialEq, Eq)]
pub struct Result384 {
    pub value: i64,
    pub boundary: i64,
    pub bad: bool,
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
fn choose(bit: u64, a: u64, b: u64) -> u64 {
    let bit = opaque_mask(bit);
    let m = opaque_mask(0u64.wrapping_sub(bit));
    b ^ ((a ^ b) & m)
}
fn mul(a: &[u64; 6], b: &[u64; 6]) -> [u64; 12] {
    let mut o = [0u64; 12];
    for i in 0..6 {
        let mut c = 0u128;
        for j in 0..6 {
            let z = (a[i] as u128) * (b[j] as u128) + (o[i + j] as u128) + c;
            o[i + j] = z as u64;
            c = z >> 64;
        }
        o[i + 6] = c as u64;
    }
    o
}
fn less(a: &[u64; 7], b: &[u64; 7]) -> u64 {
    let mut borrow = 0u128;
    for i in 0..7 {
        let z = (1u128 << 64) + (a[i] as u128) - (b[i] as u128) - borrow;
        borrow = 1 - (z >> 64);
    }
    borrow as u64
}
fn plus(a: &[u64; 7], k: u64) -> [u64; 7] {
    let mut out = *a;
    let mut c = k as u128;
    for i in 0..7 {
        c += out[i] as u128;
        out[i] = c as u64;
        c >>= 64;
    }
    out
}
/// Fixed 29 rounds, always 28 full products after public initial round. Compiled for tests
/// only; the signer's path is `sampler_bundle::power_prefixed`.
// Each round's private bit and full masks stay opaque before all consumers.
// Six limbs share the SAME bit. Reusing its mask changes no predicate scope.
#[cfg(test)]
fn power(m: u64) -> [u64; 6] {
    let mut a = [0u64; 6];
    let mut seen = opaque_mask(m & 1);
    let initial = opaque_mask(0u64.wrapping_sub(opaque_mask(seen)));
    for (j, value) in a.iter_mut().enumerate() {
        *value = tables::POWERS[0][j] & initial;
    }
    for (i, powers) in tables::POWERS.iter().enumerate().take(29).skip(1) {
        let p = mul(&a, powers);
        let bit = opaque_mask((m >> i) & 1);
        let seen_mask = opaque_mask(0u64.wrapping_sub(opaque_mask(seen)));
        let bit_mask = opaque_mask(0u64.wrapping_sub(opaque_mask(bit)));
        for (j, value) in a.iter_mut().enumerate() {
            let table = powers[j];
            let candidate = table ^ ((p[j + 6] ^ table) & seen_mask);
            *value ^= (candidate ^ *value) & bit_mask;
        }
        seen |= bit;
    }
    a
}
#[cfg(test)]
mod vectors;

#[path = "sampler_bundle.rs"]
mod sampler_bundle;
pub use sampler_bundle::{prefix13, Prefixes};
/// Refines the boundary `n` with one caller-owned 384-bit coin and the prefix that `prefix13`
/// computed for `n`. `bad` is true when `n` is outside -848..=296263653, when the coin is
/// zero, or when the coin falls in the guard band where neither side is decided. The caller
/// charges those events. For M = 65586/65536 and the base theta of the main crate, 848 is the
/// largest n with M * theta^n >= 1, and 296263653 the largest n with theta^n / M >= 2^-384.
pub fn refine_prefixed(raw: &[u64; 6], n: i64, prefix: &[u64; 6]) -> Result384 {
    let magnitude = n.unsigned_abs();
    let negative = opaque_mask((n < 0) as u64);
    let invalid = opaque_mask(opaque_mask((n < -848) as u64) | opaque_mask((n > 296263653) as u64));
    let a = sampler_bundle::power_prefixed(magnitude, prefix);
    let mut product = [0u64; 7];
    let mut carry = 0u128;
    let mut nz = 0;
    for i in 0..6 {
        let z = (raw[i] as u128) * 65586 + carry;
        product[i] = z as u64;
        carry = z >> 64;
        nz |= raw[i];
    }
    product[6] = carry as u64;
    let mut u = [0u64; 7];
    for i in 0..6 {
        u[i] = (product[i] >> 16) | (product[i + 1] << 48);
    }
    u[6] = product[6] >> 16;
    let low: [u64; 6] = core::array::from_fn(|i| u[i]);
    let p = mul(&low, &a);
    let mut v = [0u64; 7];
    let mut c = 0u128;
    for i in 0..6 {
        c += (p[i + 6] as u128) + (a[i] as u128) * (u[6] as u128);
        v[i] = c as u64;
        c >>= 64;
    }
    v[6] = c as u64;
    let mut aa = [0u64; 7];
    aa[..6].copy_from_slice(&a);
    let mut one = [0u64; 7];
    one[6] = 1;
    let posbelow = less(&u, &aa);
    let posabove = 1 - less(&u, &plus(&aa, 55));
    let negbelow = 1 - less(&one, &plus(&v, 20));
    let negabove = 1 - less(&v, &one);
    let zero = opaque_mask((magnitude == 0) as u64);
    let below = choose(zero, less(&u, &one), choose(negative, negbelow, posbelow));
    let above = choose(
        zero,
        1 - less(&u, &one),
        choose(negative, negabove, posabove),
    );
    let bad =
        opaque_mask(invalid | opaque_mask((nz == 0) as u64) | (1 - opaque_mask(below | above)));
    Result384 {
        value: n.wrapping_add(below as i64),
        boundary: n,
        bad: bad != 0,
    }
}

// The fixed-vector tests of `vectors.rs` exercise the shipped path through this helper.
#[cfg(test)]
fn refine(raw: &[u64; 6], n: i64) -> Result384 {
    let mut prefixes = Prefixes::zeroed();
    prefix13(&[n.unsigned_abs(); 13], &mut prefixes);
    refine_prefixed(raw, n, prefixes.get(0))
}
