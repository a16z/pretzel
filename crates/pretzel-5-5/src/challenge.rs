//! The 255-bit challenge family C_255 and its fold.

use crate::params::N;

/// A challenge is a 256-bit vector; bit i lives at index i.
pub type Challenge = [bool; N];

// Explicit returns keep mutually exclusive selector branches structurally aligned.
#[allow(clippy::needless_return)]
// Keep the integer predicate and its signedness explicit.
#[allow(clippy::manual_is_multiple_of)]
pub fn weight(c: &Challenge) -> usize {
    // SAFETY: `bool` is one byte holding 0 or 1, so the 256 bytes of `c` are
    // sixteen aligned-enough (unaligned loads are valid) blocks; every lane sums
    // at most sixteen ones. The reduction leaves the vector unit through UMOV.
    unsafe {
        use core::arch::aarch64::*;
        const _: () = assert!(N % 16 == 0 && N / 16 <= 255);
        let p = c.as_ptr().cast::<u8>();
        let mut acc = vdupq_n_u8(0);
        for b in 0..N / 16 {
            acc = vaddq_u8(acc, vld1q_u8(p.add(16 * b)));
        }
        return crate::ct::lanes::sum_u8x16(acc) as usize;
    }
}

/// Membership in C_255: weight < 128, or weight == 128 with c_255 = 0.
pub fn in_c255(c: &Challenge) -> bool {
    let w = weight(c);
    w < 128 || (w == 128 && !c[N - 1])
}

/// Fold 255 hash bits into C_255: x = (u, 0); output x if wt(x) <= 128,
/// else its bitwise complement.
// Keep the integer predicate and its signedness explicit.
#[allow(clippy::manual_is_multiple_of)]
pub fn fold(hash: &[u8; 32]) -> Challenge {
    let mut x = [false; N];
    for i in 0..(N - 1) {
        x[i] = (hash[i / 8] >> (i % 8)) & 1 == 1;
    }
    // x[255] = 0 appended
    let complement = crate::ct::opaque_mask(u64::from(weight(&x) > 128)) != 0;
    for bit in &mut x {
        *bit ^= complement;
    }
    x
}

/// Coefficientwise parity of the leading response polynomial.
pub fn parity_of(z0: &[i32; N]) -> Challenge {
    core::array::from_fn(|i| z0[i].rem_euclid(2) == 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fold_lands_in_c255() {
        for seed in 0u64..2000 {
            let mut h = [0u8; 32];
            let mut s = seed.wrapping_mul(0x9e3779b97f4a7c15).wrapping_add(1);
            for b in h.iter_mut() {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                *b = s as u8;
            }
            let c = fold(&h);
            assert!(in_c255(&c), "seed {seed}");
        }
    }

    #[test]
    fn fold_is_injective_on_samples() {
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        for seed in 0u64..2000 {
            let mut h = [0u8; 32];
            let mut s = seed.wrapping_mul(0x2545f4914f6cdd1d).wrapping_add(7);
            for b in h.iter_mut() {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                *b = s as u8;
            }
            h[31] &= 0x7f; // only 255 bits participate
            let c = fold(&h);
            assert!(seen.insert(c.to_vec()), "collision at seed {seed}");
        }
    }

    #[test]
    fn all_weights_below_128_fixed() {
        // a low-weight input folds to itself
        let mut h = [0u8; 32];
        h[0] = 0b101;
        let c = fold(&h);
        assert_eq!(weight(&c), 2);
        assert!(c[0] && c[2]);
    }

    #[test]
    fn heavy_input_complements() {
        let h = [0xffu8; 32]; // 255 ones -> wt 255 > 128 -> complement: wt 1 at position 255
        let c = fold(&h);
        assert_eq!(weight(&c), 1);
        assert!(c[N - 1]);
        assert!(in_c255(&c));
    }
}
