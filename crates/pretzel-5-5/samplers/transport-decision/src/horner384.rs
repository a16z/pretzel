// Included at the end of lib.rs: fixed-width floor(h*v/2^64)+c.
// h is a signed two's-complement 384-bit word; arithmetic wraps mod 2^384.
// All six input limbs are consumed before their respective slots are replaced.
#[inline(always)]
fn horner_step(h: &mut Word, v: u64, c: &Word) {
    let negative = opaque_mask(0u64.wrapping_sub(h[5] >> 63));
    let mut product_carry = ((h[0] as u128) * (v as u128)) >> 64;
    let mut addition_carry = 0u128;
    for i in 1..6 {
        let product = (h[i] as u128) * (v as u128) + product_carry;
        product_carry = product >> 64;
        let sum = (product as u64 as u128) + (c[i - 1] as u128) + addition_carry;
        h[i - 1] = sum as u64;
        addition_carry = sum >> 64;
    }
    h[5] = (product_carry as u64)
        .wrapping_sub(v & negative)
        .wrapping_add(c[5])
        .wrapping_add(addition_carry as u64);
}

#[cfg(test)]
mod horner_step_tests {
    use super::*;
    #[test]
    fn signed_horner_matches_full_product_and_carry_chains() {
        let mut state = 0x1298_54cd_3210_abefu64;
        for trial in 0..10000 {
            let mut next = || {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state
            };
            let mut h: Word = core::array::from_fn(|_| next());
            let mut c: Word = core::array::from_fn(|_| next());
            let mut v = next();
            match trial {
                0 => {
                    h = [0; 6];
                    c = [0; 6];
                    v = 0;
                }
                1 => {
                    h = [u64::MAX; 6];
                    c = [u64::MAX; 6];
                    v = u64::MAX;
                }
                2 => {
                    h = [u64::MAX; 6];
                    c = [1, 0, 0, 0, 0, 0];
                    v = 1;
                }
                3 => {
                    h = [0, 0, 0, 0, 0, 1 << 63];
                    v = u64::MAX;
                }
                4 => {
                    h[5] = i64::MAX as u64;
                    v = u64::MAX;
                }
                _ => {}
            }
            let mut z = mul(&h, &[v]);
            z[6] = z[6].wrapping_sub(v & 0u64.wrapping_sub(h[5] >> 63));
            let mut want: Word = core::array::from_fn(|i| z[i + 1]);
            add(&mut want, &c);
            horner_step(&mut h, v, &c);
            assert_eq!(h, want, "trial {trial}");
        }
    }
}
