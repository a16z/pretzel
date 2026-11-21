//! Exact secant weights, indexed by decoded signed public values.
//! No approximation.
use super::W_HEAD;
const SIGNED: [u64; 577] = {
    assert!(1024u64 * 288 * 288 < (1u64 << 32));
    let mut table = [0; 577];
    let mut i = 0;
    while i < 577 {
        let x = i as i32 - 288;
        let a = x.unsigned_abs() as usize;
        // This compile-time bound rules out low-word carry for all 1024 terms.
        assert!((W_HEAD[a] as u64) * 1024 < (1u64 << 32));
        table[i] = ((a * a) as u64) << 32 | W_HEAD[a] as u64;
        i += 1;
    }
    table
};
pub(super) fn packed(head: &crate::signature_codec::DecodedHead<'_>) -> u64 {
    let mut sums = [0u64; 8];
    for block in head.values().chunks_exact(8) {
        for j in 0..8 {
            // SAFETY: DecodedHead has one codec-private constructor, reached
            // only after decode_head establishes every coefficient is in
            // [-288,288], including exceptional values.
            // Shared immutable borrow prevents changing the validated values.
            let index = (block[j] + 288) as usize;
            debug_assert!(index < SIGNED.len(), "decoded head exceeds secant domain");
            // SAFETY: by the argument above `block[j]` is in [-288, 288], so `index` is at most
            // 576, below the 577 entries of `SIGNED`.
            sums[j] += unsafe { *SIGNED.get_unchecked(index) };
        }
    }
    sums.into_iter().sum()
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature_codec as codec;

    #[test]
    fn public_signed_head_caps_complete_domain_and_decoded_heads() {
        for value in -288i32..=288 {
            let a = value.unsigned_abs() as usize;
            assert_eq!(
                SIGNED[(value + 288) as usize],
                ((a * a) as u64) << 32 | W_HEAD[a] as u64
            );
        }
        for position in [0, 255, 256, 1023] {
            let cap = if position < 256 { 31 } else { 255 };
            for value in -cap..=cap {
                // One extreme value fits the capacity of the sparse exception list;
                // the other coefficients are small.
                let mut values = core::array::from_fn::<_, 1024, _>(|i| (i % 7) as i32 - 3);
                values[position] = value;
                let mut bytes = [0; codec::HEAD_BYTES];
                let mut hint = [0; codec::HINT_BYTES];
                codec::encode_admitted(&values, &[0; 768], &mut bytes, &mut hint);
                let mut decoded_values = [0; 1024];
                let head = codec::decode_head_borrowed(&bytes, &mut decoded_values).unwrap();
                assert_eq!(head.values(), &values);
                let actual = packed(&head);
                assert_eq!(actual, super::super::public_head_packed_reference(&head));
                let norm: u64 = values.iter().map(|&v| (v as i64 * v as i64) as u64).sum();
                let score: u64 = values
                    .iter()
                    .map(|v| W_HEAD[v.unsigned_abs() as usize] as u64)
                    .sum();
                assert_eq!(actual >> 32, norm);
                assert_eq!(actual as u32 as u64, score);
            }
        }
    }
}
