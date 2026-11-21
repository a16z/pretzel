//! Exact secant weights, indexed by decoded signed public values.
//! No approximation.
use super::W_HEAD;
const SIGNED: [u64; 577] = {
    let mut table = [0; 577];
    let mut i = 0;
    while i < 577 {
        let x = i as i32 - 288;
        let a = x.unsigned_abs() as usize;
        // This compile-time bound rules out low-word carry for all 1536 terms.
        assert!((W_HEAD[a] as u64) * 1536 < (1u64 << 32));
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
            // only after decode_fields establishes every coefficient is in
            // [-288,288], including exceptional values.
            // Shared immutable borrow prevents changing the validated values.
            let index = (block[j] + 288) as usize;
            debug_assert!(index < SIGNED.len(), "decoded head exceeds secant domain");
            // SAFETY: DecodedHead's codec-private constructor bounds every coefficient to
            // [-288,288]. Thus index=block[j]+288 lies in 0..577, the SIGNED table extent; the
            // immutable borrow preserves that validation.
            sums[j] += unsafe { *SIGNED.get_unchecked(index) };
        }
    }
    sums.into_iter().sum()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn secant_complete_table_and_decoded_heads() {
        for value in -288i32..=288 {
            let a = value.unsigned_abs() as usize;
            assert_eq!(
                SIGNED[(value + 288) as usize],
                ((a * a) as u64) << 32 | W_HEAD[a] as u64
            );
        }
        let mut rng = 0xabcdef123456u64;
        for trial in 0..10000 {
            let mut bytes = [0u8; crate::signature_codec::HEAD_BYTES];
            for byte in &mut bytes[..1472] {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                *byte = rng as u8;
            }
            // Exercise valid exceptions at extrema and both sign directions.
            if trial % 3 != 0 {
                let position = 256 + (trial % 1280);
                let sign = trial % 2;
                bytes[192 + position - 256] = if sign == 0 { 224 } else { 32 };
                let record = position | (sign << 11);
                bytes[1472] = 1;
                bytes[1473] = record as u8;
                bytes[1474] = (record >> 8) as u8;
            }
            let mut values = [0; 1536];
            let (head, _) =
                crate::signature_codec::decode_fields_borrowed(&bytes, &mut values).unwrap();
            let packed = packed(&head);
            assert_eq!(packed, super::super::public_head_packed_reference(&head));
            let norm: u64 = head
                .values()
                .iter()
                .map(|v| {
                    let a = v.unsigned_abs() as u64;
                    a * a
                })
                .sum();
            let score: u64 = head
                .values()
                .iter()
                .map(|v| W_HEAD[v.unsigned_abs() as usize] as u64)
                .sum();
            assert_eq!(packed >> 32, norm);
            assert_eq!(packed as u32 as u64, score);
        }
    }
}
