//! Fixed-neighbor displacement routing for stable filters.
//! Active records carry marker bit 31, payload in the low B bits, and the
//! original position minus prefix rank in between. Inactive records are zero.
//! Monotone rank and displacement prevent collisions at every public stride.
//! This is not a routing algorithm for arbitrary permutations.
use zeroize::Zeroizing;

pub(crate) fn route<const B: u32>(mut records: Zeroizing<Vec<u32>>) -> Zeroizing<Vec<u32>> {
    let n = records.len();
    // Strides 1,2,4,... below n cover every displacement bit of values below n;
    // monotone displacements keep active records apart at every stage. That
    // argument does not need n to be a power of two, but this function requires
    // one, by the assertion below.
    assert!(n.is_power_of_two());
    assert!(B > 0 && B < 31 && n > 0 && n <= 1usize << (31 - B));
    let mut next = Zeroizing::new(vec![0u32; n]);
    let mut stride = 1;
    while stride < n {
        shift_stage(&records, &mut next, stride, (stride as u32) << B);
        core::mem::swap(&mut records, &mut next);
        stride *= 2;
    }
    records
}

/// Same network restricted to the public prefix that a bounded filter needs:
/// only strides up to `max_shift` (every active record moves by at most that
/// many positions when the filter succeeds), and at each stage only the
/// positions that later stages read for the first `needed` outputs. For every
/// filter whose displacements are all at most `max_shift`, the first `needed`
/// outputs equal those of `route`. Otherwise (an exhausted filter) the prefix
/// may hold partially routed or merged records; callers must not use them
/// beyond a canonical range mask. All bounds are public constants.
#[cfg(test)]
pub(crate) fn route_prefix<const B: u32>(
    mut records: Zeroizing<Vec<u32>>,
    needed: usize,
    max_shift: usize,
) -> Zeroizing<Vec<u32>> {
    let n = records.len();
    assert!(B > 0 && B < 31 && n.is_power_of_two() && n <= 1usize << (31 - B));
    assert!(max_shift.is_power_of_two() && max_shift < n && needed + 2 * max_shift <= n);
    let mut next = Zeroizing::new(vec![0u32; n]);
    let mut stride = 1;
    while stride <= max_shift {
        // Positions this stage must produce: the final `needed` plus every
        // later stride (each later stage reads `stride` positions further).
        let limit = needed + 2 * max_shift - 2 * stride;
        let extent = (limit + stride).min(n);
        shift_stage(
            &records[..extent],
            &mut next[..extent],
            stride,
            (stride as u32) << B,
        );
        core::mem::swap(&mut records, &mut next);
        stride *= 2;
    }
    records
}

/// `route_prefix` over two caller-owned buffers of equal length (no
/// allocation). Returns the buffer holding the routed records; the other one
/// holds the previous stage. Both belong to the erased signing scratch.
#[cfg(test)]
pub(crate) fn route_prefix_into<'a, const B: u32>(
    mut records: &'a mut [u32],
    mut next: &'a mut [u32],
    needed: usize,
    max_shift: usize,
) -> &'a mut [u32] {
    let n = records.len();
    assert_eq!(next.len(), n);
    assert!(B > 0 && B < 31 && n.is_power_of_two() && n <= 1usize << (31 - B));
    assert!(max_shift.is_power_of_two() && max_shift < n && needed + 2 * max_shift <= n);
    let mut stride = 1;
    while stride <= max_shift {
        let limit = needed + 2 * max_shift - 2 * stride;
        let extent = (limit + stride).min(n);
        shift_stage(
            &records[..extent],
            &mut next[..extent],
            stride,
            (stride as u32) << B,
        );
        core::mem::swap(&mut records, &mut next);
        stride *= 2;
    }
    records
}

#[inline(never)]
fn shift_stage(input: &[u32], out: &mut [u32], stride: usize, bit: u32) {
    let n = input.len();
    assert_eq!(out.len(), n);
    assert!(stride < n);
    let paired = n - stride;
    let mut i = 0;
    // SAFETY: NEON is in the baseline of every target this crate builds for. `out.len() == n` and
    // `stride < n` are asserted above. Under `i + 4 <= n - stride` the four-word loads at `i` and
    // at `i + stride` end at or before `n`, and so does the store to `out` at `i`. Loads and stores
    // are unaligned forms; `input` and `out` cannot overlap. The asm template is an assembler
    // comment that emits no instruction.
    unsafe {
        use core::arch::aarch64::*;
        let mask = vdupq_n_u32(bit);
        let zero = vdupq_n_u32(0);
        // Both addresses below are public. Unaligned vector loads are valid;
        // i+stride+4<=n guarantees the shifted block lies entirely in bounds.
        while i + 4 <= paired {
            let a = vld1q_u32(input.as_ptr().add(i));
            let b = vld1q_u32(input.as_ptr().add(i + stride));
            let mut keep = vceqq_u32(vandq_u32(a, mask), zero);
            let mut take = vmvnq_u32(vceqq_u32(vandq_u32(b, mask), zero));
            core::arch::asm!("/* {keep:v} {take:v} */",keep=inout(vreg) keep,take=inout(vreg) take,options(nomem,nostack,preserves_flags));
            let value = vbicq_u32(vorrq_u32(vandq_u32(a, keep), vandq_u32(b, take)), mask);
            vst1q_u32(out.as_mut_ptr().add(i), value);
            i += 4;
        }
    }
    while i < paired {
        let a = input[i];
        let b = input[i + stride];
        let keep = crate::ct::opaque_mask(0u64.wrapping_sub(u64::from(a & bit == 0))) as u32;
        let take = crate::ct::opaque_mask(0u64.wrapping_sub(u64::from(b & bit != 0))) as u32;
        out[i] = ((a & keep) | (b & take)) & !bit;
        i += 1;
    }
    // SAFETY: NEON is in the baseline of every target this crate builds for. Under `i + 4 <= n` the
    // four-word load from `input` and the store to `out`, both at `i`, stay inside slices of length
    // `n`. The asm template is an assembler comment that emits no instruction.
    unsafe {
        use core::arch::aarch64::*;
        let mask = vdupq_n_u32(bit);
        let zero = vdupq_n_u32(0);
        while i + 4 <= n {
            let a = vld1q_u32(input.as_ptr().add(i));
            let mut keep = vceqq_u32(vandq_u32(a, mask), zero);
            core::arch::asm!("/* {keep:v} */",keep=inout(vreg) keep,options(nomem,nostack,preserves_flags));
            vst1q_u32(out.as_mut_ptr().add(i), vandq_u32(a, keep));
            i += 4;
        }
    }
    while i < n {
        let a = input[i];
        let keep = crate::ct::opaque_mask(0u64.wrapping_sub(u64::from(a & bit == 0))) as u32;
        out[i] = a & keep;
        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn check<const B: u32>(active: &[bool], reverse: bool) {
        let n = active.len();
        let mut rank = 0u32;
        let mut words = Zeroizing::new(vec![0u32; n]);
        let mut expected = Vec::new();
        for i in 0..n {
            let src = if reverse { n - 1 - i } else { i };
            let value = (src as u32 * 137) & ((1 << B) - 1);
            if active[src] {
                words[i] = (1 << 31) | ((i as u32 - rank) << B) | value;
                expected.push((1 << 31) | value);
                rank += 1;
            }
        }
        expected.resize(n, 0);
        assert_eq!(*route::<B>(words), expected);
    }
    #[test]
    fn bounded_prefix_matches_full_network_for_bounded_filters() {
        let mut state = 0x5eed1234abcdu64;
        for (n, needed, max_shift) in [
            (2048usize, 768usize, 512usize),
            (2048, 1024, 256),
            (256, 64, 32),
            (64, 16, 8),
        ] {
            for trial in 0..64 {
                // At most max_shift rejected records among the first needed+max_shift candidates.
                let candidates = needed + max_shift;
                let rejected = trial % (max_shift + 1);
                let mut active = vec![false; n];
                let mut positions: Vec<usize> = (0..candidates).collect();
                for i in (1..candidates).rev() {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    let j = (state as usize) % (i + 1);
                    positions.swap(i, j);
                }
                for &p in &positions[rejected..] {
                    active[p] = true;
                }
                let mut words = Zeroizing::new(vec![0u32; n]);
                let mut rank = 0u32;
                for i in 0..n {
                    if active[i] {
                        words[i] =
                            (1 << 31) | ((i as u32 - rank) << 13) | ((i as u32 * 137) & 8191);
                        rank += 1;
                    }
                }
                let full = route::<13>(words.clone());
                let bounded = route_prefix::<13>(words, needed, max_shift);
                assert_eq!(&bounded[..needed], &full[..needed], "n={n} trial={trial}");
            }
        }
    }
    #[test]
    fn every_small_filter_and_larger_patterns_preserve_stable_order() {
        for n in [1, 2, 4, 8, 16] {
            for mask in 0..1u32 << n {
                let active: Vec<_> = (0..n).map(|i| mask >> i & 1 != 0).collect();
                check::<8>(&active, false);
                check::<13>(&active, true);
            }
        }
        let mut state = 0x871692338u64;
        for n in [32, 64, 128, 256, 512, 1024, 2048, 4096] {
            for cutoff in [0, 1, 8, 15, 16] {
                let active: Vec<_> = (0..n)
                    .map(|_| {
                        state ^= state << 13;
                        state ^= state >> 7;
                        state ^= state << 17;
                        state & 15 < cutoff
                    })
                    .collect();
                check::<8>(&active, true);
                check::<13>(&active, false);
            }
        }
    }
}
