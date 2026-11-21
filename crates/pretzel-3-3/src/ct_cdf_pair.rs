//! Fixed-offset compare-exchange for four-word CDF records on AArch64.
//! Network indices and direction are public. All payload words are preserved.
//! DIT and a proof for the compiled code are requirements of the target.

/// # Safety
///
/// `ap` and `bp` must each be valid for reads and writes of one `[u64; 4]`, and the two records
/// must not overlap. The template loads both records, then stores both.
#[inline(always)]
unsafe fn exchange<const ASC: bool>(ap: *mut [u64; 4], bp: *mut [u64; 4]) {
    // SAFETY contract: ap and bp point to disjoint, initialized four-word
    // records. All memory operands below have one of those public bases and
    // fixed offsets. Flags and every scratch register are declared clobbered.
    macro_rules! body {($cmp0:literal,$cmp1:literal,$cmp2:literal,$cmp3:literal)=>{
        core::arch::asm!(
            "ldp {a0}, {a1}, [{ap}]", "ldp {a2}, {a3}, [{ap}, #16]",
            "ldp {b0}, {b1}, [{bp}]", "ldp {b2}, {b3}, [{bp}, #16]",
            "and {ta}, {a3}, #1", "and {tb}, {b3}, #1",
            $cmp0,$cmp1,$cmp2,$cmp3,
            "mov {tmp}, {a0}","csel {a0}, {b0}, {a0}, lo","csel {b0}, {tmp}, {b0}, lo",
            "mov {tmp}, {a1}","csel {a1}, {b1}, {a1}, lo","csel {b1}, {tmp}, {b1}, lo",
            "mov {tmp}, {a2}","csel {a2}, {b2}, {a2}, lo","csel {b2}, {tmp}, {b2}, lo",
            "mov {tmp}, {a3}","csel {a3}, {b3}, {a3}, lo","csel {b3}, {tmp}, {b3}, lo",
            "stp {a0}, {a1}, [{ap}]", "stp {a2}, {a3}, [{ap}, #16]",
            "stp {b0}, {b1}, [{bp}]", "stp {b2}, {b3}, [{bp}, #16]",
            ap=in(reg) ap,bp=in(reg) bp,
            a0=out(reg) _,a1=out(reg) _,a2=out(reg) _,a3=out(reg) _,
            b0=out(reg) _,b1=out(reg) _,b2=out(reg) _,b3=out(reg) _,
            ta=out(reg) _,tb=out(reg) _,tmp=out(reg) _,options(nostack)
        );
    }}
    if ASC {
        body!(
            "subs xzr, {tb}, {ta}",
            "sbcs xzr, {b2}, {a2}",
            "sbcs xzr, {b1}, {a1}",
            "sbcs xzr, {b0}, {a0}"
        );
    } else {
        body!(
            "subs xzr, {ta}, {tb}",
            "sbcs xzr, {a2}, {b2}",
            "sbcs xzr, {a1}, {b1}",
            "sbcs xzr, {a0}, {b0}"
        );
    }
}

#[inline(always)]
fn block<const ASC: bool>(rows: &mut [[u64; 4]], distance: usize) {
    assert_eq!(rows.len(), 2 * distance);
    let ptr = rows.as_mut_ptr();
    for offset in 0..distance {
        // SAFETY: `rows.len() == 2 * distance` is asserted above, `offset < distance` and `distance
        // + offset < 2 * distance`. The two complete records are in bounds of the exclusively
        // borrowed slice and disjoint, which is what `exchange` requires. No secret-derived raw
        // pointer.
        unsafe {
            exchange::<ASC>(ptr.add(offset), ptr.add(distance + offset));
        }
    }
}

#[inline(never)]
pub(crate) fn sort(rows: &mut [[u64; 4]]) {
    let n = rows.len();
    assert!(n.is_power_of_two());
    let mut width = 2;
    while width <= n {
        let mut distance = width / 2;
        while distance != 0 {
            // Both public powers divide n, so no final partial block exists.
            for (number, rows) in rows.chunks_exact_mut(2 * distance).enumerate() {
                if (number * 2 * distance) & width == 0 {
                    block::<true>(rows, distance);
                } else {
                    block::<false>(rows, distance);
                }
            }
            distance /= 2;
        }
        width *= 2;
    }
}

#[inline(never)]
pub(crate) fn merge(rows: &mut [[u64; 4]]) {
    let n = rows.len();
    assert!(n.is_power_of_two());
    let mut distance = n / 2;
    while distance != 0 {
        for rows in rows.chunks_exact_mut(2 * distance) {
            block::<true>(rows, distance);
        }
        distance /= 2;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn key(a: [u64; 4]) -> [u64; 4] {
        [a[0], a[1], a[2], a[3] & 1]
    }
    #[test]
    fn both_directions_preserve_records_at_every_comparison_limb() {
        let mut state = 0xc761822318u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..10000 {
            let a = core::array::from_fn(|_| next());
            for changed in 0..=4 {
                let mut b = core::array::from_fn(|_| next());
                b[..changed].copy_from_slice(&a[..changed]);
                let mut up = [a, b];
                let mut down = [a, b];
                unsafe {
                    exchange::<true>(up.as_mut_ptr(), up.as_mut_ptr().add(1));
                    exchange::<false>(down.as_mut_ptr(), down.as_mut_ptr().add(1));
                }
                assert_eq!(up, if key(b) < key(a) { [b, a] } else { [a, b] });
                assert_eq!(down, if key(a) < key(b) { [b, a] } else { [a, b] });
            }
        }
    }
}
