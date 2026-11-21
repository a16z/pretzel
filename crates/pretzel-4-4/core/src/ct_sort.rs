//! Public-size bitonic networks. Every compared address and direction is public.
use crate::ct::{ct_lt_u64, opaque_mask};

#[inline(always)]
#[cfg(test)]
fn cdf_less<const W: usize>(a: &[u64; W], b: &[u64; W]) -> u64 {
    #[cfg(target_arch = "aarch64")]
    {
        let result;
        // SAFETY: register-only unsigned subtraction. The tag bit is the
        // least-significant comparison word; no memory, branch or stack use.
        // Flags are clobbered. DIT remains the caller's separate contract.
        unsafe {
            core::arch::asm!(
            "subs xzr, {at}, {bt}",
            "sbcs xzr, {a2}, {b2}",
            "sbcs xzr, {a1}, {b1}",
            "sbcs xzr, {a0}, {b0}",
            "csetm {out}, lo",
            at=in(reg) a[3]&1, bt=in(reg) b[3]&1,
            a2=in(reg) a[2], b2=in(reg) b[2],
            a1=in(reg) a[1], b1=in(reg) b[1],
            a0=in(reg) a[0], b0=in(reg) b[0],
            out=lateout(reg) result, options(nomem,nostack));
        }
        result
    }
}

/// Fixed bitonic network over public power-of-two lengths. SIMD comparisons
/// operate only on register values; every load, store and direction is public.
#[inline(never)]
pub(crate) fn sort_u32(words: &mut [u32]) {
    assert!(words.len().is_power_of_two());
    #[cfg(target_arch = "aarch64")]
    if words.len() >= 4 {
        // SAFETY: AArch64 NEON is enabled by this build. Length is a power of
        // two >=4; all vector blocks contain four in-bounds, disjoint words.
        unsafe {
            sort_u32_neon(words);
        }
        return;
    }
    let mut width = 2;
    while width <= words.len() {
        let mut distance = width / 2;
        while distance != 0 {
            for base in (0..words.len()).step_by(2 * distance) {
                for offset in 0..distance {
                    let i = base + offset;
                    let j = i + distance;
                    let (a, b) = (words[i], words[j]);
                    let mask = if i & width == 0 {
                        ct_lt_u64(b as u64, a as u64)
                    } else {
                        ct_lt_u64(a as u64, b as u64)
                    };
                    let diff = (a ^ b) & opaque_mask(mask) as u32;
                    words[i] = a ^ diff;
                    words[j] = b ^ diff;
                }
            }
            distance /= 2;
        }
        width *= 2;
    }
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
/// # Safety
/// Call only on AArch64 with NEON, guaranteed by the supported target and the module cfg.
/// words.len() must be a power of two of at least four.
unsafe fn sort_u32_neon(words: &mut [u32]) {
    // SAFETY: The caller guarantees a power-of-two length >=4. Each distance divides the
    // length, and four-lane loads/stores fit each network half or four-word tile; words is
    // exclusively borrowed.
    unsafe {
        use core::arch::aarch64::*;
        let ptr = words.as_mut_ptr();
        let n = words.len();
        let mut width = 2;
        while width <= n {
            let mut distance = width / 2;
            while distance != 0 {
                if distance >= 4 {
                    for base in (0..n).step_by(2 * distance) {
                        for offset in (0..distance).step_by(4) {
                            let i = base + offset;
                            let j = i + distance;
                            let a = vld1q_u32(ptr.add(i));
                            let b = vld1q_u32(ptr.add(j));
                            let lo = vminq_u32(a, b);
                            let hi = vmaxq_u32(a, b);
                            let (x, y) = if i & width == 0 { (lo, hi) } else { (hi, lo) };
                            vst1q_u32(ptr.add(i), x);
                            vst1q_u32(ptr.add(j), y);
                        }
                    }
                } else {
                    let lanes = if width == 2 {
                        [u32::MAX, 0, 0, u32::MAX]
                    } else if distance == 1 {
                        [u32::MAX, 0, u32::MAX, 0]
                    } else {
                        [u32::MAX, u32::MAX, 0, 0]
                    };
                    let mask = vld1q_u32(lanes.as_ptr());
                    for i in (0..n).step_by(4) {
                        let a = vld1q_u32(ptr.add(i));
                        let b = if distance == 1 {
                            vrev64q_u32(a)
                        } else {
                            vextq_u32::<2>(a, a)
                        };
                        let lo = vminq_u32(a, b);
                        let hi = vmaxq_u32(a, b);
                        let mask = if i & width == 0 {
                            mask
                        } else {
                            vmvnq_u32(mask)
                        };
                        vst1q_u32(ptr.add(i), vbslq_u32(mask, lo, hi));
                    }
                }
                distance /= 2;
            }
            width *= 2;
        }
    }
}

/// Ascending merge of a bitonic run. The peak may occur at any position.
#[inline(never)]
#[cfg(test)]
pub(crate) fn merge_cdf<const W: usize>(rows: &mut [[u64; W]]) {
    #[cfg(target_arch = "aarch64")]
    if W == 4 {
        // The const width is checked before reinterpreting the same u64 rows.
        let rows=
        // SAFETY: W==4 is checked before the cast. [u64; W] and [u64; 4] then have identical size,
        // alignment and validity; the slice keeps its original length and exclusive borrow.
        unsafe {core::slice::from_raw_parts_mut(rows.as_mut_ptr().cast::<[u64;4]>(),rows.len())};
        crate::ct_cdf_pair::merge(rows);
        return;
    }

    assert!(rows.len().is_power_of_two());
    let mut distance = rows.len() / 2;
    while distance != 0 {
        for base in (0..rows.len()).step_by(2 * distance) {
            for offset in 0..distance {
                let i = base + offset;
                let j = i + distance;
                let (a, b) = (rows[i], rows[j]);
                let less = cdf_less(&b, &a);
                let mask = opaque_mask(less);
                for limb in 0..W {
                    let diff = (a[limb] ^ b[limb]) & mask;
                    rows[i][limb] = a[limb] ^ diff;
                    rows[j][limb] = b[limb] ^ diff;
                }
            }
        }
        distance /= 2;
    }
}

/// Sort CDF records by (192-bit word, boundary before query), or by original
/// tag. The public const selects the order; payload moves with every exchange.
#[inline(never)]
#[cfg(test)]
pub(crate) fn sort_cdf<const WORD_ORDER: bool, const W: usize>(rows: &mut [[u64; W]]) {
    #[cfg(target_arch = "aarch64")]
    if WORD_ORDER && W == 4 {
        let rows=
        // SAFETY: W==4 is checked before the cast. [u64; W] and [u64; 4] then have identical size,
        // alignment and validity; the slice keeps its original length and exclusive borrow.
        unsafe {core::slice::from_raw_parts_mut(rows.as_mut_ptr().cast::<[u64;4]>(),rows.len())};
        crate::ct_cdf_pair::sort(rows);
        return;
    }

    assert!(rows.len().is_power_of_two());
    let n = rows.len();
    let mut width = 2;
    while width <= n {
        let mut distance = width / 2;
        while distance != 0 {
            for base in (0..n).step_by(2 * distance) {
                for offset in 0..distance {
                    let i = base + offset;
                    let j = i + distance;
                    let (a, b) = (rows[i], rows[j]);
                    let (x, y) = if i & width == 0 { (b, a) } else { (a, b) };
                    let less = if WORD_ORDER {
                        {
                            cdf_less(&x, &y)
                        }
                    } else {
                        ct_lt_u64(x[3], y[3])
                    };
                    let mask = opaque_mask(less);
                    for limb in 0..W {
                        let diff = (a[limb] ^ b[limb]) & mask;
                        rows[i][limb] = a[limb] ^ diff;
                        rows[j][limb] = b[limb] ^ diff;
                    }
                }
            }
            distance /= 2;
        }
        width *= 2;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn u32_network_matches_total_order() {
        let mut seed = 0xabe7168364u64;
        for log in 0..=14 {
            for pattern in 0..6 {
                let mut words: Vec<u32> = (0..1 << log)
                    .map(|i| {
                        seed ^= seed << 13;
                        seed ^= seed >> 7;
                        seed ^= seed << 17;
                        match pattern {
                            0 => 0,
                            1 => u32::MAX,
                            2 => i,
                            3 => u32::MAX - i,
                            4 => seed as u32 % 7,
                            _ => seed as u32,
                        }
                    })
                    .collect();
                let mut expected = words.clone();
                expected.sort_unstable();
                sort_u32(&mut words);
                assert_eq!(words, expected, "log={log} pattern={pattern}");
            }
        }
    }
    #[test]
    fn borrow_comparison_matches_lexicographic_order() {
        let mut seed = 0x2736561682734u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..10000 {
            let a = [next(), next(), next(), next() & 1];
            let b = [next(), next(), next(), next() & 1];
            assert_eq!(cdf_less(&a, &b), 0u64.wrapping_sub(u64::from(a < b)));
            for limb in 0..4 {
                let mut b = a;
                b[limb] = b[limb].wrapping_add(1);
                b[3] &= 1;
                assert_eq!(cdf_less(&a, &b), 0u64.wrapping_sub(u64::from(a < b)));
                assert_eq!(cdf_less(&b, &a), 0u64.wrapping_sub(u64::from(b < a)));
            }
            assert_eq!(cdf_less(&a, &a), 0);
        }
    }
}
