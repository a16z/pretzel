//! Exact two-symbol CDF groups. All preparation inputs are immutable public CDFs.
#[cfg(any(test, not(all(target_arch = "aarch64", target_endian = "little"))))]
use crate::ct::{ct_eq_limbs, ct_lt_limbs_be, opaque_mask};
#[cfg(any(test, not(all(target_arch = "aarch64", target_endian = "little"))))]
use zeroize::Zeroizing;
#[cfg(any(test, not(all(target_arch = "aarch64", target_endian = "little"))))]
const MAX: [u64; 3] = [u64::MAX; 3];

// For ordered endpoints, floor((lo+hi)/2)+round_up. Arithmetic wraps for
// discarded slots; no data-dependent range assertion or branch is introduced.
#[inline(never)]
pub(crate) fn midpoint(lo: [u64; 3], hi: [u64; 3], round_up: u64) -> [u64; 3] {
    let mut difference = [0u64; 3];
    let mut borrow = 0i128;
    for i in (0..3).rev() {
        let v = hi[i] as i128 - lo[i] as i128 - borrow;
        difference[i] = v as u64;
        borrow = (v >> 127) & 1;
    }
    let half = [
        difference[0] >> 1,
        (difference[1] >> 1) | (difference[0] << 63),
        (difference[2] >> 1) | (difference[1] << 63),
    ];
    let mut out = [0; 3];
    let mut carry = round_up as u128;
    for i in (0..3).rev() {
        let v = lo[i] as u128 + half[i] as u128 + carry;
        out[i] = v as u64;
        carry = v >> 64;
    }
    out
}

pub(crate) fn prepare(bounds: &[[u64; 3]]) -> Vec<[u64; 4]> {
    assert!(!bounds.is_empty() && bounds.len() % 2 == 1 && bounds.len() < 1 << 15);
    assert!(bounds.windows(2).all(|w| w[0] <= w[1]));
    let mut out: Vec<[u64; 4]> = Vec::new();
    for i in (0..bounds.len()).step_by(2) {
        let has_mid = i + 1 < bounds.len();
        let mut round_up = 0;
        if has_mid {
            let floor = midpoint(bounds[i], bounds[i + 2], 0);
            round_up = u64::from(bounds[i + 1] != floor);
            assert_eq!(
                midpoint(bounds[i], bounds[i + 2], round_up),
                bounds[i + 1],
                "exact CDF midpoint reconstruction"
            );
        }
        let tag = (((i + 1) as u64) << 1) | (round_up << 16) | (u64::from(has_mid) << 17);
        let row = [bounds[i][0], bounds[i][1], bounds[i][2], tag];
        if out.last().is_some_and(|last| last[..3] == row[..3]) {
            *out.last_mut().unwrap() = row;
        } else {
            out.push(row);
        }
    }
    out
}

#[cfg(any(test, not(all(target_arch = "aarch64", target_endian = "little"))))]
pub(crate) fn classify(
    groups: &[[u64; 4]],
    z: &[u64; 3],
    draws: &[[u64; 3]],
) -> Zeroizing<Vec<[u64; 2]>> {
    if draws.is_empty() {
        return Zeroizing::new(Vec::new());
    }
    assert!(draws.len() < 1 << 16);
    let queries = draws.len().next_power_of_two();
    let n = (queries + groups.len()).next_power_of_two();
    let mut records = Zeroizing::new(vec![[u64::MAX; 4]; n]);
    for (i, u) in draws.iter().enumerate() {
        records[i] = [u[0], u[1], u[2], 2 * i as u64 + 1];
    }
    crate::ct_sort::sort_cdf::<true, 4>(&mut records[..queries]);
    for (i, b) in groups.iter().enumerate() {
        records[n - 1 - i] = *b;
    }
    crate::ct_sort::merge_cdf(&mut records);
    let mut following = Zeroizing::new(vec![[0u64; 3]; n]);
    let mut next = Zeroizing::new(MAX);
    for i in (0..n).rev() {
        let boundary = opaque_mask(0u64.wrapping_sub(1 ^ (records[i][3] & 1)));
        for k in 0..3 {
            next[k] = (records[i][k] & boundary) | (next[k] & !boundary);
        }
        following[i] = *next;
    }
    let mut last = Zeroizing::new([0u64; 3]);
    let mut metadata = 0u64;
    let mut seen = 0u64;
    let mut results = Zeroizing::new(vec![u32::MAX; n]);
    for i in 0..n {
        let row = records[i];
        let boundary = opaque_mask(0u64.wrapping_sub(1 ^ (row[3] & 1)));
        for k in 0..3 {
            last[k] = (row[k] & boundary) | (last[k] & !boundary);
        }
        metadata = (row[3] & boundary) | (metadata & !boundary);
        seen |= boundary;
        let u = [row[0], row[1], row[2]];
        let mid = Zeroizing::new(midpoint(*last, following[i], (metadata >> 16) & 1));
        let present = opaque_mask(0u64.wrapping_sub((metadata >> 17) & 1));
        let count = ((metadata >> 1) & 0x7fff) + ((!ct_lt_limbs_be(&u, &mid) & present) & 1);
        let tie = (ct_eq_limbs(&u, &last) & seen)
            | (ct_eq_limbs(&u, &mid) & present)
            | ct_eq_limbs(&u, z);
        let query = opaque_mask(
            crate::ct::ct_lt_u64(row[3], 2 * draws.len() as u64) & 0u64.wrapping_sub(row[3] & 1),
        ) as u32;
        let packed = (((row[3] >> 1) << 16) | (count << 1) | (tie & 1)) as u32;
        results[i] = (packed & query) | !query;
    }
    crate::ct_sort::sort_u32(&mut results);
    Zeroizing::new(
        results[..draws.len()]
            .iter()
            .map(|&r| {
                [
                    ((r & 0xffff) >> 1) as u64,
                    0u64.wrapping_sub((r & 1) as u64),
                ]
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn grouped_scan_preserves_duplicate_midpoint_and_endpoint_ties() {
        for bounds in [
            vec![[0, 0, 0]],
            vec![[0, 0, 1], [0, 0, 2], [0, 0, 3]],
            vec![[0, 0, 1], [0, 0, 1], [0, 0, 1], [0, 0, 2], [0, 0, 3]],
            vec![[0, 0, 1], [0, 0, 2], [0, 0, 2], [0, 0, 2], [0, 0, 3]],
            vec![MAX; 5],
        ] {
            let g = prepare(&bounds);
            let z = *bounds.last().unwrap();
            let queries: Vec<_> = (0..16).map(|i| [0, 0, i]).chain([MAX]).collect();
            let actual = classify(&g, &z, &queries);
            for (i, u) in queries.iter().enumerate() {
                assert_eq!(
                    actual[i],
                    [
                        bounds.iter().filter(|b| *b <= u).count() as u64,
                        0u64.wrapping_sub(u64::from(bounds.contains(u) || *u == z))
                    ]
                );
            }
        }
    }
}
