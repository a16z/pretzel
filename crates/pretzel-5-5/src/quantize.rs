//! Quantizer Q_{q,L} and canonical cell centers.

use crate::params::{LQ, Q};

/// Label table: LABELS[x] = floor(L x / q) for x in [0, q) (exact).
#[allow(dead_code)]
const LABELS: [u8; Q as usize] = {
    let mut t = [0u8; Q as usize];
    let mut x = 0usize;
    while x < Q as usize {
        t[x] = ((LQ as i64 * x as i64) / Q as i64) as u8;
        x += 1;
    }
    t
};

/// Cell label of x in [0, q).
///
/// The table is not touched: the label is floor(L x / q) by an exact
/// multiply-shift, so the unreleased commitment value never selects an
/// address. The multiply-shift agrees with the table on all
/// 7681 inputs (`ct_label_and_center_match_tables`).
#[inline]
pub fn q_label(x: i32) -> i32 {
    debug_assert!((0..Q).contains(&x));
    {
        q_label_ct(x)
    }
}

/// Barrett constant for division by q of y = L x < 2^19: m = ceil(2^32 / q)
/// = 559168, error e = m q - 2^32 = 2112, and floor(y m / 2^32) = floor(y / q)
/// exactly whenever y e < 2^32, which the assertion below checks for every y <= L q.
const LABEL_MUL: u64 = (1u64 << 32).div_ceil(Q as u64);
const _: () = assert!(LABEL_MUL == 559168);
const _: () =
    assert!((LQ as u64) * (Q as u64) * (LABEL_MUL * Q as u64 - (1u64 << 32)) < (1u64 << 32));

/// Address-independent label: no table, no branch.
#[inline(always)]
pub fn q_label_ct(x: i32) -> i32 {
    let y = (LQ as u64) * (x as u32 as u64);
    ((y * LABEL_MUL) >> 32) as i32
}

/// Reference formula, kept as the oracle for the table.
#[cfg(test)]
fn q_label_reference(x: i32) -> i32 {
    ((LQ as i64 * x as i64) / Q as i64) as i32
}

/// Left edge of cell j: smallest x with label j = ceil(q*j/L).
#[inline]
// Keep explicit integer boundary arithmetic in the implementation and oracle.
#[allow(clippy::manual_div_ceil)]
pub fn cell_left(j: i32) -> i32 {
    ((Q as i64 * j as i64 + LQ as i64 - 1) / LQ as i64) as i32
}

pub fn cell_size(j: i32) -> i32 {
    cell_left(j + 1) - cell_left(j)
}

/// Canonical center C(j): midpoint for odd-size cells; for even-size cells,
/// alternate lower/upper midpoint by the cell's rank among even-size cells
/// (rank 0 lower, rank 1 upper, ...). For this parameter set C(0) = 60
/// (test `paper_center_example`).
pub fn center(j: i32) -> i32 {
    debug_assert!((0..LQ).contains(&j));
    {
        center_ct(j)
    }
}

/// Address-independent center: the closed formula evaluated with constant
/// divisors (compiled to multiply-shift), never the CENTERS table.
#[inline(always)]
pub fn center_ct(j: i32) -> i32 {
    const {
        assert!(Q == 7681 && LQ == 64);
    }
    120 * j
        + 60
        + ((crate::ct::opaque_mask(u64::from(j != 0))
            & crate::ct::opaque_mask(u64::from((j & 1) == 0))) as i32)
}

/// Closed formula (paper), evaluated once per label into CENTERS.
// Keep explicit integer boundary arithmetic in the implementation and oracle.
#[allow(clippy::manual_div_ceil)]
const fn center_formula(j: i32) -> i32 {
    let left = (Q * j + LQ - 1) / LQ;
    let next = (Q * (j + 1) + LQ - 1) / LQ;
    let size = next - left;
    let mut rank = 0;
    let mut k = 0;
    while k < j {
        let a = (Q * k + LQ - 1) / LQ;
        let b = (Q * (k + 1) + LQ - 1) / LQ;
        if (b - a) % 2 == 0 {
            rank += 1;
        }
        k += 1;
    }
    left + (size - 1) / 2 + ((1 ^ (size & 1)) & (rank & 1))
}

#[allow(dead_code)]
pub(crate) const CENTERS: [i32; LQ as usize] = {
    let mut t = [0i32; LQ as usize];
    let mut j = 0usize;
    while j < LQ as usize {
        t[j] = center_formula(j as i32);
        j += 1;
    }
    t
};

/// Centered representative of v mod q in (-q/2, q/2].
#[inline]
pub fn center_mod_q(v: i32) -> i32 {
    let r = v.rem_euclid(Q);
    r - Q * i32::from(r > Q / 2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_label_and_center_match_tables() {
        for x in 0..Q {
            assert_eq!(q_label_ct(x), LABELS[x as usize] as i32, "label {x}");
            assert_eq!(q_label_ct(x), q_label_reference(x));
        }
        for j in 0..LQ {
            assert_eq!(center_ct(j), CENTERS[j as usize], "center {j}");
        }
    }

    #[test]
    fn label_and_center_tables_match_formulas() {
        for x in 0..Q {
            assert_eq!(q_label(x), q_label_reference(x));
        }
        for j in 0..LQ {
            let left = cell_left(j);
            let size = cell_size(j);
            let rank = (0..j).filter(|&k| cell_size(k) % 2 == 0).count() as i32;
            let expected = left + (size - 1) / 2 + ((1 ^ (size & 1)) & (rank & 1));
            assert_eq!(center(j), expected);
        }
    }

    #[test]
    fn closed_center_matches_counting_definition_exhaustively() {
        for j in 0..LQ {
            let left = cell_left(j);
            let size = cell_size(j);
            let reference = if size % 2 == 1 {
                left + (size - 1) / 2
            } else {
                let rank = (0..j).filter(|&t| cell_size(t) % 2 == 0).count() as i32;
                left + size / 2 - 1 + rank % 2
            };
            assert_eq!(center(j), reference);
        }
    }

    #[test]
    fn cells_partition() {
        // labels are monotone, cells sized 120/121, and cover [0, q)
        let mut total = 0;
        for j in 0..LQ {
            let s = cell_size(j);
            assert!(s == 120 || s == 121, "cell {j} size {s}");
            total += s;
            // every x in the cell maps to label j
            for x in [cell_left(j), cell_left(j) + s - 1] {
                assert_eq!(q_label(x), j);
            }
        }
        assert_eq!(total, Q);
    }

    #[test]
    fn paper_center_example() {
        // Q64 cell zero is {0..120} with center 60.
        assert_eq!(cell_left(0), 0);
        assert_eq!(cell_size(0), 121);
        assert_eq!(center(0), 60);
    }

    #[test]
    fn centers_inside_cells() {
        for j in 0..LQ {
            let c = center(j);
            assert!(c >= cell_left(j) && c < cell_left(j + 1), "center of {j}");
            // center error to any point of the cell is at most60
            let worst = (c - cell_left(j)).max(cell_left(j + 1) - 1 - c);
            assert!(worst <= 60, "cell {j} worst offset {worst}");
        }
    }

    #[test]
    // Keep explicit integer boundary arithmetic in the implementation and oracle.
    #[allow(clippy::manual_div_ceil)]
    fn even_cells_alternate() {
        let evens: Vec<i32> = (0..LQ).filter(|&j| cell_size(j) % 2 == 0).collect();
        for (rank, &j) in evens.iter().enumerate() {
            let lower = cell_left(j) + cell_size(j) / 2 - 1;
            let expect = lower + (rank as i32 % 2);
            assert_eq!(center(j), expect);
        }
    }
}
