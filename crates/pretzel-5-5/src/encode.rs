//! Wire encodings: the 13-bit public-key packing and the 2-bit secret-key packing.

use crate::params::*;

/// Public-key coefficients: consecutive low-first 13-bit canonical residues.
/// All 13 * M * N bits are used; no radix-q normalization or padding aliases.
// Keep explicit widths shared with architecture and profile variants.
#[allow(clippy::unnecessary_cast)]
pub fn encode_b(digits: &[i32]) -> [u8; PK_B_BYTES] {
    assert_eq!(digits.len(), M * N);
    let mut out = [0u8; PK_B_BYTES];
    let (mut acc, mut bits, mut cursor) = (0u32, 0u32, 0usize);
    for &d in digits {
        assert!((0..Q).contains(&d), "noncanonical public coefficient");
        acc |= (d as u32) << bits;
        bits += 13;
        while bits >= 8 {
            out[cursor] = acc as u8;
            cursor += 1;
            acc >>= 8;
            bits -= 8;
        }
    }
    assert_eq!((cursor, bits, acc), (PK_B_BYTES, 0, 0));
    out
}

// Keep explicit widths shared with architecture and profile variants.
#[allow(clippy::unnecessary_cast)]
pub fn decode_b(bytes: &[u8]) -> Option<Vec<i32>> {
    if bytes.len() != PK_B_BYTES {
        return None;
    }
    let mut out = Vec::with_capacity(M * N);
    let (mut acc, mut bits, mut cursor) = (0u32, 0u32, 0usize);
    for _ in 0..M * N {
        while bits < 13 {
            acc |= u32::from(bytes[cursor]) << bits;
            cursor += 1;
            bits += 8;
        }
        let d = (acc & 8191) as i32;
        if d >= Q {
            return None;
        }
        out.push(d);
        acc >>= 13;
        bits -= 13;
    }
    debug_assert_eq!((cursor, bits, acc), (PK_B_BYTES, 0, 0));
    Some(out)
}

/// Public-only canonical packed digits into caller-owned storage. A rejected
/// encoding may have written a prefix; callers must discard it on None.
/// No matrix expansion or transform is performed by this decoder.
// Keep explicit widths shared with architecture and profile variants.
#[allow(clippy::unnecessary_cast)]
pub(crate) fn decode_b_into(bytes: &[u8], mut put: impl FnMut(usize, i32)) -> Option<()> {
    if bytes.len() != PK_B_BYTES {
        return None;
    }
    let (mut acc, mut bits, mut cursor) = (0u32, 0u32, 0usize);
    for index in 0..M * N {
        while bits < 13 {
            acc |= u32::from(bytes[cursor]) << bits;
            cursor += 1;
            bits += 8;
        }
        let digit = (acc & 8191) as i32;
        if digit >= Q {
            return None;
        }
        put(index, digit);
        acc >>= 13;
        bits -= 13;
    }
    debug_assert_eq!((cursor, bits, acc), (PK_B_BYTES, 0, 0));
    Some(())
}

/// Pack TRIT_COUNT trits (s0 then e, coefficients in {-1,0,1}) at 2 bits each.
/// Codes: 0 -> 0, 1 -> 1, -1 -> 2.
// Keep explicit widths shared with architecture and profile variants.
#[allow(clippy::unnecessary_cast)]
#[cfg(test)]
pub fn pack_trits(vals: &[i32]) -> [u8; TRIT_BYTES] {
    assert_eq!(vals.len(), TRIT_COUNT);
    let mut out = [0u8; TRIT_BYTES];
    for (i, &v) in vals.iter().enumerate() {
        // No branch on the secret value. (v & 3) is 0, 1, 3 for
        // 0, 1, -1; the sign bit folds 3 into 2. Same bytes as the match.
        let code: u8 = {
            debug_assert!((-1..=1).contains(&v), "not a trit");
            let u = v as u32;
            ((u & 3) ^ (u >> 31)) as u8
        };
        out[i / 4] |= code << (2 * (i % 4));
    }
    out
}

// Keep explicit widths shared with architecture and profile variants.
#[allow(clippy::unnecessary_cast)]
pub fn unpack_trits(bytes: &[u8]) -> Option<Vec<i32>> {
    if bytes.len() != TRIT_BYTES {
        return None;
    }
    let mut out = zeroize::Zeroizing::new(Vec::with_capacity(TRIT_COUNT));
    let mut bad = 0u32;
    for i in 0..TRIT_COUNT {
        let code = (bytes[i / 4] >> (2 * (i % 4))) & 3;
        // value = (code & 1) - (code >> 1) gives 0, 1, -1 for codes
        // 0, 1, 2; code 3 is flagged and rejected after the full fixed scan.
        {
            let c = code as u32;
            bad |= (c & 1) & (c >> 1);
            out.push((c & 1) as i32 - (c >> 1) as i32);
        }
    }
    if bad != 0 {
        return None;
    }
    Some(std::mem::take(&mut *out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // Keep explicit widths shared with architecture and profile variants.
    #[allow(clippy::unnecessary_cast)]
    fn radix_roundtrip() {
        let mut digits = vec![0i32; M * N];
        let mut s = 12345u64;
        for d in digits.iter_mut() {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
            *d = ((s >> 33) % Q as u64) as i32;
        }
        let enc = encode_b(&digits);
        let dec = decode_b(&enc).unwrap();
        assert_eq!(digits, dec);
    }

    #[test]
    fn max_value_fits() {
        let digits = vec![Q - 1; M * N];
        let enc = encode_b(&digits);
        assert_eq!(decode_b(&enc).unwrap(), digits);
    }

    #[test]
    // Keep explicit widths shared with architecture and profile variants.
    #[allow(clippy::unnecessary_cast)]
    fn trits_roundtrip() {
        let vals: Vec<i32> = (0..crate::params::TRIT_COUNT)
            .map(|i| (i % 3) as i32 - 1)
            .collect();
        assert_eq!(unpack_trits(&pack_trits(&vals)).unwrap(), vals);
    }

    /// The packed codes are 0, 1 and 2 for the trits 0, 1 and -1, two bits per trit,
    /// and unpacking rejects the reserved code 3 wherever it sits.
    #[test]
    fn trit_codes_are_build_independent_and_code_three_is_rejected() {
        let vals: Vec<i32> = (0..crate::params::TRIT_COUNT)
            .map(|i| [0, 1, -1, 1, 0, 0, -1][i % 7])
            .collect();
        let packed = pack_trits(&vals);
        for (i, &v) in vals.iter().enumerate() {
            let code = (packed[i / 4] >> (2 * (i % 4))) & 3;
            assert_eq!(
                code,
                match v {
                    0 => 0,
                    1 => 1,
                    _ => 2,
                }
            );
        }
        for pos in [0usize, 1, 2, 3, 100, crate::params::TRIT_COUNT - 1] {
            let mut bad = packed;
            bad[pos / 4] |= 3 << (2 * (pos % 4));
            assert!(unpack_trits(&bad).is_none(), "code 3 at {pos}");
        }
        assert!(unpack_trits(&packed[..crate::params::TRIT_BYTES - 1]).is_none());
    }
}

/// Encode borrowed private polynomials directly into an erased byte owner.
/// Fixed addresses and loop counts; no flattened secret Vec or allocation.
/// The key sampler supplies coefficients in {-1, 0, 1}.
/// Borrow the caller's erased owner; never return secret bytes by value.
pub(crate) fn keygen_pack_trits(
    s: &[crate::ring::Poly; ELL],
    e: &[crate::ring::Poly; M],
    out: &mut zeroize::Zeroizing<[u8; TRIT_BYTES]>,
) {
    for (poly, p) in s.iter().chain(e.iter()).enumerate() {
        for (group, values) in p.0.chunks_exact(4).enumerate() {
            let mut byte = 0;
            for (slot, &v) in values.iter().enumerate() {
                let u = v as u32;
                let code = ((u & 3) ^ (u >> 31)) as u8;
                byte |= code << (2 * slot);
            }
            out[poly * (N / 4) + group] = byte;
        }
    }
}
#[cfg(test)]
mod keygen_secret_pack_tests {
    use super::*;
    #[test]
    fn every_four_trits_and_poly_boundary_matches_flat_packer() {
        for case in 0..81usize {
            let mut n = case;
            let digits: [i32; 4] = core::array::from_fn(|_| {
                let v = (n % 3) as i32 - 1;
                n /= 3;
                v
            });
            let s = core::array::from_fn(|p| {
                crate::ring::Poly(core::array::from_fn(|i| digits[(i + p) % 4]))
            });
            let e = core::array::from_fn(|p| {
                crate::ring::Poly(core::array::from_fn(|i| digits[(i + p + 1) % 4]))
            });
            let flat = zeroize::Zeroizing::new(
                s.iter()
                    .chain(e.iter())
                    .flat_map(|p| p.0)
                    .collect::<Vec<_>>(),
            );
            let reference = zeroize::Zeroizing::new(pack_trits(&flat));
            let mut packed = zeroize::Zeroizing::new([0xa5u8; TRIT_BYTES]);
            keygen_pack_trits(&s, &e, &mut packed);
            assert_eq!(&packed[..], &reference[..]);
        }
    }
}
