//! Tags discriminate formats; they are not MACs.
use crate::{
    compact_ring::CompactPoly,
    params::{ELL, M, N, PK_BYTES, Q, SK_BYTES},
    ring::Poly,
    scheme::Error,
};
use zeroize::{Zeroize, Zeroizing};
#[path = "public_matrix_sampler.rs"]
pub(crate) mod matrix13;

pub(crate) const MATRIX_DOMAIN: &[u8; 16] = b"LILT-NT-2:matrix";
pub(crate) fn public_body(tagged: &[u8]) -> Result<&[u8], Error> {
    body(tagged, PK_BYTES)
}
pub(crate) fn secret_body(tagged: &[u8]) -> Result<&[u8], Error> {
    body(tagged, SK_BYTES)
}
fn body(tagged: &[u8], size: usize) -> Result<&[u8], Error> {
    if tagged.len() != 14 + size || &tagged[..14] != PROFILE {
        return Err(Error::KeyFormat);
    }
    Ok(&tagged[14..])
}
pub(crate) fn tag_public(body: &[u8]) -> Vec<u8> {
    assert_eq!(body.len(), PK_BYTES);
    let mut out = Vec::with_capacity(14 + body.len());
    out.extend_from_slice(PROFILE);
    out.extend_from_slice(body);
    out
}
pub(crate) fn tag_secret(body: &[u8]) -> Zeroizing<Vec<u8>> {
    assert_eq!(body.len(), SK_BYTES);
    let mut out = Zeroizing::new(Vec::with_capacity(14 + body.len()));
    out.extend_from_slice(PROFILE);
    out.extend_from_slice(body);
    out
}
// Per-thread test sentinel: malformed constructors must not reach expansion.
#[cfg(test)]
std::thread_local! {static FORBID_EXPANSION:core::cell::Cell<bool>=const {core::cell::Cell::new(false)};}
#[cfg(test)]
pub(crate) fn without_expansion(f: impl FnOnce()) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            FORBID_EXPANSION.with(|v| v.set(false));
        }
    }
    FORBID_EXPANSION.with(|v| assert!(!v.replace(true)));
    let _reset = Reset;
    f();
}
// Borrowed public-only spectral destination. This owns no coefficient storage:
// its lifetime prevents aliasing while filling final MatrixAh rows. It is not
// accepted by coefficient-matrix constructors. Owning and secret routes
// use PublicMatrixNtt and its explicit Drop.
pub(crate) struct PublicMatrixNttDestination<'a> {
    rows: &'a mut [[CompactPoly; ELL + 1]; M],
}
impl<'a> PublicMatrixNttDestination<'a> {
    /// On Ok, every coefficient in delta is initialized; on Err it stays partial.
    pub(crate) fn fill_common_prefix(
        self,
        body: &[u8],
        delta: &mut core::mem::MaybeUninit<[Poly; M]>,
    ) -> Result<[crate::shake2::FastSponge; 2], crate::dither_frame::FrameError> {
        #[cfg(test)]
        FORBID_EXPANSION.with(|v| assert!(!v.get(), "malformed input reached matrix expansion"));
        crate::shake2::common_prefix::fill(body, self.rows, delta)
    }

    pub(crate) fn new(rows: &'a mut [[CompactPoly; ELL + 1]; M]) -> Self {
        Self { rows }
    }
    #[cfg(test)]
    pub(crate) fn fill_from_seed(self, seed: &[u8; 32]) {
        #[cfg(test)]
        FORBID_EXPANSION.with(|v| assert!(!v.get(), "malformed input reached matrix expansion"));
        // Preserve the clearing contract for callers supplying no b column.
        for row in self.rows.iter_mut() {
            row[0] = CompactPoly::ZERO;
        }
        self.fill_spectra_preserving_public_b(seed);
    }
    /// Fill only sampled spectral columns1..=ELL, preserving validated public b.
    /// No ownership or secret cleanup policy changes: this is a borrowed destination.
    #[cfg(test)]
    pub(crate) fn fill_spectra_preserving_public_b(self, seed: &[u8; 32]) {
        #[cfg(test)]
        FORBID_EXPANSION.with(|v| assert!(!v.get(), "malformed input reached matrix expansion"));
        let rows = self.rows;
        if crate::shake2::available() {
            crate::shake2::matrix::expand_public_ntt_into(seed, rows);
            return;
        }
        matrix13::public(seed, rows);
    }
}

// Only this owner names sampled coordinates as spectra. Column zero stays zero
// until canonical coefficient b is supplied by a separately checked constructor.
pub(crate) struct PublicMatrixNtt {
    rows: [[CompactPoly; ELL + 1]; M],
}
impl PublicMatrixNtt {
    pub(crate) fn expand(seed: &[u8; 32]) -> Self {
        #[cfg(test)]
        FORBID_EXPANSION.with(|v| assert!(!v.get(), "malformed input reached matrix expansion"));
        let mut rows = [[CompactPoly::ZERO; ELL + 1]; M];
        if crate::shake2::available() {
            crate::shake2::matrix::expand_public_ntt_into(seed, &mut rows);
            return Self { rows };
        }
        matrix13::public_lockstep(seed, &mut rows);
        Self { rows }
    }
    pub(crate) fn spectral_poly(&self, r: usize, c: usize) -> Poly {
        Poly(core::array::from_fn(|i| self.rows[r][c + 1].0[i] as i32))
    }
    pub(crate) fn into_rows(mut self) -> [[CompactPoly; ELL + 1]; M] {
        core::mem::replace(&mut self.rows, [[CompactPoly::ZERO; ELL + 1]; M])
    }
}
impl Drop for PublicMatrixNtt {
    fn drop(&mut self) {
        self.rows.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn direct_ntt_tags_and_exact_frame_lengths() {
        let pk = vec![0; PK_BYTES];
        let sk = Zeroizing::new(vec![0; SK_BYTES]);
        let tagged = tag_public(&pk);
        let secret = tag_secret(&sk);
        assert_eq!(tagged.len(), 1742);
        assert_eq!(secret.len(), 654);
        assert_eq!(public_body(&tagged).unwrap(), pk);
        assert_eq!(secret_body(&secret).unwrap(), sk.as_slice());
        assert!(public_body(&pk).is_err());
        assert!(secret_body(&sk).is_err());
        for i in 0..14 {
            let mut bad = tagged.clone();
            bad[i] ^= 1;
            assert!(public_body(&bad).is_err());
        }
        for i in 0..14 {
            let mut bad = secret.to_vec();
            bad[i] ^= 1;
            assert!(secret_body(&bad).is_err());
        }
        for len in [0, 1, 13, 14, 15, 1741, 1743] {
            let mut bad = tagged.clone();
            bad.resize(len, 0);
            assert!(public_body(&bad).is_err());
        }
        for len in [0, 1, 13, 14, 15, 653, 655] {
            let mut bad = secret.to_vec();
            bad.resize(len, 0);
            assert!(secret_body(&bad).is_err());
        }
        for tag in [b"pretzel-pk13v1", b"pretzel-nt13v1", b"pretzel-nb13v1"] {
            let mut old = tagged.clone();
            old[..14].copy_from_slice(tag);
            assert!(public_body(&old).is_err());
            let mut oldsk = secret.to_vec();
            oldsk[..14].copy_from_slice(tag);
            assert!(secret_body(&oldsk).is_err());
        }
        assert_eq!(MATRIX_DOMAIN.len() + 8 + 32 + 8 + 1, 65);
        assert_eq!(crate::dither_frame::PROFILE, PROFILE);
        assert_eq!(16 + 8 + PROFILE.len() + 8 + 1696 + 8 + 32, 1782);
    }
    #[test]
    fn direct_ntt_sampled_spectra_inverse_and_schoolbook() {
        for case in 0..8u8 {
            let seed = [case; 32];
            let a = PublicMatrixNtt::expand(&seed);
            let mut reference = [[CompactPoly::ZERO; ELL + 1]; M];
            matrix13::scalar(&seed, &mut reference);
            for r in 0..M {
                for c in 0..ELL {
                    let y = a.spectral_poly(r, c);
                    assert_eq!(y, Poly(reference[r][c + 1].0.map(|v| v as i32)));
                    let mut coefficient = y;
                    crate::ring::intt(&mut coefficient);
                    let mut back = coefficient;
                    crate::ring::ntt(&mut back);
                    assert_eq!(back, y);
                    let small = Poly(core::array::from_fn(|i| ((i + c + r) % 3) as i32 - 1));
                    let mut sn = small;
                    sn.reduce();
                    crate::ring::ntt(&mut sn);
                    let mut product = crate::ring::pointwise(&y, &sn);
                    crate::ring::intt(&mut product);
                    assert_eq!(product, crate::ring::schoolbook(&coefficient, &small));
                    assert!(y.0.iter().all(|&v| (0..Q).contains(&v)));
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "direct_ntt_vectors.rs"]
mod independent_vectors;
#[cfg(test)]
mod independent_tests {
    use super::*;
    #[test]
    fn direct_ntt_independent_sixtyfour_streams_and_inverse_vectors() {
        for (seed, r, c, spectra, coefficient) in independent_vectors::MATRIX_VECTORS {
            let sampled = PublicMatrixNtt::expand(seed);
            assert_eq!(&sampled.spectral_poly(*r, *c).0, spectra);
            let mut reference = [[CompactPoly::ZERO; ELL + 1]; M];
            matrix13::scalar(seed, &mut reference);
            assert_eq!(&reference[*r][*c + 1].0.map(|v| v as i32), spectra);
            let mut reference = Poly(*spectra);
            crate::ring::intt(&mut reference);
            assert_eq!(&reference.0, coefficient);
        }
    }
}

#[cfg(test)]
mod independent_relation_tests {
    use super::*;
    #[test]
    fn direct_ntt_independent_full_key_relation_and_packed_body() {
        let a = PublicMatrixNtt::expand(&[0; 32]);
        let s = independent_vectors::SECRET.map(Poly);
        let mut sn = s;
        for p in &mut sn {
            p.reduce();
            crate::ring::ntt(p);
        }
        let b: [Poly; M] = core::array::from_fn(|r| {
            let mut acc = Poly::ZERO;
            for c in 0..ELL {
                acc = acc.add(&crate::ring::pointwise(&a.spectral_poly(r, c), &sn[c]));
            }
            crate::ring::intt(&mut acc);
            acc.add(&Poly(independent_vectors::ERROR[r]))
        });
        assert_eq!(b.map(|x| x.0), independent_vectors::B);
        let digits: Vec<i32> = b.iter().flat_map(|p| p.0.iter().copied()).collect();
        let mut body = vec![0u8; 32];
        body.extend_from_slice(&crate::encode::encode_b(&digits));
        body.extend_from_slice(&[0u8; 32]);
        assert_eq!(body.as_slice(), &independent_vectors::BODY);
        // This public zero-seed fixture has no asserted spread property.
        assert_eq!(public_body(&tag_public(&body)).unwrap(), body);
    }
}

#[cfg(test)]
mod foreign_profile_tests {
    use super::*;
    #[test]
    fn direct_ntt_genuine_foreign_profile_key_and_signature_rejected() {
        #[cfg(all(any(target_os = "linux", target_os = "macos"), target_arch = "aarch64"))]
        let _timing_state = crate::timing_state::Guard::enter().unwrap();
        use independent_vectors::FOREIGN_PK;
        let mut old = b"pretzel-pk13v1".to_vec();
        old.extend_from_slice(FOREIGN_PK);
        assert!(crate::scheme::PreparedPk::new(&old).is_err());
        assert!(crate::scheme::PreparedPk::new(FOREIGN_PK).is_err());
        // Relabelling is not prevented by a tag: the relabelled key parses.
        let changed = tag_public(FOREIGN_PK);
        assert!(crate::scheme::PreparedPk::new(&changed).is_ok());
    }
}

#[cfg(test)]
mod caller_owned_public_matrix_tests {
    use super::*;
    #[test]
    fn caller_owned_spectra_match_retained_owner_and_vectors() {
        for case in 0..8u8 {
            let seed = [case; 32];
            let old = PublicMatrixNtt::expand(&seed);
            let mut rows = [[CompactPoly::ZERO; ELL + 1]; M];
            PublicMatrixNttDestination::new(&mut rows).fill_from_seed(&seed);
            assert_eq!(rows, old.rows);
        }
        for (seed, r, c, spectra, _) in independent_vectors::MATRIX_VECTORS.iter() {
            let mut rows = [[CompactPoly::ZERO; ELL + 1]; M];
            PublicMatrixNttDestination::new(&mut rows).fill_from_seed(seed);
            assert_eq!(&rows[*r][*c + 1].0.map(i32::from), spectra);
        }
    }
    #[test]
    fn caller_owned_destination_replaces_all_public_rows_and_preserves_canaries() {
        struct Guard {
            before: [u8; 32],
            rows: [[CompactPoly; ELL + 1]; M],
            after: [u8; 32],
        }
        let mut g = Guard {
            before: [0xa5; 32],
            rows: [[CompactPoly::ZERO; ELL + 1]; M],
            after: [0x5a; 32],
        };
        for seed in [[1; 32], [7; 32]] {
            for row in g.rows.iter_mut() {
                for p in row.iter_mut() {
                    p.0.fill(123);
                }
            }
            PublicMatrixNttDestination::new(&mut g.rows).fill_from_seed(&seed);
            assert_eq!(g.rows, PublicMatrixNtt::expand(&seed).rows);
            assert_eq!(g.before, [0xa5; 32]);
            assert_eq!(g.after, [0x5a; 32]);
        }
    }
}

#[cfg(test)]
mod preserving_public_b_tests {
    use super::*;
    #[test]
    fn spectral_fill_preserves_public_b_and_existing_fill_clears_it() {
        struct Guard {
            before: [u8; 32],
            rows: [[CompactPoly; ELL + 1]; M],
            after: [u8; 32],
        }
        for case in 0..8u8 {
            let seed = [case; 32];
            let reference = PublicMatrixNtt::expand(&seed);
            let mut g = Guard {
                before: [0xa5; 32],
                rows: [[CompactPoly::ZERO; ELL + 1]; M],
                after: [0x5a; 32],
            };
            for r in 0..M {
                for i in 0..N {
                    g.rows[r][0].0[i] = ((r * N + i + 1) % Q as usize) as i16;
                }
            }
            let b = core::array::from_fn::<_, M, _>(|r| g.rows[r][0]);
            PublicMatrixNttDestination::new(&mut g.rows).fill_spectra_preserving_public_b(&seed);
            for r in 0..M {
                assert_eq!(g.rows[r][0], b[r]);
                for c in 1..=ELL {
                    assert_eq!(g.rows[r][c], reference.rows[r][c]);
                }
            }
            assert_eq!(g.before, [0xa5; 32]);
            assert_eq!(g.after, [0x5a; 32]);
            PublicMatrixNttDestination::new(&mut g.rows).fill_from_seed(&seed);
            assert_eq!(g.rows, reference.rows);
        }
    }
}

/// Explicit public spectral encoding owner. No secret/error coordinates change.
/// The public import decoder writes straight into initialized destination rows.
pub(crate) struct SpectralPublicB {
    spectra: [Poly; M],
}

impl SpectralPublicB {
    #[allow(clippy::needless_range_loop)]
    pub(crate) fn from_relation(
        rows: &[[CompactPoly; ELL + 1]; M],
        secret: &[CompactPoly; ELL + 1],
        error: &[CompactPoly; M],
    ) -> Self {
        let mut out = Self {
            spectra: [Poly::ZERO; M],
        };
        for r in 0..M {
            let dot = zeroize::Zeroizing::new(crate::compact_ring::dot_compact(&rows[r], secret));
            for i in 0..N {
                // Both terms are canonical: sum < 2q, well inside i32.
                out.spectra[r].0[i] = (dot.0[i] + error[r].0[i] as i32).rem_euclid(Q);
            }
        }
        out
    }

    pub(crate) fn from_coefficients(coefficients: &[Poly; M]) -> Self {
        let mut spectra = *coefficients;
        for p in &mut spectra {
            p.reduce();
            crate::ring::ntt(p);
        }
        Self { spectra }
    }
    pub(crate) fn spectra(&self) -> &[Poly; M] {
        &self.spectra
    }
    pub(crate) fn install_negated(&self, rows: &mut [[CompactPoly; ELL + 1]; M]) {
        for r in 0..M {
            for i in 0..N {
                let x = self.spectra[r].0[i];
                rows[r][0].0[i] = if x == 0 { 0 } else { (Q - x) as i16 };
            }
        }
    }
    // Public coefficients only: canonical rejection and stores retain stream order.
    pub(crate) fn decode_public_negated_into(
        bytes: &[u8],
        rows: &mut [[CompactPoly; ELL + 1]; M],
    ) -> Result<(), Error> {
        if bytes.len() != M * N * 13 / 8 {
            return Err(Error::KeyFormat);
        }
        // Every 13-byte group holds eight consecutive canonical coefficients.
        // Safe overlapping loads, no overread and no temporary heap allocation.
        for (group, chunk) in bytes.chunks_exact(13).enumerate() {
            let lo = u64::from_le_bytes(chunk[..8].try_into().unwrap());
            let hi = u64::from_le_bytes(chunk[5..13].try_into().unwrap());
            let values = [
                lo & 8191,
                (lo >> 13) & 8191,
                (lo >> 26) & 8191,
                (lo >> 39) & 8191,
                (hi >> 12) & 8191,
                (hi >> 25) & 8191,
                (hi >> 38) & 8191,
                (hi >> 51) & 8191,
            ];
            for (lane, x) in values.into_iter().enumerate() {
                if x >= Q as u64 {
                    return Err(Error::KeyFormat);
                }
                let i = group * 8 + lane;
                rows[i / N][0].0[i % N] = if x == 0 { 0 } else { (Q as u64 - x) as i16 };
            }
        }
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn decode_negated_into(
        bytes: &[u8],
        rows: &mut [[CompactPoly; ELL + 1]; M],
    ) -> Result<(), Error> {
        crate::encode::decode_b_into(bytes, |i, x| {
            rows[i / N][0].0[i % N] = if x == 0 { 0 } else { (Q - x) as i16 }
        })
        .ok_or(Error::KeyFormat)
    }
}

impl Drop for SpectralPublicB {
    fn drop(&mut self) {
        self.spectra.zeroize();
    }
}

#[cfg(test)]
#[path = "spectral_b_vectors.rs"]
mod spectral_b_vectors;
#[cfg(test)]
mod spectral_b_vector_tests {
    use super::*;
    #[test]
    fn spectral_b_matches_external_coefficient_relation_vectors() {
        let coefficients = independent_vectors::B.map(Poly);
        let encoded = SpectralPublicB::from_coefficients(&coefficients);
        assert_eq!(
            encoded.spectra().map(|p| p.0),
            spectral_b_vectors::EXPECTED_B_SPECTRA
        );
        let mut rows = [[CompactPoly::ZERO; ELL + 1]; M];
        encoded.install_negated(&mut rows);
        let digits: Vec<i32> = encoded.spectra().iter().flat_map(|p| p.0).collect();
        let mut decoded = [[CompactPoly::ZERO; ELL + 1]; M];
        SpectralPublicB::decode_negated_into(&crate::encode::encode_b(&digits), &mut decoded)
            .unwrap();
        assert_eq!(rows, decoded);
    }
}

pub(crate) const PROFILE: &[u8; 14] = b"PZRU1-R4-N0001";

#[cfg(test)]
mod public_decode_tests {
    use super::*;
    #[test]
    fn public_decode_all_symbols_positions_and_canonical_rejection() {
        // Compare status and partial destination with the live shared decoder.
        // A complete key covers all eight positions and every 13-bit symbol.
        for position in 0..8 {
            for value in 0..8192u64 {
                let mut bytes = vec![0; M * N * 13 / 8];
                for bit in 0..13 {
                    bytes[(position * 13 + bit) / 8] |=
                        (((value >> bit) & 1) as u8) << ((position * 13 + bit) % 8);
                }
                let mut a = [[CompactPoly::ZERO; ELL + 1]; M];
                let mut b = a;
                let x = SpectralPublicB::decode_negated_into(&bytes, &mut a);
                let y = SpectralPublicB::decode_public_negated_into(&bytes, &mut b);
                assert_eq!(y.is_ok(), value < Q as u64);
                assert_eq!(x.is_ok(), y.is_ok());
                assert_eq!(a, b);
            }
        }
        for length in [0, 1, M * N * 13 / 8 - 1, M * N * 13 / 8 + 1] {
            assert!(SpectralPublicB::decode_public_negated_into(
                &vec![0; length],
                &mut [[CompactPoly::ZERO; ELL + 1]; M]
            )
            .is_err());
        }
    }
}
