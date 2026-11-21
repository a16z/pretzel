//! Constructor identity against the flat-buffer construction.
use super::*;

pub(super) fn previous(pk: &[u8]) -> Result<PreparedPk, Error> {
    let pk = crate::direct_ntt_profile::public_body(pk)?;
    if pk.len() != PK_BYTES {
        return Err(Error::KeyFormat);
    }
    let mut mat = MatrixAh {
        rows: [[crate::compact_ring::CompactPoly::ZERO; ELL + 1]; M],
    };
    crate::direct_ntt_profile::SpectralPublicB::decode_public_negated_into(
        &pk[32..CORE_PK_BYTES],
        &mut mat.rows,
    )?;
    let mut flat = [0i32; M * N];
    let owners = crate::shake2::common_prefix::fill_reference(pk, &mut mat.rows, &mut flat)
        .map_err(|_| Error::KeyFormat)?;
    let static_delta = core::array::from_fn(|r| Poly(core::array::from_fn(|i| flat[r * N + i])));
    let prefixes = hashes::PublicPrefixes::from_scheduled(pk.to_vec(), owners);
    Ok(PreparedPk {
        mat: Box::new(mat),
        static_delta: Box::new(static_delta),
        prefixes,
    })
}

pub(super) fn assert_same(a: &PreparedPk, b: &PreparedPk) {
    assert_eq!(a.mat.rows, b.mat.rows);
    assert_eq!(a.static_delta, b.static_delta);
    // Read every coefficient byte of the owner under test, including all rows.
    let a_bytes: Vec<u8> = a
        .static_delta
        .iter()
        .flat_map(|p| p.0.iter())
        .flat_map(|v| v.to_ne_bytes())
        .collect();
    let b_bytes: Vec<u8> = b
        .static_delta
        .iter()
        .flat_map(|p| p.0.iter())
        .flat_map(|v| v.to_ne_bytes())
        .collect();
    assert_eq!(a_bytes.len(), core::mem::size_of_val(&*a.static_delta));
    assert_eq!(a_bytes, b_bytes);
    for size in [0, 1, 135, 136, 137, 272] {
        let msg = vec![37; size];
        let mu = a.message_rep(b"prepk-direct", &msg);
        assert_eq!(mu, b.message_rep(b"prepk-direct", &msg));
        let labels = [17; M * N];
        assert_eq!(
            a.challenge_bytes(&mu, &[19; 32], &labels),
            b.challenge_bytes(&mu, &[19; 32], &labels)
        );
    }
}

#[test]
fn prepk_direct_matches_previous_for_32_keys() {
    for case in 0..32u8 {
        let mut body = vec![0u8; PK_BYTES];
        for (i, byte) in body[..32].iter_mut().enumerate() {
            *byte = case.wrapping_mul(37).wrapping_add(i as u8);
        }
        // Canonical public keys with varied spectral b across every row.
        // Preparation accepts canonical frames without needing a secret key.
        for index in 0..M * N {
            let value = ((index * 71 + case as usize * 137) % Q as usize) as u16;
            for bit in 0..13 {
                let k = 13 * index + bit;
                body[32 + k / 8] |= (((value >> bit) & 1) as u8) << (k % 8);
            }
        }
        body[CORE_PK_BYTES..].fill(case.wrapping_add(5));
        let wire = crate::direct_ntt_profile::tag_public(&body);
        let actual = PreparedPk::new(&wire).unwrap();
        assert_same(&actual, &previous(&wire).unwrap());
        // Independent retained secret/reuse route still uses the old decoder.
        let core = prepare_core_matrix(&body[..CORE_PK_BYTES]).unwrap();
        assert_same(&actual, &PreparedPk::from_parts(core, body).unwrap());
    }
}

#[test]
fn prepk_direct_malformed_errors_and_check_order_match_previous() {
    let body = vec![0u8; PK_BYTES];
    let wire = crate::direct_ntt_profile::tag_public(&body);
    let rejected = |bad: &[u8]| {
        crate::direct_ntt_profile::without_expansion(|| {
            assert_eq!(PreparedPk::new(bad).err(), Some(Error::KeyFormat));
            assert_eq!(previous(bad).err(), Some(Error::KeyFormat));
        });
    };
    for length in [0, 1, 13, 14, PK_BYTES, wire.len() - 1, wire.len() + 1] {
        let mut bad = wire.clone();
        bad.resize(length, 0);
        rejected(&bad);
    }
    for index in 0..14 {
        let mut bad = wire.clone();
        bad[index] ^= 1;
        rejected(&bad);
    }
    for index in [0, 7, N - 1, N, M * N / 2, M * N - 1] {
        for value in [Q as u16, 8191] {
            let mut bad = body.clone();
            for bit in 0..13 {
                let k = 13 * index + bit;
                bad[32 + k / 8] |= (((value >> bit) & 1) as u8) << (k % 8);
            }
            rejected(&crate::direct_ntt_profile::tag_public(&bad));
        }
    }
}

#[test]
fn prepk_direct_exhaustion_matches_previous() {
    let wire = crate::direct_ntt_profile::tag_public(&vec![0u8; PK_BYTES]);
    crate::shake2::common_prefix::dither_destination::with_exhausted(|| {
        assert_eq!(PreparedPk::new(&wire).err(), Some(Error::KeyFormat));
        assert_eq!(previous(&wire).err(), Some(Error::KeyFormat));
        // Invalid public coefficients still fail before the injected dither.
        let mut bad = wire.clone();
        bad[14 + 32] = 255;
        bad[14 + 33] = 31;
        crate::direct_ntt_profile::without_expansion(|| {
            assert_eq!(PreparedPk::new(&bad).err(), Some(Error::KeyFormat));
        });
    });
    // Injection is scoped; a later valid key must still initialize all fields.
    assert_same(&PreparedPk::new(&wire).unwrap(), &previous(&wire).unwrap());
}

#[test]
fn prepk_random_and_edge_keys_match_previous_and_keep_storage() {
    let mut state = 0x8142_f021_36ab_c507u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for case in 0..36 {
        let mut body: Vec<u8> = (0..PK_BYTES).map(|_| next() as u8).collect();
        let coefficients: Vec<i32> = (0..M * N)
            .map(|i| match case {
                0 => 0,
                1 => Q - 1,
                2 => {
                    if i % 2 == 0 {
                        0
                    } else {
                        Q - 1
                    }
                }
                3 => {
                    if i % N == 0 || i % N == N - 1 {
                        Q - 1
                    } else {
                        1
                    }
                }
                _ => (next() % Q as u64) as i32,
            })
            .collect();
        body[32..CORE_PK_BYTES].copy_from_slice(&encode::encode_b(&coefficients));
        if case < 2 {
            body[..32].fill(if case == 0 { 0 } else { 255 });
            body[CORE_PK_BYTES..].fill(if case == 0 { 0 } else { 255 });
        }
        let wire = crate::direct_ntt_profile::tag_public(&body);
        let actual = PreparedPk::new(&wire).unwrap();
        let expected = previous(&wire).unwrap();
        assert_same(&actual, &expected);
        let moved = Box::new(actual);
        assert_same(&moved, &expected);
    }
}
