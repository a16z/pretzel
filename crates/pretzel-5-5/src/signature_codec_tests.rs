// Tests of the 1908-byte field codec: grammar, limits, recovery lists and the admission masks.
use super::*;

fn list(x: i32) -> Vec<(i32, i32)> {
    let mut pairs: Vec<_> = (0..64)
        .map(|label| {
            let mut r = center(label) - x;
            if r < -3840 {
                r += 7681;
            }
            if r > 3840 {
                r -= 7681;
            }
            (label, r)
        })
        .filter(|&(_, r)| r.abs() <= 450)
        .collect();
    pairs.sort_by_key(|&(_, r)| (r.abs(), r));
    pairs
}

fn semantic(ranks: &[i32; LABELS]) -> ([i32; LABELS], [i32; LABELS]) {
    let geometry = list(0);
    (
        ranks.map(|r| geometry[r as usize].0),
        ranks.map(|r| geometry[r as usize].1),
    )
}

fn encode(head: &[i32; HEAD_COEFFICIENTS], ranks: &[i32; LABELS]) -> [u8; HEAD_BYTES] {
    let mut bytes = [0xa5; HEAD_BYTES];
    encode_admitted(head, ranks, &mut bytes, &mut []);
    bytes
}

fn roundtrip(head: &[i32; HEAD_COEFFICIENTS], ranks: &[i32; LABELS]) {
    let (labels, residual) = semantic(ranks);
    let mut ranked = [-1; LABELS];
    assert_eq!(
        capacity_mask(head, &labels, &residual, &mut ranked),
        u64::MAX
    );
    assert_eq!(&ranked, ranks);
    let bytes = encode(head, ranks);
    let mut decoded_head = [i32::MIN; HEAD_COEFFICIENTS];
    let mut decoded_local = [255; LABELS];
    assert_eq!(
        decode_fields(&bytes, &mut decoded_head, &mut decoded_local),
        Ok(())
    );
    assert_eq!(&decoded_head, head);
    assert_eq!(decoded_local, ranks.map(|r| r as u8));
    assert_eq!(encode(&decoded_head, &decoded_local.map(i32::from)), bytes);
}

#[test]
fn exact_grammar_and_no_padding() {
    assert_eq!(SIGNATURE_BYTES, 1908);
    assert_eq!(HEAD_BYTES, 1876);
    assert_eq!(LOCAL_RECORDS + 22, HEAD_BYTES);
    roundtrip(&[0; HEAD_COEFFICIENTS], &[0; LABELS]);
}

#[test]
fn exhaustive_admitted_head_values_at_field_ends() {
    let mut head = [0; HEAD_COEFFICIENTS];
    for (position, cap) in [(0, 95), (255, 95), (256, 288), (1535, 288)] {
        for value in -cap..=cap {
            head[position] = value;
            roundtrip(&head, &[0; LABELS]);
        }
        head[position] = 0;
    }
}

#[test]
fn private_rank_all_public_contexts_and_labels() {
    let mut pairs = 0;
    for x in 0..7681 {
        let geometry = list(x);
        assert!((7..=8).contains(&geometry.len()));
        for (rank, &(label, residual)) in geometry.iter().enumerate() {
            assert_eq!(private_index(label, residual), rank as u32);
            pairs += 1;
        }
    }
    assert_eq!(pairs, 57664);
}

#[test]
fn both_capacity_boundaries_equal_encoder_counts() {
    for h in [0, 39, 40, 41] {
        for l in [0, 15, 16, 17] {
            let mut head = [0; HEAD_COEFFICIENTS];
            head[..h].fill(32);
            let mut ranks = [0; LABELS];
            ranks[..l].fill(4);
            let (labels, residual) = semantic(&ranks);
            let mut actual = [-1; LABELS];
            let mask = capacity_mask(&head, &labels, &residual, &mut actual);
            assert_eq!(actual, ranks);
            assert_eq!(mask == u64::MAX, h <= 40 && l <= 16);
            // Beyond-limit calls are isolated robustness/count controls only.
            // Production must abort before calling the encoder on these cases.
            let bytes = encode(&head, &ranks);
            assert_eq!(usize::from(bytes[HEAD_COUNT]), h);
            assert_eq!(usize::from(bytes[LOCAL_COUNT]), l);
            let mut dh = [i32::MIN; HEAD_COEFFICIENTS];
            let mut dl = [255; LABELS];
            assert_eq!(
                decode_fields(&bytes, &mut dh, &mut dl).is_ok(),
                h <= 40 && l <= 16
            );
            if h > 40 || l > 16 {
                assert_eq!(dh, [i32::MIN; HEAD_COEFFICIENTS]);
                assert_eq!(dl, [255; LABELS]);
            }
        }
    }
}

#[test]
fn minus_32_and_minus_128_are_not_exceptions() {
    for (position, lo, hi) in [(0, -32, 31), (256, -128, 127)] {
        for value in [lo - 1, lo, hi, hi + 1] {
            let mut head = [0; HEAD_COEFFICIENTS];
            head[position] = value;
            let bytes = encode(&head, &[0; LABELS]);
            assert_eq!(bytes[HEAD_COUNT], u8::from(value < lo || value > hi));
            roundtrip(&head, &[0; LABELS]);
        }
    }
}

#[test]
fn active_zero_records_and_maximum_positions() {
    let mut head = [0; HEAD_COEFFICIENTS];
    head[0] = -64;
    head[1535] = 288;
    let mut ranks = [0; LABELS];
    ranks[0] = 4;
    ranks[1279] = 4;
    let bytes = encode(&head, &ranks);
    assert_eq!(read_field(&bytes, 8 * HEAD_RECORDS, 12), 0);
    assert_eq!(read_field(&bytes, 8 * LOCAL_RECORDS, 11), 0);
    roundtrip(&head, &ranks);
}

#[test]
fn ordering_duplicates_unused_and_out_of_range_records_reject() {
    for (offset, width, count_offset, limit, positions) in [
        (HEAD_RECORDS, 12, HEAD_COUNT, 1536, [3u32, 2]),
        (LOCAL_RECORDS, 11, LOCAL_COUNT, 1280, [3u32, 2]),
    ] {
        for records in [
            vec![positions[0], positions[1]],
            vec![2, 2],
            vec![limit],
            vec![1],
        ] {
            let mut bytes = [0; HEAD_BYTES];
            bytes[count_offset] = if records == [1] {
                0
            } else {
                records.len() as u8
            };
            for (i, record) in records.into_iter().enumerate() {
                write_field(&mut bytes, 8 * offset + width * i, width, record);
            }
            assert!(decode_fields(&bytes, &mut [0; HEAD_COEFFICIENTS], &mut [0; LABELS]).is_err());
        }
    }
    // Two opposite corrections could cancel to a low-field value. They are
    // noncanonical duplicate positions, rejected before the second patch.
    let mut bytes = [0; HEAD_BYTES];
    bytes[HEAD_COUNT] = 2;
    write_field(&mut bytes, 8 * HEAD_RECORDS + 12, 12, 2048);
    assert!(decode_fields(&bytes, &mut [0; HEAD_COEFFICIENTS], &mut [0; LABELS]).is_err());
}

#[test]
fn corrected_caps_and_partial_output_contract() {
    for (position, low, record) in [(0, -32, 0), (256, 33, 256 | 2048), (1535, -33, 1535)] {
        let mut head = [0; HEAD_COEFFICIENTS];
        head[position] = low;
        let mut bytes = encode(&head, &[0; LABELS]);
        bytes[HEAD_COUNT] = 1;
        write_field(&mut bytes, 8 * HEAD_RECORDS, 12, record);
        let mut dh = [i32::MIN; HEAD_COEFFICIENTS];
        let mut dl = [255; LABELS];
        assert!(decode_fields(&bytes, &mut dh, &mut dl).is_err());
        assert_eq!(dh, head);
        assert_eq!(dl, [255; LABELS]);
    }
    let bytes = [0; HEAD_BYTES];
    for length in [0, 1, HEAD_BYTES - 1] {
        let mut dh = [123; HEAD_COEFFICIENTS];
        let mut dl = [99; LABELS];
        assert!(decode_fields(&bytes[..length], &mut dh, &mut dl).is_err());
        assert_eq!(dh, [123; HEAD_COEFFICIENTS]);
        assert_eq!(dl, [99; LABELS]);
    }
}

#[test]
fn invalid_private_fields_reject_without_rank_escape() {
    let ranks = [0; LABELS];
    let (mut labels, mut residual) = semantic(&ranks);
    for position in [0, 255, 256, 1535] {
        for value in [i32::MIN, i32::MAX, -289, 289] {
            let mut head = [0; HEAD_COEFFICIENTS];
            head[position] = value;
            let mut local = [-1; LABELS];
            assert_eq!(capacity_mask(&head, &labels, &residual, &mut local), 0);
            assert!(local.iter().all(|r| (0..8).contains(r)));
        }
    }
    for value in [i32::MIN, -1, 64, i32::MAX] {
        labels[0] = value;
        assert_eq!(
            capacity_mask(
                &[0; HEAD_COEFFICIENTS],
                &labels,
                &residual,
                &mut [0; LABELS]
            ),
            0
        );
    }
    labels = semantic(&ranks).0;
    for value in [i32::MIN, -451, 451, i32::MAX] {
        residual[0] = value;
        assert_eq!(
            capacity_mask(
                &[0; HEAD_COEFFICIENTS],
                &labels,
                &residual,
                &mut [0; LABELS]
            ),
            0
        );
    }
}

#[test]
fn borrowed_views_and_canonical_columns() {
    let head = core::array::from_fn(|i| {
        if i < 256 {
            (i as i32 % 64) - 32
        } else {
            (i as i32 % 256) - 128
        }
    });
    let ranks = core::array::from_fn(|i| (i % 4) as i32);
    let bytes = encode(&head, &ranks);
    let mut out = [0; HEAD_COEFFICIENTS];
    let (decoded, planes) = decode_fields_borrowed(&bytes, &mut out).unwrap();
    assert_eq!(decoded.values(), &head);
    for col in 0..6 {
        let mut canon = [-1; 256];
        decoded.write_canonical_column(col, &mut canon);
        for i in 0..256 {
            assert_eq!(i32::from(canon[i]), head[256 * col + i].rem_euclid(7681));
        }
    }
    for row in 0..5 {
        for i in 0..256 {
            assert_eq!(i32::from(planes.row(row)[i]), ranks[row * 256 + i]);
        }
    }
}

#[cfg(test)]
#[test]
fn missing_eighth_entry_rejects_after_field_parse() {
    let x = (0..7681).find(|&x| list(x).len() == 7).unwrap();
    let mut ranks = [0; LABELS];
    ranks[0] = 7;
    let bytes = encode(&[0; HEAD_COEFFICIENTS], &ranks);
    let mut local = [0; LABELS];
    decode_fields(&bytes, &mut [0; HEAD_COEFFICIENTS], &mut local).unwrap();
    assert_eq!(local[0], 7);
    assert!(recover(x, local[0]).is_err());
}

#[cfg(test)]
#[test]
fn retained_simd_all_context_rank_pairs_match_scalar() {
    use core::arch::aarch64::*;
    unsafe {
        let tables = PublicRecoveryTables::new();
        let ranks = [0, 1, 2, 3, 4, 5, 6, 7];
        for x in 0..7681 {
            let contexts = [x as u16; 8];
            let (u, r) = public_recover8(
                vld1q_u16(contexts.as_ptr()),
                vld1_u8(ranks.as_ptr()),
                tables,
            );
            let mut labels = [0; 8];
            let mut magnitudes = [0; 8];
            vst1_u8(labels.as_mut_ptr(), u);
            vst1q_u16(magnitudes.as_mut_ptr(), r);
            for i in 0..8 {
                let expected = recover(x, ranks[i])
                    .map(|(u, r)| (u, r.unsigned_abs() as u16))
                    .unwrap_or((0, 451));
                assert_eq!((labels[i], magnitudes[i]), expected);
            }
        }
    }
}

#[cfg(test)]
#[test]
fn decoded_planes_keep_missing_rank_sentinel() {
    use core::arch::aarch64::*;
    let x = (0..7681).find(|&x| list(x).len() == 7).unwrap();
    let mut ranks = [0; LABELS];
    ranks[..8].fill(7);
    let bytes = encode(&[0; HEAD_COEFFICIENTS], &ranks);
    let mut head = [0; HEAD_COEFFICIENTS];
    let (_, planes) = decode_fields_borrowed(&bytes, &mut head).unwrap();
    unsafe {
        let contexts = [x as u16; 8];
        let (u, r) = public_recover8(
            vld1q_u16(contexts.as_ptr()),
            vld1_u8(planes.row(0).as_ptr()),
            PublicRecoveryTables::new(),
        );
        let mut labels = [255; 8];
        let mut magnitudes = [0; 8];
        vst1_u8(labels.as_mut_ptr(), u);
        vst1q_u16(magnitudes.as_mut_ptr(), r);
        assert_eq!(labels, [0; 8]);
        assert_eq!(magnitudes, [451; 8]);
    }
}
