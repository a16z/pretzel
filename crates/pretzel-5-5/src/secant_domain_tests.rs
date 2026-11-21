//! Guard the decoded-head constructor and correction boundaries.
use super::*;

fn check(bytes: &[u8]) {
    let mut reference = [i32::MAX; HEAD_COEFFICIENTS];
    let mut local = [255; LABELS];
    let expected = decode_fields_reference(bytes, &mut reference, &mut local);
    let mut values = [i32::MAX; HEAD_COEFFICIENTS];
    let actual = decode_fields_borrowed(bytes, &mut values);
    assert_eq!(actual.is_ok(), expected.is_ok());
    if let Ok((head, _)) = actual {
        assert_eq!(head.values(), &reference);
        assert!(head.values().iter().all(|&v| (-288..=288).contains(&v)));
    }
    assert_eq!(values, reference, "partial head writes on rejected packet");
}

fn packet(position: usize, low: i32, positive: bool) -> [u8; HEAD_BYTES] {
    let mut bytes = [0u8; HEAD_BYTES];
    if position < 256 {
        write_field(&mut bytes, 6 * position, 6, (low as u32) & 63);
    } else {
        bytes[MIDDLE + position - 256] = low as u8;
    }
    bytes[HEAD_COUNT] = 1;
    write_field(
        &mut bytes,
        8 * HEAD_RECORDS,
        12,
        position as u32 | if positive { 2048 } else { 0 },
    );
    bytes
}

#[test]
fn secant_domain_all_constructors_and_cap_boundaries() {
    // Every possible low field and correction sign at both endpoints of each
    // field class, including values on and outside both magnitude caps.
    for position in [0, 255, 256, 1535] {
        let (first, last) = if position < 256 {
            (-32, 31)
        } else {
            (-128, 127)
        };
        for low in first..=last {
            for positive in [false, true] {
                check(&packet(position, low, positive));
            }
        }
    }
    // Every position at signed cap endpoints and an adjacent rejected value.
    for position in 0..HEAD_COEFFICIENTS {
        let lows: &[i32] = if position < 256 {
            &[-32, -31, 31]
        } else {
            &[-33, -32, 32, 33]
        };
        for &low in lows {
            for positive in [false, true] {
                check(&packet(position, low, positive));
            }
        }
    }
    let zero = [0u8; HEAD_BYTES];
    for length in 0..HEAD_BYTES {
        check(&zero[..length]);
    }
    check(&zero);
    check(&[0; HEAD_BYTES + 1]);
    // The largest correction count and malformed ordering/count/position paths
    // must never expose a typed head after a rejected decode.
    let mut bytes = zero;
    bytes[HEAD_COUNT] = HEAD_EXCEPTIONS as u8;
    for slot in 0..HEAD_EXCEPTIONS {
        let position = 256 + slot;
        bytes[MIDDLE + slot] = 32;
        write_field(
            &mut bytes,
            8 * HEAD_RECORDS + 12 * slot,
            12,
            position as u32 | 2048,
        );
    }
    check(&bytes);
    bytes[HEAD_COUNT] += 1;
    check(&bytes);
    for position in 1536..2048 {
        let mut bytes = zero;
        bytes[HEAD_COUNT] = 1;
        write_field(&mut bytes, 8 * HEAD_RECORDS, 12, position);
        check(&bytes);
    }
    let mut bytes = packet(256, 32, true);
    bytes[HEAD_COUNT] = 2;
    write_field(&mut bytes, 8 * HEAD_RECORDS + 12, 12, 256 | 2048);
    check(&bytes);
    let mut bytes = zero;
    bytes[LOCAL_COUNT] = 17;
    check(&bytes);
}
