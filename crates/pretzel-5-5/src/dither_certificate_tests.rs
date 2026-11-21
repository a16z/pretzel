//! The cap predicates of the signer and of the verifier agree with the scalar
//! specification written in these tests, on the cases below.
use crate::{
    params::*,
    params_tables::{W_HEAD, W_RES},
    quantize, signature_codec,
};

#[test]
fn certificate_geometry_and_constants() {
    assert_eq!((Q, N, ELL, M, LQ), (7681, 256, 5, 5, 64));
    assert_eq!((CAP_INF_HEAD, CAP_INF_RES), (288, 451));
    assert_eq!(
        (CAP_EUC2_HEAD, CAP_EUC2_RES, CAP_Q20),
        (2150 * 2150, 3170 * 3170, 40_741_973)
    );
    assert_eq!(signature_codec::HEAD_EXCEPTIONS, 40);
    assert_eq!(signature_codec::LABEL_EXCEPTIONS, 16);
    assert_eq!((W_HEAD.len(), W_RES.len()), (289, 452));
    assert_eq!(crate::dither_frame::EXPANSION_CANDIDATES, 1664);
    assert_eq!(crate::dither_frame::MAX_CANDIDATES, 2048);
    for x in 0..Q {
        assert_eq!(quantize::q_label(x), 64 * x / Q);
        let mut expected = Vec::new();
        for label in 0..64 {
            let center = 120 * label + 60 + i32::from(label != 0 && label % 2 == 0);
            assert_eq!(quantize::center(label), center);
            let residual = (center - x + Q / 2).rem_euclid(Q) - Q / 2;
            if residual.abs() <= 450 {
                expected.push((residual.abs(), residual, label as u8));
            }
        }
        expected.sort_unstable();
        for slot in 0..8 {
            let actual = signature_codec::recover(x, slot as u8);
            assert_eq!(actual.ok(), expected.get(slot).map(|&(_, r, u)| (u, r)));
        }
    }
}

#[test]
// Keep the public coordinate order explicit across the independent arrays.
#[allow(clippy::needless_range_loop)]
fn certificate_predicate_matches_signer_and_verifier() {
    let mut head = vec![0i32; signature_codec::HEAD_COEFFICIENTS];
    let mut residual = Box::new([60i32; signature_codec::LABELS]);
    let mut labels = Box::new([0i32; signature_codec::LABELS]);
    let mut local = Box::new([0i32; signature_codec::LABELS]);
    let mut decoded = Box::new([0i32; signature_codec::HEAD_COEFFICIENTS]);
    let mut decoded_local = Box::new([0u8; signature_codec::LABELS]);
    let mut bytes = vec![0u8; signature_codec::HEAD_BYTES];
    for trial in 0..512usize {
        head.fill(0);
        residual.fill(60);
        labels.fill(0);
        // Exercise both endpoints, counts at/beyond capacity, norms and score.
        let values = [
            -289, -288, -129, -128, -96, -95, -33, -32, 31, 32, 95, 96, 127, 128, 288, 289,
        ];
        let count = [1, 16, 17, 40, 41, 256, 1280, 1536][trial % 8];
        for (i, value) in head.iter_mut().enumerate().take(count) {
            *value = values[(trial / 8 + i / 256) % values.len()];
        }
        if trial % 3 == 0 {
            for i in 0..[1, 16, 17, 1280][trial % 4] {
                residual[i] = [60, -450, 450, 451, -451, 300, 301, 0][trial / 4 % 8];
                labels[i] = (trial / 32 % 64) as i32;
            }
        }
        let norm_h: u64 = head
            .iter()
            .map(|&v| (i64::from(v) * i64::from(v)) as u64)
            .sum();
        let norm_r: u64 = residual
            .iter()
            .map(|&v| (i64::from(v) * i64::from(v)) as u64)
            .sum();
        let score: u64 = head
            .iter()
            .map(|v| u64::from(*W_HEAD.get(v.unsigned_abs() as usize).unwrap_or(&u32::MAX)))
            .chain(
                residual
                    .iter()
                    .map(|v| u64::from(*W_RES.get(v.unsigned_abs() as usize).unwrap_or(&u32::MAX))),
            )
            .sum();
        let caps = head.iter().all(|v| v.abs() <= CAP_INF_HEAD)
            && residual.iter().all(|v| v.abs() <= CAP_INF_RES)
            && norm_h <= CAP_EUC2_HEAD
            && norm_r <= CAP_EUC2_RES
            && score <= CAP_Q20;
        // Compare the selected CT signer against the scalar cap specification.
        assert_eq!(
            crate::scheme::certificate_caps(&head, residual.as_slice()),
            (caps, caps)
        );
        let mut head_exceptions = 0;
        let mut label_exceptions = 0;
        let mut capacity = true;
        for (i, &v) in head.iter().enumerate() {
            let (cap, half) = if i < 256 { (95, 32) } else { (288, 128) };
            capacity &= v.abs() <= cap;
            head_exceptions += usize::from(v < -half || v >= half);
        }
        for i in 0..signature_codec::LABELS {
            let x = (quantize::center(labels[i]) - residual[i]).rem_euclid(Q);
            let expected = Some((labels[i] as u8, residual[i]));
            let slot = (0..8u8).find(|&j| signature_codec::recover(x, j).ok() == expected);
            capacity &= residual[i].abs() <= 450 && slot.is_some();
            label_exceptions += usize::from(slot.is_some_and(|j| j >= 4));
        }
        capacity &= head_exceptions <= signature_codec::HEAD_EXCEPTIONS
            && label_exceptions <= signature_codec::LABEL_EXCEPTIONS;
        assert_eq!(
            signature_codec::capacity_mask(&head, &labels, &residual, &mut local) == u64::MAX,
            capacity
        );
        if capacity {
            signature_codec::encode_admitted(&head, &local, &mut bytes, &mut []);
            let fields = signature_codec::decode_fields(&bytes, &mut decoded, &mut decoded_local);
            assert!(fields.is_ok());
            let contexts =
                core::array::from_fn(|i| (quantize::center(labels[i]) - residual[i]).rem_euclid(Q));
            let (public_head, public_residual) =
                crate::scheme::verifier::certificate_public_stats(&bytes, &contexts).unwrap();
            assert_eq!(public_head >> 32, norm_h);
            assert_eq!(public_residual >> 32, norm_r);
            assert_eq!(
                u64::from(public_head as u32) + u64::from(public_residual as u32),
                score
            );
            // The three caps, evaluated on the statistics that the verifier computes.
            let public_caps = public_head >> 32 <= CAP_EUC2_HEAD
                && public_residual >> 32 <= CAP_EUC2_RES
                && u64::from(public_head as u32) + u64::from(public_residual as u32) <= CAP_Q20;
            assert_eq!(public_caps, caps);
            assert_eq!(decoded.as_slice(), head.as_slice());
            for i in 0..signature_codec::LABELS {
                let x = (quantize::center(labels[i]) - residual[i]).rem_euclid(Q);
                assert_eq!(
                    signature_codec::recover(x, decoded_local[i]),
                    Ok((labels[i] as u8, residual[i]))
                );
            }
        }
    }
}
