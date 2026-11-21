//! Predicate binding only: finite test cases do not prove the sampler law,
//! matrix spread, transport law or independence of random tapes.
use super::*;
use crate::{quantize, rice_codec as codec};

fn reference(head: &[i32; 1280], residual: &[i32; 1024], local: &[i32; 1024]) -> bool {
    let mut hn = 0u64;
    let mut rn = 0u64;
    let mut score = 0u64;
    let mut quotient = 0u64;
    for (i, &v) in head.iter().enumerate() {
        let a = v.unsigned_abs() as usize;
        let limit = if i < 256 {
            FORMAT_HEAD_LIMIT_LEAD as usize
        } else {
            FORMAT_HEAD_LIMIT as usize
        };
        if a > limit {
            return false;
        }
        hn += (a * a) as u64;
        score += u64::from(W_HEAD[a]);
        let zz = ((v as u32) << 1) ^ ((v >> 31) as u32);
        quotient += u64::from(zz >> if i < 256 { 3 } else { 6 });
    }
    for &v in residual {
        let a = v.unsigned_abs() as usize;
        if a > FORMAT_RES_LIMIT as usize {
            return false;
        }
        rn += (a * a) as u64;
        score += u64::from(W_RES[a]);
    }
    hn <= CAP_EUC2_HEAD
        && rn <= CAP_EUC2_RES
        && score <= CAP_Q20
        && quotient <= 1088
        && local.iter().filter(|&&k| k >= 2).count() <= codec::EXCEPTIONS
}

#[test]
fn row_certificate_signer_and_verifier_predicates() {
    assert_eq!((Q, N, ELL, M, LQ), (7681, 256, 4, 4, 34));
    assert_eq!(
        (CAP_EUC2_HEAD, CAP_EUC2_RES, CAP_Q20),
        (1593 * 1593, 3068 * 3068, 30850912)
    );
    // The generic cap is 451; the Rice capacity/recovery predicate tightens it to 450.
    assert_eq!((CAP_INF_HEAD, CAP_INF_RES), (288, 451));
    assert_eq!(
        (FORMAT_HEAD_LIMIT_LEAD, FORMAT_HEAD_LIMIT, FORMAT_RES_LIMIT),
        (288, 255, 450)
    );
    assert_eq!(
        (codec::HEAD_BYTES, codec::HINT_BYTES, codec::EXCEPTIONS),
        (1160, 169, 50)
    );
    assert_eq!((W_HEAD.len(), W_RES.len()), (289, 452));
    let matrix = MatrixAh {
        rows: [[crate::compact_ring::CompactPoly::ZERO; ELL + 1]; M],
    };
    for case in 0..640usize {
        let mut head = [0i32; 1280];
        let mut labels = [0i32; 1024];
        let mut residual = [0i32; 1024];
        let mut local = [0i32; 1024];
        let mut expected_local = [0i32; 1024];
        let mut delta = [Poly::ZERO; M];
        for i in 0..1024 {
            let x = ((i * 719 + case * 31) % Q as usize) as i32;
            let u = quantize::q_label(x);
            labels[i] = u;
            residual[i] = (quantize::center(u) - x + Q / 2).rem_euclid(Q) - Q / 2;
            expected_local[i] = i32::from(codec::public_local_index(x, u).unwrap());
            delta[i / N].0[i % N] = x;
        }
        match case % 8 {
            0 => head[case % 1280] = case as i32 - 320,
            1 => head.fill((case % 65) as i32 - 32),
            2 => residual[case % 1024] = [450, 451, -450, -451][case / 8 % 4],
            3 => {
                // Exactly 1088 and 1089 Rice quotient units, inside coefficient caps.
                for v in &mut head[..15] {
                    *v = 288;
                }
                head[15] = if case / 8 % 2 == 0 { 32 } else { 36 };
            }
            4 => {
                // Exactly 50/51 label exceptions, with recoverable residuals.
                for i in 0..50 + case / 8 % 2 {
                    let x = delta[i / N].0[i % N];
                    let (u, r) = codec::recover(x, 2).unwrap();
                    labels[i] = i32::from(u);
                    residual[i] = r;
                }
            }
            5 => head.fill(288),
            6 => residual.fill(450),
            _ => {}
        }
        // Recover contexts from labels and residuals, as the signer capacity test does.
        let mut recoverable = true;
        for i in 0..1024 {
            let x = (quantize::center(labels[i]) - residual[i]).rem_euclid(Q);
            delta[i / N].0[i % N] = x;
            if let Some(k) = codec::public_local_index(x, labels[i]) {
                expected_local[i] = i32::from(k);
            } else {
                recoverable = false;
            }
        }
        let expected = recoverable && reference(&head, &residual, &expected_local);
        let capacity = codec::capacity_mask(&head, &labels, &residual, &mut local) == u64::MAX;
        let actual = capacity && check_caps_ct(&head, &residual) == u64::MAX;
        assert_eq!(actual, expected, "signer case {case}");
        if !capacity {
            continue;
        }
        assert_eq!(local, expected_local);
        let mut response = vec![0; codec::HEAD_BYTES];
        let mut hint = vec![0; codec::HINT_BYTES];
        codec::encode_admitted(&head, &local, &mut response, &mut hint);
        let mut decoded = [0; 1280];
        let decoded = codec::decode_head_borrowed(&response, &mut decoded).unwrap();
        let planes = codec::decode_local_planes(&hint).unwrap();
        let mut recovered_labels = [0u8; 1024];
        let packed = matrix
            .compact_residual_caps(&decoded, &delta, &planes, &mut recovered_labels)
            .unwrap();
        let h = public_head_packed(&decoded);
        let accepted = h >> 32 <= CAP_EUC2_HEAD
            && packed >> 32 <= CAP_EUC2_RES
            && (h as u32 as u64) + (packed as u32 as u64) <= CAP_Q20;
        assert_eq!(accepted, expected, "verifier case {case}");
        assert_eq!(recovered_labels.map(i32::from), labels);
    }
    // Every context x and label u whose centred residual is at most 450 in absolute
    // value: `public_local_index` followed by `recover` returns the label and residual.
    for x in 0..Q {
        for u in 0..34 {
            let r = (quantize::center(u) - x + Q / 2).rem_euclid(Q) - Q / 2;
            if r.unsigned_abs() <= FORMAT_RES_LIMIT as u32 {
                let k = codec::public_local_index(x, u).unwrap();
                assert_eq!(codec::recover(x, k).unwrap(), (u as u8, r));
            }
        }
    }
}
