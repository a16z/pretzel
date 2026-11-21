use super::*;

// The verifier, its entry point with a caller-supplied message representative and the
// scalar reference verifier must agree on every error variant and on success.
fn compare(pk: &PreparedPk, context: &[u8], message: &[u8], signature: &[u8]) {
    let verifier = PreparedVerifier;
    assert_eq!(
        format!("{:?}", verifier.verify(pk, context, message, signature)),
        format!(
            "{:?}",
            verifier.verify_using_message_rep(pk, signature, || {
                {
                    pk.prefixes.message_rep(context, message)
                }
            })
        )
    );
    assert_eq!(
        format!("{:?}", verifier.verify(pk, context, message, signature)),
        format!(
            "{:?}",
            verifier.verify_reference(pk, context, message, signature)
        )
    );
}

// A changed signature, context or message must be rejected, and the three verifiers
// must agree on the error.
fn rejects(pk: &PreparedPk, context: &[u8], message: &[u8], signature: &[u8]) {
    assert!(PreparedVerifier
        .verify(pk, context, message, signature)
        .is_err());
    compare(pk, context, message, signature);
}

// Public bytes already authenticated by the fixture test.
fn fixture(key: usize, case: usize) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    const FIXTURE: &[u8] = include_bytes!("signature_vectors.bin");
    const ROW: usize = 4 + 1908 + 64;
    assert_eq!(FIXTURE.len(), 4 * 2158 + 128 * ROW);
    let raw = FIXTURE[key * 2158..(key + 1) * 2158].to_vec();
    let offset = 4 * 2158 + (key * 32 + case) * ROW + 4;
    let signature = FIXTURE[offset..offset + 1908].to_vec();
    let context = match case % 3 {
        0 => vec![],
        1 => b"speed-conformance".to_vec(),
        _ => vec![0, 255, key as u8, case as u8],
    };
    let mut message = vec![0; [0, 32, 4096][(case / 3) % 3]];
    Xof::new(
        b"PRETZEL-RL5-SPEED-CONFORMANCE-MESSAGE-v1",
        &[&(key as u64).to_le_bytes(), &(case as u64).to_le_bytes()],
    )
    .fill(&mut message);
    (raw, signature, message, context)
}

#[test]
fn public_golden_vectors_and_all_signature_bit_rejects() {
    for key in 0..4 {
        let (raw, _, _, _) = fixture(key, 0);
        let pk = PreparedPk::new(&raw).unwrap();
        for case in 0..32 {
            let (_, signature, message, context) = fixture(key, case);
            PreparedVerifier
                .verify(&pk, &context, &message, &signature)
                .unwrap();
            {
                let mut head = [0; 1536];
                let (decoded, _) =
                    crate::signature_codec::decode_fields_borrowed(&signature[32..], &mut head)
                        .unwrap();
                crate::neon::public_response_ntt::check_decoded_columns(&decoded);
            }
            compare(&pk, &context, &message, &signature);
            rejects(&pk, b"wrong context", &message, &signature);
            rejects(&pk, &context, b"wrong message", &signature);
            // All bits and lengths on one complete signature per key; every
            // fixture case is checked above against the independent path.
            if case == 0 {
                // Valid fields reach message hashing with long wrong contexts,
                // including the first full context block and longer runs.
                for length in [116, 117, 118, 252, 253, 254, 389, 4096] {
                    rejects(&pk, &vec![0xa5; length], &message, &signature);
                }
                let mut bad = signature.clone();
                for bit in 0..signature.len() * 8 {
                    bad[bit / 8] ^= 1 << (bit % 8);
                    rejects(&pk, &context, &message, &bad);
                    bad[bit / 8] ^= 1 << (bit % 8);
                }
                for len in 0..signature.len() {
                    rejects(&pk, &context, &message, &signature[..len]);
                }
                // Corrupt several distant head/hint regions and the challenge together.
                for offset in [32, 63, 64, 127, 128, 255, 256, signature.len() - 1] {
                    let mut faults = signature.clone();
                    faults[0] ^= 0x80;
                    faults[offset] ^= 0x55;
                    faults[signature.len() - 2] ^= 0xaa;
                    rejects(&pk, b"wrong context", b"wrong message", &faults);
                }
                bad.push(0);
                rejects(&pk, &context, &message, &bad);
            }
        }
    }
}

#[test]
fn public_random_public_packets_match_reference_error_variants() {
    let mut state = 0x192837465u64;
    let mut next = || {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        (state >> 32) as u8
    };
    // A canonical public envelope and spectral b=0 need no private material.
    let mut raw = vec![0; crate::params::PUBLIC_KEY_WIRE_BYTES];
    raw[..14].copy_from_slice(crate::direct_ntt_profile::PROFILE);
    let pk = PreparedPk::new(&raw).unwrap();
    for trial in 0..256 {
        let mut sig = vec![0; crate::signature_codec::SIGNATURE_BYTES];
        for byte in &mut sig {
            *byte = next();
        }
        // Mostly well-formed low fields, plus unrestricted malformed controls.
        if trial % 2 == 0 {
            sig[32 + 1472] = 0;
            sig[32 + 1473..32 + 1533].fill(0);
            sig[32 + 1853] = 0;
            sig[32 + 1854..].fill(0);
        }
        compare(&pk, b"", b"public random packet", &sig);
    }
}

// Pin observable error precedence on length/record/cap/hash mutations.
// A panicking representative closure also pins that early rejects do not hash.
#[test]
fn public_malformed_fixtures_pin_reject_order() {
    let (raw, signature, message, context) = fixture(0, 0);
    let pk = PreparedPk::new(&raw).unwrap();
    let verifier = PreparedVerifier;
    verifier
        .verify(&pk, &context, &message, &signature)
        .unwrap();
    let early = |packet: &[u8], expected: Error| {
        let actual = verifier.verify_public_using_message_rep(&pk, packet, || {
            panic!("message hash reached before early rejection")
        });
        assert_eq!(
            format!("{actual:?}"),
            format!("{:?}", Err::<(), _>(expected))
        );
        compare(&pk, b"wrong context", b"wrong message", packet);
    };
    let mut caps = signature.clone();
    caps[32..32 + 192].fill(0x55);
    caps[32 + 192..32 + 1472].fill(127);
    caps[32 + 1472..32 + 1533].fill(0);
    // 1280 * 127^2 already exceeds CAP_EUC2_HEAD, before any hash check.
    early(&caps, Error::CapExceeded);
    for (offset, value) in [(1472, 41), (1853, 17), (1473, 1)] {
        let mut decode = caps.clone();
        decode[32 + offset] = value;
        early(&decode, Error::Decode);
        // Length outranks both malformed fields and exceeded caps.
        early(&decode[..decode.len() - 1], Error::SignatureLength);
        decode.push(0);
        early(&decode, Error::SignatureLength);
    }
    // A salt-only mutation preserves the decoded head, recovery and all caps.
    let mut mismatch = signature.clone();
    mismatch[0] ^= 1;
    let hashed = std::cell::Cell::new(false);
    let result = verifier.verify_public_using_message_rep(&pk, &mismatch, || {
        hashed.set(true);
        pk.prefixes.verify_message_rep(&context, &message)
    });
    assert!(hashed.get());
    assert!(matches!(result, Err(Error::ChallengeMismatch)));
    compare(&pk, &context, &message, &mismatch);
}
