//! Compiled inside the backend to compare its actual private constants and
//! serializers with the generated paper table. All inputs are public fixtures.
use crate::{hashes::Xof, params::*};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use std::collections::BTreeMap;

fn table() -> BTreeMap<&'static str, Vec<u8>> {
    let mut rows = BTreeMap::new();
    for line in include_str!("../kat/spec_domains_table.tex").lines() {
        let Some((row, name)) = line.split_once("% spec:") else {
            continue;
        };
        let mut bytes = Vec::new();
        for chunk in row.split("\\texttt{").skip(1) {
            let hex = chunk.split_once('}').unwrap().0;
            assert_eq!(hex.len() % 2, 0);
            for pair in hex.as_bytes().chunks_exact(2) {
                bytes.push(u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap());
            }
        }
        assert!(rows.insert(name.trim(), bytes).is_none());
    }
    rows
}
fn part(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(bytes);
}
fn digest<const N: usize>(bytes: &[u8]) -> [u8; N] {
    let mut hash = Shake256::default();
    hash.update(bytes);
    let mut out = [0; N];
    hash.finalize_xof().read(&mut out);
    out
}
fn common(d: &BTreeMap<&str, Vec<u8>>, core: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    part(&mut out, &d["id"]);
    part(&mut out, core);
    out
}

#[test]
fn every_table_byte_matches_selected_constants() {
    let mut rows = table();
    let actual: [(&str, &[u8]); 15] = [
        ("id", PROFILE_ID),
        ("key", DOM_KEY),
        ("matrix", crate::direct_ntt_profile::MATRIX_DOMAIN),
        ("dither", crate::dither_frame::DOMAIN),
        ("message", DOM_MSG),
        ("challenge", DOM_CHAL),
        ("public_row", b"PRETZEL-RICE-PUBLIC-ROW-v1"),
        ("schedule", crate::randomness::CT_TAPE_DOMAIN),
        ("salt", DOM_SALT),
        ("lead", DOM_MASK_LEAD),
        ("secret", DOM_MASK_SEC),
        ("error", DOM_MASK_ERR),
        ("transport", DOM_TRANSPORT),
        ("dummy", DOM_DUMMY),
        ("integrity", &[]),
    ];
    for (name, bytes) in actual {
        assert_eq!(rows.remove(name).unwrap(), bytes, "{name}");
    }
    assert!(rows.is_empty(), "unmatched paper rows");
    assert_eq!(PROFILE_ID, crate::direct_ntt_profile::PROFILE);
    assert_eq!(PROFILE_ID, crate::dither_frame::PROFILE);
}

#[test]
fn public_serializers_match_paper_layouts() {
    let d = table();
    for case in [0u8, 1, 135, 136, 137, 255] {
        let seed = [case; 32];
        let body: Vec<u8> = (0..PK_BYTES)
            .map(|i| (i as u8).wrapping_mul(37).wrapping_add(case))
            .collect();
        let core = &body[..CORE_PK_BYTES];
        let dither_seed: &[u8; 32] = body[CORE_PK_BYTES..].try_into().unwrap();
        let context = vec![case; usize::from(case)];
        let message = vec![case.wrapping_add(1); 2 * usize::from(case)];
        let mu = [case; 64];
        let labels: Vec<u8> = (0..1024).map(|i| (i % 64) as u8).collect();
        let mut key = d["key"].clone();
        part(&mut key, &seed);
        assert_eq!(key.len(), 53);
        assert_eq!(
            digest::<512>(&key),
            Xof::new(DOM_KEY, &[&seed]).bytes::<512>()
        );
        assert_eq!(body.len(), 1728);
        assert_eq!(digest::<32>(&body), crate::hashes::shake256_32(&body));
        let mut input = common(&d, core);
        input.extend_from_slice(&d["message"]);
        input.extend_from_slice(dither_seed);
        part(&mut input, &context);
        part(&mut input, &message);
        assert_eq!(
            digest::<64>(&input),
            crate::hashes::message_rep(&body, &context, &message)
        );
        let mut input = common(&d, core);
        input.extend_from_slice(&d["challenge"]);
        input.extend_from_slice(dither_seed);
        part(&mut input, &mu);
        part(&mut input, &seed);
        part(&mut input, &labels);
        assert_eq!(input.len(), 2916);
        assert_eq!(
            digest::<32>(&input),
            crate::hashes::challenge_bytes(&body, &mu, &seed, &labels)
        );
        let mut input = common(&d, core);
        input.extend_from_slice(&d["dither"]);
        part(&mut input, dither_seed);
        let bytes = digest::<3072>(&input);
        let expected: Vec<i32> = bytes
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]) & 8191)
            .filter(|&x| x < 7681)
            .take(1024)
            .map(i32::from)
            .collect();
        let actual = crate::dither_frame::expand(core, dither_seed);
        if expected.len() == 1024 {
            assert_eq!(actual.unwrap().as_slice(), expected);
        } else {
            assert!(actual.is_err());
        }
    }
}

#[test]
fn matrix_serializer_and_bit_order_match_paper() {
    let d = table();
    for seed in [[0u8; 32], [0xa5; 32]] {
        let actual = crate::direct_ntt_profile::PublicMatrixNtt::expand(&seed);
        for lane in 0..2usize {
            let mut input = d["matrix"].clone();
            part(&mut input, &seed);
            part(&mut input, &[lane as u8]);
            let mut h = Shake256::default();
            h.update(&input);
            let mut reader = h.finalize_xof();
            let (mut bit, mut byte, mut used) = (8, 0u8, 0usize);
            while used < 2048 {
                let mut value = 0i32;
                for shift in 0..13 {
                    if bit == 8 {
                        let mut b = [0];
                        reader.read(&mut b);
                        byte = b[0];
                        bit = 0;
                    }
                    value |= i32::from((byte >> bit) & 1) << shift;
                    bit += 1;
                }
                if value < Q {
                    let poly = 2 * (used / N) + lane;
                    assert_eq!(
                        actual.spectral_poly(poly / ELL, poly % ELL).0[used % N],
                        value
                    );
                    used += 1;
                }
            }
        }
    }
}

#[test]
fn scheduled_attempt_serializers_match_paper() {
    let d = table();
    let key = [0x31; 32];
    let entropy = [0x82; 32];
    let mu = [0x57; 64];
    let body = vec![0x19; PK_BYTES];
    let prefixes = crate::randomness::StreamPrefixes::new(&key, &body);
    let mut pool = crate::ct_stream_schedule::PrefixPool::new();
    for retry in [0u32, 1, 255, 511] {
        let mut scheduled = crate::randomness::AttemptRandomness::from_prefixes_pooled(
            &prefixes, &mu, retry, &entropy, &mut pool,
        );
        let mut direct =
            crate::randomness::AttemptRandomness::new(&key, &body, &mu, retry, &entropy);
        for (index, name) in ["salt", "lead", "secret", "error", "transport", "dummy"]
            .iter()
            .enumerate()
        {
            let mut input = d[*name].clone();
            for field in [
                d["id"].as_slice(),
                &d["schedule"],
                &key,
                &body,
                &mu,
                &retry.to_le_bytes(),
                &entropy,
            ] {
                part(&mut input, field);
            }
            let expected = digest::<512>(&input);
            if index == 0 {
                assert_eq!(scheduled.rho, expected[..32]);
                assert_eq!(direct.rho, expected[..32]);
            } else {
                let direct_stream = match index {
                    1 => &mut direct.lead,
                    2 => &mut direct.secret,
                    3 => &mut direct.error,
                    4 => &mut direct.transport,
                    _ => &mut direct.dummy,
                };
                assert_eq!(direct_stream.bytes::<512>(), expected, "direct {name}");
                // The selected schedule allocates zero dummy bytes and reads none.
                if index != 5 {
                    let stream = match index {
                        1 => &mut scheduled.lead,
                        2 => &mut scheduled.secret,
                        3 => &mut scheduled.error,
                        _ => &mut scheduled.transport,
                    };
                    assert_eq!(stream.bytes::<512>(), expected, "scheduled {name}");
                }
            }
        }
        scheduled.recycle(&mut pool);
    }
}

#[test]
fn lambda_lower_endpoint_matches_oracle() {
    use crate::fixed::{fx_from_hex, Fx, FRAC_LIMBS, LIMBS};
    let ctx = crate::theta::ThetaCtx::new();
    assert!(ctx.lambda.valid());
    let lo = ctx.lambda.lo;
    assert_eq!(
        lo.0[FRAC_LIMBS], 0,
        "lambda must fit in 384 fractional bits"
    );
    let hex: String = lo.0[..FRAC_LIMBS]
        .iter()
        .rev()
        .map(|word| format!("{word:016x}"))
        .collect();
    println!("LAMBDA_LO=0x{hex}");
    // Round-to-nearest reference (theta.rs warm_lambda_matches_directed_oracle).
    // As in that test, the enclosure [lo, hi] must contain it up to 2^12 ulps;
    // lo is a lower endpoint, so it may sit well below the reference.
    let expect = fx_from_hex(concat!("0000000000000000",
        "ffb416894f3c7a0bc481a981ad807ddaa31794ffc411cab7d16dd3653df19c459b55e280c1c67913523d9365386a779a"));
    let mut slack = [0u64; LIMBS];
    slack[0] = 1 << 12;
    let slack = Fx(slack);
    assert!(
        lo.sub_sat(&slack).le(&expect) && expect.le(&ctx.lambda.hi.add(&slack)),
        "lambda enclosure does not contain the reference value"
    );
    assert!(
        lo.le(&expect),
        "lambda.lo must not exceed the reference value"
    );
    let distance = expect.sub(&lo);
    println!("LAMBDA_LO_DISTANCE_ULPS={} (ulp=2^-384)", distance.0[0]);
    // Exact lower endpoint the build computes; the specification states this value.
    let pinned = fx_from_hex(concat!("0000000000000000",
        "ffb416894f3c7a0bc481a981ad807ddaa31794ffc411cab7d16dd3653df19c459b55e280c1c67913523d93653864193d"));
    assert!(
        lo.le(&pinned) && pinned.le(&lo),
        "lambda.lo changed: {lo:?}"
    );
}

#[test]
fn public_mask_tables_and_key_supplement() {
    use std::io::Write;
    assert_eq!(
        include_bytes!("../kat/key_d256.h").as_slice(),
        include_bytes!("../core/src/interval-key256-table.h").as_slice()
    );
    let ctx = crate::theta::ThetaCtx::new();
    let mut output = Vec::new();
    writeln!(
        output,
        "# Selected rank-four public mask tables; projected 192-bit boundaries."
    )
    .unwrap();
    writeln!(output, "# P: name, weight, even-only, normalizer; B: name, index, symbol, boundary; A: name, index, row.").unwrap();
    writeln!(
        output,
        "# P/B: three u64 words, most significant first; A: same threshold plus metadata."
    )
    .unwrap();
    for (name, weight, even) in [
        ("lead", PROPOSAL_W0, true),
        ("secret", WS, false),
        ("error", WE, false),
    ] {
        let cdt = crate::gauss::Cdt::new(&ctx, weight, even);
        let (bounds, z) = cdt.ct_tables();
        let alias = crate::ct_alias::Alias::new(bounds, z).expect("selected mask alias");
        writeln!(
            output,
            "P\t{name}\t{weight}\t{even}\t{:016x}\t{:016x}\t{:016x}",
            z[0], z[1], z[2]
        )
        .unwrap();
        for (index, row) in bounds.iter().enumerate() {
            writeln!(
                output,
                "B\t{name}\t{index}\t{}\t{:016x}\t{:016x}\t{:016x}",
                cdt.values()[index],
                row[0],
                row[1],
                row[2]
            )
            .unwrap();
        }
        for index in 0..=alias.column_mask() as usize {
            let row = alias.row(index);
            writeln!(
                output,
                "A\t{name}\t{index}\t{:016x}\t{:016x}\t{:016x}\t{:016x}",
                row[0], row[1], row[2], row[3]
            )
            .unwrap();
        }
    }
    // Ordinary test runs need no filesystem output. It is written only when
    // PRETZEL_SPEC_MASK_OUTPUT is set.
    if let Some(path) = std::env::var_os("PRETZEL_SPEC_MASK_OUTPUT") {
        std::fs::write(path, output).expect("write public mask supplement");
    }
}
