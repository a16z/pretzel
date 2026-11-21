//! Sparse release serialization in words. Called only after irrevocable admission.
//! All accumulators and branches are functions of the released packet.

#[cfg(test)]
pub(super) use crate::signature_codec::encode_admitted as encode_reference;

#[inline(always)]
fn index(bytes: &mut [u8], count: usize, value: usize) {
    let bit = count * 10;
    let value = (value as u32) << (bit % 8);
    bytes[bit / 8] |= value as u8;
    bytes[bit / 8 + 1] |= (value >> 8) as u8;
}

pub(super) fn encode(head: &[i32], local: &[i32; 768], response: &mut [u8], hint: &mut [u8]) {
    assert_eq!(head.len(), 1024);
    assert_eq!(response.len(), 981);
    assert_eq!(hint.len(), 147);
    response.fill(0);
    hint.fill(0);
    for (block, values) in head[..256].chunks_exact(8).enumerate() {
        let mut word = 0u64;
        for (lane, &v) in values.iter().enumerate() {
            word |= u64::from((v as u32) & 63) << (6 * lane);
        }
        response[6 * block..6 * block + 6].copy_from_slice(&word.to_le_bytes()[..6]);
    }
    let mut count = 0;
    for i in 0..768 {
        let v = head[256 + i];
        response[192 + i] = v as u8;
        if !(-128..=127).contains(&v) {
            index(&mut response[961..], count, i);
            count += 1;
        }
    }
    response[960] = count as u8;
    let mut count = 0;
    for (block, values) in local.chunks_exact(8).enumerate() {
        let mut primary = 0u8;
        let mut exceptional = 0u8;
        for (lane, &v) in values.iter().enumerate() {
            primary |= ((v & 1) as u8) << lane;
            exceptional |= ((v >> 1) as u8) << lane;
        }
        hint[block] = primary;
        while exceptional != 0 {
            let lane = exceptional.trailing_zeros() as usize;
            exceptional &= exceptional - 1;
            index(&mut hint[97..], count, 8 * block + lane);
            count += 1;
        }
    }
    hint[96] = count as u8;
}

#[cfg(test)]
mod tests {
    use super::*;
    fn compare(head: &[i32; 1024], local: &[i32; 768]) {
        let (mut a, mut b) = ([0xa5; 981], [0x5a; 981]);
        let (mut x, mut y) = ([0xa5; 147], [0x5a; 147]);
        encode(head, local, &mut a, &mut x);
        crate::signature_codec::encode_admitted(head, local, &mut b, &mut y);
        assert_eq!(a, b);
        assert_eq!(x, y);
        let mut decoded = [0; 1024];
        crate::signature_codec::decode_head(&a, &mut decoded).unwrap();
        assert_eq!(&decoded, head);
        let mut decoded = [0; 768];
        crate::signature_codec::decode_local(&x, &mut decoded).unwrap();
        assert_eq!(&decoded.map(i32::from), local);
    }
    #[test]
    fn sparse_packets_fixed_seeds_and_boundaries() {
        let mut seed = 20261110u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for case in 0..2048 {
            let mut head = [0; 1024];
            for v in &mut head[..256] {
                *v = (next() % 63) as i32 - 31;
            }
            for v in &mut head[256..] {
                *v = (next() % 256) as i32 - 128;
            }
            for j in 0..case % 17 {
                head[256 + (j * 47 + case) % 768] = if j % 2 == 0 { -255 } else { 255 };
            }
            let mut local = core::array::from_fn(|_| (next() & 1) as i32);
            for j in 0..case % 41 {
                local[(j * 19 + case) % 768] += 2;
            }
            compare(&head, &local);
        }
        for i in 0..1024 {
            let values: &[i32] = if i < 256 {
                &[-31, -1, 0, 1, 31]
            } else {
                &[-255, -129, -128, -1, 0, 1, 127, 128, 255]
            };
            for &v in values {
                let mut head = [0; 1024];
                head[i] = v;
                compare(&head, &[0; 768]);
            }
        }
        // Simultaneous full response/hint capacities at both boundary ends.
        for end in [false, true] {
            let mut head = [0; 1024];
            let mut local = [0; 768];
            for i in 0..16 {
                head[256 + if end { 767 - i } else { i }] = if i % 2 == 0 { -255 } else { 255 };
            }
            for i in 0..40 {
                local[if end { 767 - i } else { i }] = 2 + (i % 2) as i32;
            }
            compare(&head, &local);
        }
        // Every possible hint block mask at both ends.
        for mask in 0u16..256 {
            for block in [0, 1, 94, 95] {
                let mut local = [0; 768];
                for i in 0..8 {
                    local[8 * block + i] = 1 + 2 * i32::from((mask >> i) & 1);
                }
                compare(&[0; 1024], &local);
            }
        }
    }
    struct Tape {
        xof: crate::hashes::Xof,
        calls: Vec<usize>,
    }
    impl Tape {
        fn new(seed: &[u8]) -> Self {
            Self {
                xof: crate::hashes::Xof::new(b"R3-SPARSE-PACK-ORACLE-v1", &[seed]),
                calls: Vec::new(),
            }
        }
    }
    impl crate::EntropySource for Tape {
        fn fill(&mut self, bytes: &mut [u8]) -> Result<(), crate::EntropyError> {
            self.calls.push(bytes.len());
            self.xof.fill(bytes);
            Ok(())
        }
    }
    #[test]
    fn sparse_signatures_keys_attempts_entropy_and_erasure() {
        use crate::scheme::{keygen_with_entropy, Ctx, PreparedSk, SigningScratch};
        let ctx = Ctx::new();
        let verifier = crate::scheme::verifier::PreparedVerifier::new(&ctx).unwrap();
        for seed in 0u64..4 {
            let key = keygen_with_entropy(&ctx, &mut Tape::new(&seed.to_le_bytes())).unwrap();
            let sk = PreparedSk::new(&key.sk).unwrap();
            for case in 0u64..8 {
                let bytes = [seed.to_le_bytes(), case.to_le_bytes()].concat();
                let msg = vec![case as u8; [0, 32, 136, 1024][case as usize % 4]];
                let context = if case % 2 == 0 {
                    &b""[..]
                } else {
                    &b"sparse-oracle"[..]
                };
                let (mut a, mut b) = (Tape::new(&bytes), Tape::new(&bytes));
                let (mut sa, mut sb) = (SigningScratch::new(), SigningScratch::new());
                let expected = super::super::sign_with_policy::<true>(
                    &ctx, &sk, context, &msg, &mut a, &mut sa,
                )
                .unwrap();
                let got = super::super::sign_prepared_using_scratch(
                    &ctx, &sk, context, &msg, &mut b, &mut sb,
                )
                .unwrap();
                assert_eq!(got, expected);
                assert_eq!(a.calls, b.calls);
                let (mut ta, mut tb) = ([0; 64], [0; 64]);
                a.xof.fill(&mut ta);
                b.xof.fill(&mut tb);
                assert_eq!(ta, tb);
                assert!(sa.is_erased() && sb.is_erased());
                verifier
                    .verify_serialized_complete(&key.pk, context, &msg, &got.0)
                    .unwrap();
                assert_eq!(sk.public_key(), key.pk.as_slice());
            }
        }
    }
}
