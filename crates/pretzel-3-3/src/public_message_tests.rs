//! Shared tests for the common-prefix public message transcript.
use super::*;

// The scalar context continuation, kept only in the test image.
// Taking the raw message snapshot also spells out the empty-context prefix.
fn previous(prefixes: &PublicPrefixes, context: &[u8], message: &[u8]) -> [u8; 64] {
    let mut sponge = prefixes.message_fast.public_prefix_snapshot();
    sponge.part(context);
    sponge.public_part(message);
    let mut reader = crate::shake2::PublicReader::from_absorbed(sponge);
    let mut out = [0; 64];
    reader.read(&mut out);
    out
}

// Plain Keccak over the full wire transcript, independent of all prepared
// prefixes, fast sponges, readers and public block assembly.
fn reference(pk: &[u8], context: &[u8], message: &[u8]) -> [u8; 64] {
    fn part(bytes: &mut Vec<u8>, input: &[u8]) {
        bytes.extend_from_slice(&(input.len() as u64).to_le_bytes());
        bytes.extend_from_slice(input);
    }
    let mut bytes = Vec::new();
    part(&mut bytes, PROFILE_ID);
    part(&mut bytes, &pk[..CORE_PK_BYTES]);
    bytes.extend_from_slice(DOM_MSG);
    bytes.extend_from_slice(&pk[CORE_PK_BYTES..]);
    part(&mut bytes, context);
    part(&mut bytes, message);
    bytes.push(0x1f);
    bytes.resize(bytes.len().div_ceil(136) * 136, 0);
    *bytes.last_mut().unwrap() ^= 0x80;
    let mut state = [0u64; 25];
    for block in bytes.chunks_exact(136) {
        for (word, input) in state.iter_mut().zip(block.chunks_exact(8)) {
            *word ^= u64::from_le_bytes(input.try_into().unwrap());
        }
        keccak::f1600(&mut state);
    }
    let mut out = [0; 64];
    for (chunk, word) in out.chunks_exact_mut(8).zip(state) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    out
}

#[test]
fn public_context_blocks_match_previous_and_plain_keccak() {
    let mut rng = 0x318abcdefu64;
    let mut bytes = |len| -> Vec<u8> {
        (0..len)
            .map(|_| {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                rng as u8
            })
            .collect()
    };
    let pk = bytes(PK_BYTES);
    let prefixes = PublicPrefixes::new(&pk);
    let prefix_len = 8 + PROFILE_ID.len() + 8 + CORE_PK_BYTES + DOM_MSG.len() + 32;
    let mut lengths = vec![0, 1, 7, 8, 32, 4096];
    // Every rate boundary through sixteen blocks, both payload-relative and
    // relative to the actual cached prefix plus the context length word.
    for block in 1usize..=16 {
        for boundary in [136 * block, 136 * block - (prefix_len + 8) % 136] {
            lengths.extend([boundary - 1, boundary, boundary + 1]);
        }
    }
    lengths.sort_unstable();
    lengths.dedup();
    for context_len in lengths {
        let context = bytes(context_len);
        let next = 136 - (prefix_len + 16 + context_len) % 136;
        for message_len in [0, 1, 32, next - 1, next, next + 1, next + 136, 4096] {
            let message = bytes(message_len);
            let got = prefixes.verify_message_rep(&context, &message);
            assert_eq!(got, previous(&prefixes, &context, &message));
            assert_eq!(got, reference(&pk, &context, &message));
        }
    }
}

// The exact scalar continuation, including the uncached mu length word.
fn previous_challenge(
    prefixes: &PublicPrefixes,
    mu: &[u8; 64],
    rho: &[u8; 32],
    labels: &[u8],
) -> [u8; 32] {
    let mut sponge = prefixes.challenge_fast.public_prefix_snapshot();
    sponge.public_part(mu);
    sponge.part(rho);
    sponge.public_part(labels);
    let mut reader = crate::shake2::PublicReader::from_absorbed(sponge);
    let mut out = [0; 32];
    reader.read(&mut out);
    out
}

#[test]
fn cached_verify_prefixes_match_uncached_at_rate_boundaries() {
    for pk_len in [0, 1, 135, 136, 137, PK_BYTES] {
        let key: Vec<u8> = (0..pk_len).map(|i| i as u8).collect();
        let prefix_len = if pk_len == PK_BYTES {
            8 + PROFILE_ID.len() + 8 + CORE_PK_BYTES + DOM_MSG.len() + 32
        } else {
            DOM_MSG.len() + 8 + PROFILE_ID.len() + 8 + pk_len
        };
        for context_len in [0, 1, 135, 136, 272] {
            let context = vec![0xa5; context_len];
            let offset = (prefix_len + 16 + context_len) % 136;
            let mut lengths = vec![0, 1];
            // Check raw message and framed message boundaries through sixteen blocks.
            for block in 1..=16 {
                for boundary in [136 * block, 136 * block - offset] {
                    lengths.extend([boundary - 1, boundary]);
                }
            }
            lengths.sort_unstable();
            lengths.dedup();
            for length in lengths {
                let message = vec![length as u8; length];
                let rho = [length as u8; 32];
                for labels_len in [0, 135, 136, 137, crate::params::M * 256] {
                    let labels = vec![0x5a; labels_len];
                    let prefixes = PublicPrefixes::new(&key);
                    assert!(prefixes.verify_prefixes.empty_context.get().is_none());
                    assert!(prefixes.verify_prefixes.challenge_mu64.get().is_none());
                    // First use and reuse of the same owner both match the
                    // uncached continuation at every transcript boundary.
                    for _ in 0..2 {
                        let mu = prefixes.verify_message_rep(&context, &message);
                        assert_eq!(mu, previous(&prefixes, &context, &message));
                        assert_eq!(
                            prefixes.verify_challenge_bytes(&mu, &rho, &labels),
                            previous_challenge(&prefixes, &mu, &rho, &labels)
                        );
                        assert_eq!(
                            prefixes.verify_prefixes.empty_context.get().is_some(),
                            context.is_empty()
                        );
                        assert!(prefixes.verify_prefixes.challenge_mu64.get().is_some());
                    }
                }
            }
        }
    }
}
