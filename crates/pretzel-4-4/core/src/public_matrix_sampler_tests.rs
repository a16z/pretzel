//! Differential tests shared by both parameter sets.
use super::{
    tests::{packed, reference_feed},
    *,
};

type Rows = [[CompactPoly; ELL + 1]; M];

fn same(a: &Cursor, b: &Cursor, out: &Rows, reference: &Rows) {
    assert_eq!((a.acc, a.bits, a.used), (b.acc, b.bits, b.used));
    assert_eq!(out, reference);
}

fn random(state: &mut u64) -> u8 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state as u8
}

struct Counted<'a> {
    bytes: &'a [u8],
    fetched: core::cell::Cell<usize>,
}
impl RateSource for Counted<'_> {
    fn len(&self) -> usize {
        self.bytes.len()
    }
    fn byte(&self, pos: usize) -> u8 {
        self.fetched.set(self.fetched.get().max(pos + 1));
        self.bytes[pos]
    }
    fn candidates(&self, pos: usize) -> [i16; 8] {
        self.fetched.set(self.fetched.get().max(pos + 13));
        self.bytes.candidates(pos)
    }
}

fn compare_chunk(
    lane: usize,
    bytes: &[u8],
    a: &mut Cursor,
    b: &mut Cursor,
    out: &mut Rows,
    expected: &mut Rows,
) {
    let source = Counted {
        bytes,
        fetched: core::cell::Cell::new(0),
    };
    a.feed_source(lane, &source, out);
    let fetched = reference_feed(b, lane, bytes, expected);
    assert_eq!(source.fetched.get(), fetched);
    same(a, b, out, expected);
}

#[test]
fn every_accept_pattern_stores_in_order_and_preserves_tail() {
    for mask in 0..256 {
        let candidates: [u16; 8] = core::array::from_fn(|lane| {
            if mask & (1 << lane) == 0 {
                8191
            } else {
                7680 - lane as u16
            }
        });
        let mut got = [37; 8];
        let count = store_eight(candidates.map(|value| value as i16), &mut got);
        let expected: Vec<i16> = candidates
            .iter()
            .copied()
            .filter(|&v| v < Q as u16)
            .map(|v| v as i16)
            .collect();
        assert_eq!(count, expected.len());
        assert_eq!(&got[..count], expected.as_slice());
        assert!(got[count..].iter().all(|&value| value == 37));
    }
    // Every candidate value in every position exercises the scalar store offsets.
    for lane in 0..8 {
        for value in 0..8192u16 {
            let mut candidates = [8191; 8];
            candidates[lane] = value;
            let mut got = [37; 8];
            let count = store_eight(candidates.map(|value| value as i16), &mut got);
            assert_eq!(count, usize::from(value < Q as u16));
            if count != 0 {
                assert_eq!(got[0], value as i16);
            }
            assert!(got[count..].iter().all(|&value| value == 37));
        }
    }
}

#[test]
fn every_accept_pattern_matches_across_polynomial_boundaries() {
    for lane in 0..2 {
        for mask in 0..256 {
            let candidates = core::array::from_fn::<_, 8, _>(|i| {
                if mask & (1 << i) == 0 {
                    8191
                } else {
                    100 + i as u16
                }
            });
            let bytes = packed(&candidates);
            for used in 248..=256 {
                let mut a = Cursor {
                    acc: 0,
                    bits: 0,
                    used,
                };
                let mut b = Cursor {
                    acc: 0,
                    bits: 0,
                    used,
                };
                let mut out = [[CompactPoly([37; N]); ELL + 1]; M];
                let mut expected = out;
                compare_chunk(lane, &bytes, &mut a, &mut b, &mut out, &mut expected);
            }
        }
    }
}

#[test]
fn every_rate_offset_short_tail_and_quota_matches_scalar_state() {
    for lane in 0..2 {
        for offset in 0..RATE {
            for pattern in 0..12 {
                let mut rng = 0x123456789abcdefu64 + offset as u64;
                let bytes: Vec<u8> = if pattern == 11 {
                    (0..3 * RATE).map(|_| random(&mut rng)).collect()
                } else {
                    let candidates: Vec<u16> = (0..3 * RATE)
                        .map(|i| match pattern {
                            0 => 0,
                            1 => 8191,
                            2 => {
                                if i % 2 == 0 {
                                    7680
                                } else {
                                    7681
                                }
                            }
                            _ => {
                                if i % 8 == pattern - 3 {
                                    8191
                                } else {
                                    i as u16
                                }
                            }
                        })
                        .collect();
                    packed(&candidates)
                };
                let mut a = Cursor::new();
                let mut b = Cursor::new();
                let mut out = [[CompactPoly([37; N]); ELL + 1]; M];
                let mut reference = out;
                // Every offset in the rate, including empty and incomplete input.
                for chunk in [
                    &bytes[..offset],
                    &bytes[offset..offset + RATE],
                    &bytes[offset + RATE..2 * RATE + offset],
                ] {
                    compare_chunk(lane, chunk, &mut a, &mut b, &mut out, &mut reference);
                }
                // Preserve the real residual bits, then end at each batch position.
                for remaining in 0..=8 {
                    let mut a = Cursor {
                        acc: b.acc,
                        bits: b.bits,
                        used: lane_coefficients(lane) - remaining,
                    };
                    let mut b = Cursor {
                        acc: a.acc,
                        bits: a.bits,
                        used: a.used,
                    };
                    let mut out = reference;
                    let mut expected = reference;
                    for chunk in [&bytes[..RATE], &[0u8; RATE][..], &[][..]] {
                        compare_chunk(lane, chunk, &mut a, &mut b, &mut out, &mut expected);
                    }
                    assert!(a.complete(lane));
                }
            }
        }
    }
}

#[test]
fn random_streams_and_swapped_physical_lanes_match_after_every_block() {
    for seed in 1..=64 {
        let mut rng = seed;
        let mut cursors = [Cursor::new(), Cursor::new()];
        let mut scalar = [Cursor::new(), Cursor::new()];
        let mut out = [[CompactPoly([37; N]); ELL + 1]; M];
        let mut expected = out;
        for block_index in 0..64 {
            let blocks: [[u8; RATE]; 2] = core::array::from_fn(|lane| {
                core::array::from_fn(|_| {
                    if lane == 1 && block_index < 7 {
                        255
                    } else {
                        random(&mut rng)
                    }
                })
            });
            let swap = block_index % 2;
            let pair = core::array::from_fn(|i| {
                if i / 2 < 17 {
                    let lane = (i % 2) ^ swap;
                    u64::from_le_bytes(
                        blocks[lane][8 * (i / 2)..8 * (i / 2 + 1)]
                            .try_into()
                            .unwrap(),
                    )
                } else {
                    u64::MAX
                }
            });
            for lane in 0..2 {
                cursors[lane].feed_pair(lane, lane ^ swap, &pair, &mut out);
                reference_feed(&mut scalar[lane], lane, &blocks[lane], &mut expected);
                same(&cursors[lane], &scalar[lane], &out, &expected);
            }
        }
        assert!(cursors.iter().enumerate().all(|(lane, c)| c.complete(lane)));
    }
}

#[test]
fn paired_candidates_match_serialized_rate_at_every_offset() {
    let pair = core::array::from_fn(|i| (i as u64).wrapping_mul(0x123456789abcdef));
    for lane in 0..2 {
        let source = PairRate { pair: &pair, lane };
        let bytes: [u8; RATE] = core::array::from_fn(|pos| source.byte(pos));
        for pos in 0..=RATE - 13 {
            assert_eq!(source.candidates(pos), bytes[..].candidates(pos));
        }
    }
}

#[test]
fn paired_candidate_extraction_exhaustive_symbols_and_alignments() {
    for offset in 0..8 {
        let physical_lane = offset % 2;
        for position in 0..8 {
            for value in 0..8192u16 {
                let mut candidates = [8191; 8];
                candidates[position] = value;
                let bytes = packed(&candidates);
                let mut pair = [0u64; 50];
                for (i, &byte) in bytes.iter().enumerate() {
                    let pos = offset + i;
                    pair[2 * (pos / 8) + physical_lane] |= (byte as u64) << (8 * (pos % 8));
                }
                let source = PairRate {
                    pair: &pair,
                    lane: physical_lane,
                };
                assert_eq!(source.candidates(offset), candidates.map(|v| v as i16));
            }
        }
    }
}

fn matrix_reader(seed: &[u8; 32], lane: usize) -> sha3::Shake256Reader {
    use sha3::digest::{ExtendableOutput, Update};
    let mut sponge = sha3::Shake256::default();
    sponge.update(crate::direct_ntt_profile::MATRIX_DOMAIN);
    sponge.update(&32u64.to_le_bytes());
    sponge.update(seed);
    sponge.update(&1u64.to_le_bytes());
    sponge.update(&[lane as u8]);
    sponge.finalize_xof()
}

#[test]
fn owning_and_portable_expansions_match_old_sampler_for_32_seeds() {
    for case in 0..32u8 {
        let seed = core::array::from_fn(|i| case.wrapping_mul(37).wrapping_add(i as u8));
        let mut expected = [[CompactPoly::ZERO; ELL + 1]; M];
        scalar(&seed, &mut expected);
        let owner = crate::direct_ntt_profile::PublicMatrixNtt::expand(&seed);
        assert_eq!(owner.into_rows(), expected);
        let mut rows = [[CompactPoly::ZERO; ELL + 1]; M];
        public_lockstep(&seed, &mut rows);
        assert_eq!(rows, expected);
        public(&seed, &mut rows);
        assert_eq!(rows, expected);
    }
}

#[test]
// Keep the original physical lane order explicit in the schedule oracle.
#[allow(clippy::needless_range_loop)]
fn lockstep_producers_preserve_squeeze_order_and_continuation_for_32_seeds() {
    use sha3::digest::XofReader;
    for case in 0..32u8 {
        let seed = core::array::from_fn(|i| case.wrapping_mul(31).wrapping_add(i as u8));
        // Independent model of the producer's squeeze and early-stop schedule.
        let mut readers = core::array::from_fn::<_, 2, _>(|lane| matrix_reader(&seed, lane));
        let mut cursors = [Cursor::new(), Cursor::new()];
        let mut expected = [[CompactPoly([37; N]); ELL + 1]; M];
        let mut trace = Vec::new();
        while cursors
            .iter()
            .enumerate()
            .any(|(lane, c)| !c.complete(lane))
        {
            let blocks: [[u8; RATE]; 2] = core::array::from_fn(|lane| {
                let mut block = [0; RATE];
                readers[lane].read(&mut block);
                trace.push((lane, block));
                block
            });
            for lane in 0..2 {
                cursors[lane].feed_scalar_oracle(lane, &blocks[lane], &mut expected);
            }
        }
        let continuation: [[u8; RATE]; 2] = core::array::from_fn(|lane| {
            let mut block = [0; RATE];
            readers[lane].read(&mut block);
            block
        });
        // Exercise both production producers against the independent schedule model.
        for paired in [false, true] {
            let mut readers = core::array::from_fn::<_, 2, _>(|lane| matrix_reader(&seed, lane));
            let mut actual_trace = Vec::new();
            let mut next = || {
                core::array::from_fn::<_, 2, _>(|lane| {
                    let mut block = [0; RATE];
                    readers[lane].read(&mut block);
                    actual_trace.push((lane, block));
                    block
                })
            };
            let mut rows = [[CompactPoly([37; N]); ELL + 1]; M];
            if paired {
                let mut pair = [u64::MAX; 50];
                fill_pair(
                    &mut pair,
                    |pair| {
                        let blocks = next();
                        for lane in 0..2 {
                            for word in 0..17 {
                                pair[2 * word + lane] = u64::from_le_bytes(
                                    blocks[lane][8 * word..8 * word + 8].try_into().unwrap(),
                                );
                            }
                        }
                    },
                    &mut rows,
                );
                for lane in 0..2 {
                    let source = PairRate { pair: &pair, lane };
                    let block: [u8; RATE] = core::array::from_fn(|pos| source.byte(pos));
                    assert_eq!(block, trace[trace.len() - 2 + lane].1);
                }
                assert!(pair[34..].iter().all(|&word| word == u64::MAX));
            } else {
                fill(next, &mut rows);
            }
            assert_eq!(rows, expected);
            assert_eq!(actual_trace, trace);
            for lane in 0..2 {
                let mut block = [0; RATE];
                readers[lane].read(&mut block);
                assert_eq!(block, continuation[lane]);
            }
        }
    }
}

#[test]
fn single_stream_squeezes_and_cursor_continuation_match_for_32_seeds() {
    use sha3::digest::XofReader;
    for case in 0..32u8 {
        let seed = core::array::from_fn(|i| case.wrapping_mul(19).wrapping_add(i as u8));
        for lane in 0..2 {
            let mut reader = matrix_reader(&seed, lane);
            let mut actual = Cursor::new();
            let mut oracle = Cursor::new();
            let mut rows = [[CompactPoly([37; N]); ELL + 1]; M];
            let mut expected = rows;
            while !oracle.complete(lane) {
                let mut block = [0; RATE];
                reader.read(&mut block);
                actual.feed(lane, &block, &mut rows);
                oracle.feed_scalar_oracle(lane, &block, &mut expected);
                same(&actual, &oracle, &rows, &expected);
            }
        }
    }
}
