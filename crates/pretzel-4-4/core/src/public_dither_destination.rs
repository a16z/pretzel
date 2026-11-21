//! Destination-only public dither decoding. Secret preparation keeps its decoder.
use crate::{
    dither_frame::{FrameError, DITHER_COEFFICIENTS, EXPANSION_CANDIDATES},
    params::{M, N},
    ring::Poly,
};
use core::mem::MaybeUninit;
#[cfg(test)]
use zeroize::Zeroizing;

const RATE: usize = 136;
const _: () = assert!(DITHER_COEFFICIENTS == M * N);

// A scoped public-only failure injection after real sponge work.
#[cfg(test)]
std::thread_local! {
    static EXHAUST: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}
#[cfg(test)]
pub(crate) fn with_exhausted<T>(f: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            EXHAUST.with(|v| v.set(false));
        }
    }
    EXHAUST.with(|v| assert!(!v.replace(true)));
    let _reset = Reset;
    f()
}

pub(crate) trait Destination {
    fn write(&mut self, index: usize, value: i32);
}

// Used by the public completion path and scheduler reference tests.
impl Destination for [i32; DITHER_COEFFICIENTS] {
    fn write(&mut self, index: usize, value: i32) {
        self[index] = value;
    }
}

impl Destination for MaybeUninit<[Poly; M]> {
    fn write(&mut self, index: usize, value: i32) {
        assert!(index < DITHER_COEFFICIENTS);
        // SAFETY: Poly is repr(transparent) over [i32; N]; [Poly; M] has
        // exactly M*N contiguous, aligned i32 slots with no padding. The
        // checked index stays in that allocation. This exclusive borrow
        // prevents aliases, and pointer writes never read unwritten slots
        // or form a reference to an uninitialized Poly.
        unsafe { self.as_mut_ptr().cast::<i32>().add(index).write(value) };
    }
}

/// Ok means all DITHER_COEFFICIENTS slots have been written, in order.
/// Error or unwind exposes no initialized-owner claim and drops only scratch.
#[cfg(test)]
pub(crate) fn decode_into(
    mut fill: impl FnMut(&mut [u8]),
    out: &mut impl Destination,
) -> Result<(), FrameError> {
    let mut block = Zeroizing::new([0u8; RATE]);
    let (mut pos, mut end, mut fetched, mut used) = (0, 0, 0, 0);
    for _ in 0..EXPANSION_CANDIDATES {
        if pos == end {
            end = (2 * EXPANSION_CANDIDATES - fetched).min(RATE);
            fill(&mut block[..end]);
            #[cfg(test)]
            EXHAUST.with(|v| {
                if v.get() {
                    block[..end].fill(255);
                }
            });
            pos = 0;
            fetched += end;
        }
        let v = u16::from_le_bytes([block[pos], block[pos + 1]]) & 8191;
        pos += 2;
        if v < 7681 {
            out.write(used, v as i32);
            used += 1;
            if used == DITHER_COEFFICIENTS {
                return Ok(());
            }
        }
    }
    Err(FrameError::DitherExhausted)
}

/// Read the public dither lane directly after each requested permutation.
/// STRIDE is one for scalar state and two for lane zero of a paired state.
/// Success initializes every destination coefficient in stream order.
pub(crate) fn decode_words<const WORDS: usize, const STRIDE: usize>(
    words: &mut [u64; WORDS],
    mut advance: impl FnMut(&mut [u64; WORDS], usize),
    out: &mut impl Destination,
) -> Result<(), FrameError> {
    assert!((STRIDE == 1 && WORDS == 25) || (STRIDE == 2 && WORDS == 50));
    let mut fetched = 0;
    let mut used = 0;
    while fetched < 2 * EXPANSION_CANDIDATES {
        let end = (2 * EXPANSION_CANDIDATES - fetched).min(RATE);
        advance(words, end);
        fetched += end;
        for pos in (0..end).step_by(2) {
            // Aligned 16-bit candidates never cross a numeric LE word.
            let v = ((words[STRIDE * (pos / 8)] >> (8 * (pos % 8))) & 8191) as i32;
            #[cfg(test)]
            let v = if EXHAUST.with(|flag| flag.get()) {
                8191
            } else {
                v
            };
            if v < 7681 {
                out.write(used, v);
                used += 1;
                if used == DITHER_COEFFICIENTS {
                    return Ok(());
                }
            }
        }
    }
    Err(FrameError::DitherExhausted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_dither_words_exhaustion_and_unwind() {
        let mut out = Box::<[Poly; M]>::new_uninit();
        let mut words = [0u64; 50];
        let mut calls = 0;
        let result = decode_words::<50, 2>(
            &mut words,
            |words, _| {
                words.fill(if calls == 0 { 0 } else { u64::MAX });
                calls += 1;
            },
            &mut *out,
        );
        assert_eq!(result, Err(FrameError::DitherExhausted));
        assert_eq!(calls, (2 * EXPANSION_CANDIDATES).div_ceil(RATE));
        let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut calls = 0;
            let _ = decode_words::<50, 2>(
                &mut words,
                |words, _| {
                    calls += 1;
                    if calls == 2 {
                        panic!("partial public destination");
                    }
                    words.fill(0);
                },
                &mut *out,
            );
        }));
        assert!(failed.is_err());
        // Both paths wrote only a prefix. Drop the allocation without reading it.
        drop(out);
    }

    #[test]
    fn public_dither_words_match_bytes_and_all_cutoffs() {
        for last in DITHER_COEFFICIENTS - 1..=EXPANSION_CANDIDATES {
            let mut bytes = vec![255u8; 2 * EXPANSION_CANDIDATES];
            for i in 0..DITHER_COEFFICIENTS - 1 {
                // High bits exercise the mask, including canonical endpoints.
                let value = ((i * 71) % 7681) as u16 | 0xe000;
                bytes[2 * i..2 * i + 2].copy_from_slice(&value.to_le_bytes());
            }
            if last < EXPANSION_CANDIDATES {
                bytes[2 * last..2 * last + 2].copy_from_slice(&7680u16.to_le_bytes());
            }
            let mut expected = [-1; DITHER_COEFFICIENTS];
            let mut old_fetched = 0;
            let old = decode_into(
                |block| {
                    block.copy_from_slice(&bytes[old_fetched..old_fetched + block.len()]);
                    old_fetched += block.len();
                },
                &mut expected,
            );
            fn compare<const W: usize, const S: usize>(
                bytes: &[u8],
                expected: &[i32; DITHER_COEFFICIENTS],
                old: Result<(), FrameError>,
                old_fetched: usize,
            ) {
                let mut words = [0u64; W];
                let mut fetched = 0;
                let mut actual = [-1; DITHER_COEFFICIENTS];
                let result = decode_words::<W, S>(
                    &mut words,
                    |words, end| {
                        for pos in (0..end).step_by(2) {
                            let shift = 8 * (pos % 8);
                            let value = u16::from_le_bytes([
                                bytes[fetched + pos],
                                bytes[fetched + pos + 1],
                            ]);
                            let word = &mut words[S * (pos / 8)];
                            *word = (*word & !(0xffffu64 << shift)) | ((value as u64) << shift);
                        }
                        fetched += end;
                    },
                    &mut actual,
                );
                assert_eq!(result, old);
                assert_eq!(fetched, old_fetched);
                assert_eq!(&actual, expected);
            }
            compare::<25, 1>(&bytes, &expected, old, old_fetched);
            compare::<50, 2>(&bytes, &expected, old, old_fetched);
        }
    }

    #[test]
    fn public_dither_destination_every_byte_and_all_cutoffs() {
        // Cover every possible final accepted candidate, including the last
        // partial rate block. Compare fetch extents and the reference decoder.
        for last in DITHER_COEFFICIENTS - 1..EXPANSION_CANDIDATES {
            let mut bytes = vec![255u8; 2 * EXPANSION_CANDIDATES];
            for i in 0..DITHER_COEFFICIENTS - 1 {
                bytes[2 * i..2 * i + 2].copy_from_slice(&((i % 7681) as u16).to_le_bytes());
            }
            bytes[2 * last..2 * last + 2].copy_from_slice(&7680u16.to_le_bytes());
            let mut expected = [0i32; DITHER_COEFFICIENTS];
            let mut old_fetched = 0;
            super::super::decode_into(
                |b| {
                    b.copy_from_slice(&bytes[old_fetched..old_fetched + b.len()]);
                    old_fetched += b.len();
                },
                &mut expected,
            )
            .unwrap();
            let mut actual = MaybeUninit::<[Poly; M]>::uninit();
            let mut fetched = 0;
            decode_into(
                |b| {
                    b.copy_from_slice(&bytes[fetched..fetched + b.len()]);
                    fetched += b.len();
                },
                &mut actual,
            )
            .unwrap();
            assert_eq!(fetched, old_fetched);
            // SAFETY: successful decode wrote every i32 in this padding-free
            // transparent polynomial array. No other bytes need initialization.
            let actual = unsafe { actual.assume_init() };
            let expected_bytes: Vec<u8> = expected.iter().flat_map(|v| v.to_ne_bytes()).collect();
            // SAFETY: every byte of actual is initialized and the byte slice
            // is read-only, in bounds, and cannot outlive the array.
            let actual_bytes = unsafe {
                core::slice::from_raw_parts(
                    actual.as_ptr().cast::<u8>(),
                    core::mem::size_of_val(&actual),
                )
            };
            assert_eq!(actual_bytes, expected_bytes.as_slice());
        }
    }

    #[test]
    fn public_dither_destination_exhaustion_and_unwind() {
        let mut out = MaybeUninit::<[Poly; M]>::uninit();
        let mut fetched = 0;
        assert_eq!(
            decode_into(
                |b| {
                    fetched += b.len();
                    b.fill(255);
                },
                &mut out,
            ),
            Err(FrameError::DitherExhausted)
        );
        assert_eq!(fetched, 2 * EXPANSION_CANDIDATES);
        // Write a partial owner before both failure modes; never assume_init.
        let mut calls = 0;
        assert_eq!(
            decode_into(
                |b| {
                    b.fill(if calls == 0 { 0 } else { 255 });
                    calls += 1;
                },
                &mut out,
            ),
            Err(FrameError::DitherExhausted)
        );
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut calls = 0;
            let _ = decode_into(
                |b| {
                    calls += 1;
                    if calls == 2 {
                        panic!("partial public dither");
                    }
                    b.fill(0);
                },
                &mut out,
            );
        }));
        assert!(result.is_err());
    }
}
