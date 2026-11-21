//! Release-only packing. The caller has already irrevocably admitted the response.
//! Every variable branch/address below is a function of eventual public bytes.
struct Unary<'a> {
    bytes: &'a mut [u8],
    base: usize,
    word: u64,
    position: usize,
}
impl Unary<'_> {
    fn flush(&mut self) {
        let at = self.base / 8;
        let n = (self.bytes.len() - at).min(8);
        self.bytes[at..at + n].copy_from_slice(&self.word.to_le_bytes()[..n]);
    }
    #[inline(always)]
    fn put(&mut self, q: usize) {
        self.position += q;
        if self.position - self.base >= 64 {
            self.flush();
            self.base = (self.position / 64) * 64;
            self.word = 0;
        }
        self.word |= 1u64 << (self.position - self.base);
        self.position += 1;
    }
}
#[inline(always)]
fn block<const WIDTH: usize>(values: &[i32], low: &mut [u8], unary: &mut Unary<'_>) {
    let mut packed = 0u64;
    for (j, &v) in values.iter().enumerate() {
        let value = super::zigzag(v);
        packed |= u64::from(value & ((1 << WIDTH) - 1)) << (WIDTH * j);
        unary.put((value >> WIDTH) as usize);
    }
    low.copy_from_slice(&packed.to_le_bytes()[..WIDTH]);
}
pub(super) fn encode(head: &[i32], local: &[i32; 1024], response: &mut [u8], hint: &mut [u8]) {
    assert_eq!(head.len(), 1280);
    assert_eq!(response.len(), super::HEAD_BYTES);
    assert_eq!(hint.len(), super::HINT_BYTES);
    response.fill(0);
    hint.fill(0);
    let (low, unary) = response.split_at_mut(864);
    {
        let mut writer = Unary {
            bytes: unary,
            base: 0,
            word: 0,
            position: 0,
        };
        for i in 0..32 {
            block::<3>(
                &head[i * 8..i * 8 + 8],
                &mut low[i * 3..i * 3 + 3],
                &mut writer,
            );
        }
        for i in 0..128 {
            block::<6>(
                &head[256 + i * 8..256 + i * 8 + 8],
                &mut low[96 + i * 6..96 + i * 6 + 6],
                &mut writer,
            );
        }
        writer.flush();
    }
    let (primary, ef) = hint.split_at_mut(128);
    let (count, rest) = ef.split_at_mut(1);
    let (low, high) = rest.split_at_mut(super::LOW_BYTES);
    let mut used = 0;
    for (chunk, values) in local.chunks_exact(8).enumerate() {
        let mut first = 0u8;
        let mut second = 0u8;
        for j in 0..8 {
            first |= ((values[j] & 1) as u8) << j;
            second |= (((values[j] >> 1) & 1) as u8) << j;
        }
        primary[chunk] = first;
        while second != 0 {
            let lane = second.trailing_zeros() as usize;
            second &= second - 1;
            let index = 8 * chunk + lane;
            super::write(low, used * super::SPLIT, super::SPLIT, index as u32);
            let bit = (index >> super::SPLIT) + used;
            high[bit / 8] |= 1 << (bit % 8);
            used += 1;
        }
    }
    count[0] = used as u8;
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn release_packing_matches_scalar_reference() {
        let mut state = 51u64;
        for case in 0..2000 {
            let head = core::array::from_fn::<_, 1280, _>(|i| {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                let b = if i < 256 { 25 } else { 129 };
                ((state >> 32) % b) as i32 - (b / 2) as i32
            });
            let mut local = [0; 1024];
            for i in 0..1024 {
                local[i] = ((i + case) & 1) as i32;
            }
            let count = case % (super::super::EXCEPTIONS + 1);
            for j in 0..count {
                local[(j * 19 + case) % 1024] += 2;
            }
            let (mut a, mut b) = ([0; super::super::HEAD_BYTES], [0; super::super::HEAD_BYTES]);
            let (mut x, mut y) = ([0; super::super::HINT_BYTES], [0; super::super::HINT_BYTES]);
            encode(&head, &local, &mut a, &mut x);
            super::super::encode_admitted_scalar(&head, &local, &mut b, &mut y);
            assert_eq!(a, b);
            assert_eq!(x, y);
            let mut decoded = [0; 1280];
            super::super::decode_head(&a, &mut decoded).unwrap();
            assert_eq!(decoded, head);
            let mut hints = [0u8; 1024];
            super::super::decode_local(&x, &mut hints).unwrap();
            assert_eq!(hints.map(i32::from), local);
        }
    }
}

#[cfg(test)]
mod unary_oracle {
    use super::*;
    #[test]
    fn word_writer_matches_bit_oracle_at_boundaries() {
        for first in 0..128 {
            for q in [0usize, 1, 7, 8, 63, 64, 65, 72] {
                let mut backing = [0xa5u8; 304];
                backing[4..300].fill(0);
                let mut expected = [0u8; 296];
                let mut writer = Unary {
                    bytes: &mut backing[4..300],
                    base: 0,
                    word: 0,
                    position: 0,
                };
                let mut pos = 0;
                for gap in [first, q, 0, 1, 63, 64, 72] {
                    writer.put(gap);
                    pos += gap;
                    expected[pos / 8] |= 1 << (pos % 8);
                    pos += 1;
                }
                writer.flush();
                assert_eq!(&backing[4..300], &expected);
                assert_eq!(&backing[..4], &[0xa5; 4]);
                assert_eq!(&backing[300..], &[0xa5; 4]);
            }
        }
        let mut actual = [0u8; 296];
        let mut writer = Unary {
            bytes: &mut actual,
            base: 0,
            word: 0,
            position: 0,
        };
        writer.put(2367);
        writer.flush();
        assert_eq!(actual[295], 128);
        assert!(actual[..295].iter().all(|&v| v == 0));
    }
}

#[cfg(test)]
mod admitted_boundaries {
    use super::*;
    fn compare(head: &[i32; 1280], local: &[i32; 1024]) {
        let sum: usize = head
            .iter()
            .enumerate()
            .map(|(i, &v)| (super::super::zigzag(v) >> if i < 256 { 3 } else { 6 }) as usize)
            .sum();
        assert!(sum <= 1088);
        assert!(head
            .iter()
            .enumerate()
            .all(|(i, &v)| v.unsigned_abs() <= if i < 256 { 288 } else { 255 }));
        assert!(local.iter().all(|&k| (0..4).contains(&k)));
        assert!(local.iter().filter(|&&k| k >= 2).count() <= 50);
        let (mut a, mut b) = (
            [0xa5; super::super::HEAD_BYTES],
            [0x5a; super::super::HEAD_BYTES],
        );
        let (mut x, mut y) = (
            [0xa5; super::super::HINT_BYTES],
            [0x5a; super::super::HINT_BYTES],
        );
        encode(head, local, &mut a, &mut x);
        super::super::encode_admitted_scalar(head, local, &mut b, &mut y);
        assert_eq!(a, b);
        assert_eq!(x, y);
        let mut decoded = [0; 1280];
        super::super::decode_head(&a, &mut decoded).unwrap();
        assert_eq!(&decoded, head);
        let mut decoded = [0; 1024];
        super::super::decode_local(&x, &mut decoded).unwrap();
        assert_eq!(&decoded.map(i32::from), local);
    }
    #[test]
    fn whole_packets_all_unary_sums_and_field_boundaries() {
        // Every possible final position, including full words and the last physical word.
        for sum in 0usize..=1088 {
            for reverse in [false, true] {
                let mut head = [0; 1280];
                let mut remaining = sum;
                for j in 0..1280 {
                    let i = if reverse { 1279 - j } else { j };
                    let width = if i < 256 { 3 } else { 6 };
                    let q = remaining.min(if i < 256 { 72 } else { 7 });
                    remaining -= q;
                    head[i] = ((q << width) / 2) as i32;
                }
                assert_eq!(remaining, 0);
                let mut local = [0; 1024];
                for (i, k) in local.iter_mut().enumerate() {
                    *k = (i & 1) as i32;
                }
                for j in 0..sum % 51 {
                    local[(j * 19 + sum) % 1024] += 2;
                }
                compare(&head, &local);
            }
        }
        for i in [0, 7, 8, 255, 256, 263, 264, 1279] {
            let cap = if i < 256 { 288 } else { 255 };
            for value in [-cap, -1, 0, 1, cap] {
                let mut head = [0; 1280];
                head[i] = value;
                let mut local = [0; 1024];
                local[0] = 2;
                local[1023] = 3;
                compare(&head, &local);
            }
        }
    }
    #[test]
    fn empty_full_and_partial_final_word() {
        let mut bytes = [0u8; 296];
        let mut writer = Unary {
            bytes: &mut bytes,
            base: 0,
            word: 0,
            position: 0,
        };
        writer.flush();
        assert_eq!(bytes, [0; 296]);
        for count in [1, 63, 64, 65, 1280, 2367, 2368] {
            let mut bytes = [0u8; 296];
            let mut writer = Unary {
                bytes: &mut bytes,
                base: 0,
                word: 0,
                position: 0,
            };
            for _ in 0..count {
                writer.put(0);
            }
            writer.flush();
            for bit in 0..2368 {
                assert_eq!((bytes[bit / 8] >> (bit % 8)) & 1, u8::from(bit < count));
            }
        }
    }
}
