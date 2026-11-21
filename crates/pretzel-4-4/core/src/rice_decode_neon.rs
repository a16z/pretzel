//! Public bounded Rice decoding: byte lookup for unary gaps, SIMD remainder merge.
use crate::params::{FORMAT_HEAD_LIMIT, FORMAT_HEAD_LIMIT_LEAD};
use core::arch::aarch64::*;
#[derive(Clone, Copy)]
struct UnaryByte {
    gaps: u64,
    count: u8,
    tail: u8,
}
const fn unary_table() -> [UnaryByte; 256] {
    let mut out = [UnaryByte {
        gaps: 0,
        count: 0,
        tail: 8,
    }; 256];
    let mut byte = 0;
    while byte < 256 {
        let mut gaps = 0u64;
        let mut count = 0;
        let mut previous = -1i32;
        let mut bit = 0;
        while bit < 8 {
            if byte & (1 << bit) != 0 {
                gaps |= ((bit - previous - 1) as u64) << (8 * count);
                count += 1;
                previous = bit;
            }
            bit += 1;
        }
        out[byte] = UnaryByte {
            gaps,
            count,
            tail: (7 - previous) as u8,
        };
        byte += 1;
    }
    out
}
static UNARY: [UnaryByte; 256] = unary_table();
const fn indices(width: usize) -> [u8; 16] {
    let mut out = [0; 16];
    let mut i = 0;
    while i < 8 {
        out[2 * i] = (i * width / 8) as u8;
        out[2 * i + 1] = (i * width / 8 + 1) as u8;
        i += 1;
    }
    out
}
const fn shifts(width: usize) -> [i16; 8] {
    let mut out = [0; 8];
    let mut i = 0;
    while i < 8 {
        out[i] = -((i * width % 8) as i16);
        i += 1;
    }
    out
}
static INDEX3: [u8; 16] = indices(3);
static INDEX6: [u8; 16] = indices(6);
static SHIFT3: [i16; 8] = shifts(3);
static SHIFT6: [i16; 8] = shifts(6);
#[inline(never)]
pub(super) fn decode(response: &[u8], head: &mut [i32; 1280]) -> Result<(), ()> {
    if response.len() != 1160 {
        return Err(());
    }
    let mut quotients = [0u8; 1288];
    let mut used = 0usize;
    let mut pending = 0usize;
    let unary = &response[864..];
    let mut at = 0;
    while at < unary.len() {
        if at + 4 <= unary.len() && unary[at..at + 4].iter().all(|&v| v != 0) {
            let a = UNARY[unary[at] as usize];
            let b = UNARY[unary[at + 1] as usize];
            let c = UNARY[unary[at + 2] as usize];
            let d = UNARY[unary[at + 3] as usize];
            let n0 = a.count as usize;
            let n1 = b.count as usize;
            let n2 = c.count as usize;
            let n3 = d.count as usize;
            let total = n0 + n1 + n2 + n3;
            if (a.gaps & 255) as usize + pending > 72 || used + total > 1280 {
                return Err(());
            }
            quotients[used..used + 8].copy_from_slice(&(a.gaps + pending as u64).to_le_bytes());
            let p = used + n0;
            quotients[p..p + 8].copy_from_slice(&(b.gaps + a.tail as u64).to_le_bytes());
            let p = p + n1;
            quotients[p..p + 8].copy_from_slice(&(c.gaps + b.tail as u64).to_le_bytes());
            let p = p + n2;
            quotients[p..p + 8].copy_from_slice(&(d.gaps + c.tail as u64).to_le_bytes());
            used += total;
            pending = d.tail as usize;
            at += 4;
        } else {
            let record = UNARY[unary[at] as usize];
            at += 1;
            if record.count == 0 {
                pending += 8;
                continue;
            }
            if (record.gaps & 255) as usize + pending > 72 || used + record.count as usize > 1280 {
                return Err(());
            }
            quotients[used..used + 8]
                .copy_from_slice(&(record.gaps + pending as u64).to_le_bytes());
            used += record.count as usize;
            pending = record.tail as usize;
        }
        if used == 1280 {
            if unary[at..].iter().any(|&v| v != 0) {
                return Err(());
            }
            break;
        }
    }

    if used != 1280 {
        return Err(());
    }
    // Fixed 2368-bit unary field and exactly 1280 delimiters imply sum(q)<=1088.
    // SAFETY: The response length check admits 1160 bytes; the largest 16-byte remainder load
    // ends at byte 873. The 160 eight-lane groups fit the 1288-byte quotients and 1280-i32 head
    // arrays. Fixed index/shift tables have complete vector widths; AArch64 supplies NEON and
    // output is exclusively borrowed.
    unsafe {
        let index3 = vld1q_u8(INDEX3.as_ptr());
        let index6 = vld1q_u8(INDEX6.as_ptr());
        let shift3 = vld1q_s16(SHIFT3.as_ptr());
        let shift6 = vld1q_s16(SHIFT6.as_ptr());
        let mut bad = vdupq_n_u16(0);
        for block in 0..160 {
            let offset = block * 8;
            let (position, index, shift, mask, bits, cap) = if block < 32 {
                (
                    block * 3,
                    index3,
                    shift3,
                    7,
                    3,
                    FORMAT_HEAD_LIMIT_LEAD as u16,
                )
            } else {
                (
                    96 + (block - 32) * 6,
                    index6,
                    shift6,
                    63,
                    6,
                    FORMAT_HEAD_LIMIT as u16,
                )
            };
            // The largest load ends at byte 873, within the checked response.
            // TBL selects only the current three or six remainder bytes.
            let raw = vld1q_u8(response.as_ptr().add(position));
            let low = vandq_u16(
                vshlq_u16(vreinterpretq_u16_u8(vqtbl1q_u8(raw, index)), shift),
                vdupq_n_u16(mask),
            );
            let q = vmovl_u8(vld1_u8(quotients.as_ptr().add(offset)));
            let v = vorrq_u16(low, vshlq_u16(q, vdupq_n_s16(bits)));
            let sign = vnegq_s16(vreinterpretq_s16_u16(vandq_u16(v, vdupq_n_u16(1))));
            let signed = veorq_s16(vreinterpretq_s16_u16(vshrq_n_u16::<1>(v)), sign);
            bad = vorrq_u16(
                bad,
                vcgtq_u16(vreinterpretq_u16_s16(vabsq_s16(signed)), vdupq_n_u16(cap)),
            );
            vst1q_s32(
                head.as_mut_ptr().add(offset),
                vmovl_s16(vget_low_s16(signed)),
            );
            vst1q_s32(head.as_mut_ptr().add(offset + 4), vmovl_high_s16(signed));
        }
        if vmaxvq_u16(bad) != 0 {
            return Err(());
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_byte_expands_correctly() {
        for byte in 0..256 {
            let row = UNARY[byte];
            let mut gaps = Vec::new();
            let mut previous = -1;
            for bit in 0..8 {
                if byte & (1 << bit) != 0 {
                    gaps.push((bit - previous - 1) as u8);
                    previous = bit;
                }
            }
            assert_eq!(row.count as usize, gaps.len());
            assert_eq!(&row.gaps.to_le_bytes()[..gaps.len()], gaps);
            assert_eq!(row.tail, (7 - previous) as u8);
        }
    }
    #[test]
    fn malformed_fields_match_scalar() {
        let mut rng = 17u64;
        for case in 0..100000 {
            let mut bytes = [0u8; 1160];
            for b in &mut bytes {
                rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
                *b = (rng >> 32) as u8;
            }
            if case % 3 == 0 {
                bytes[864..].fill(255);
                bytes[1024..].fill(0);
            }
            let (mut a, mut b) = ([0; 1280], [0; 1280]);
            let x = decode(&bytes, &mut a);
            let y = super::super::decode_head_scalar(&bytes, &mut b);
            assert_eq!(x.is_ok(), y.is_ok());
            if x.is_ok() {
                assert_eq!(a, b);
            }
        }
    }
    #[test]
    fn admitted_coefficients_and_bit_mutations_match() {
        let local = [0; 1024];
        let mut encoded = [0; super::super::HEAD_BYTES];
        let mut hint = [0; super::super::HINT_BYTES];
        for position in [
            0usize, 1, 7, 8, 247, 248, 255, 256, 257, 263, 264, 1272, 1279,
        ] {
            let cap = if position < 256 { 288 } else { 255 };
            for value in -cap..=cap {
                let mut head = [0; 1280];
                head[position] = value;
                super::super::encode_admitted(&head, &local, &mut encoded, &mut hint);
                let mut actual = [0; 1280];
                assert_eq!(decode(&encoded, &mut actual), Ok(()));
                assert_eq!(actual, head);
            }
        }
        // Exercise mixed nonzero quotient runs, including byte and field boundaries.
        let head = core::array::from_fn(|i| {
            if i < 256 {
                (i % 23) as i32 - 11
            } else {
                (i % 97) as i32 - 48
            }
        });
        super::super::encode_admitted(&head, &local, &mut encoded, &mut hint);
        let mut actual = [0; 1280];
        assert_eq!(decode(&encoded, &mut actual), Ok(()));
        assert_eq!(actual, head);
        for at in 0..encoded.len() {
            for bit in 0..8 {
                let mut changed = encoded;
                changed[at] ^= 1 << bit;
                let (mut a, mut b) = ([0; 1280], [0; 1280]);
                let x = decode(&changed, &mut a);
                let y = super::super::decode_head_scalar(&changed, &mut b);
                assert_eq!(x.is_ok(), y.is_ok());
                if x.is_ok() {
                    assert_eq!(a, b);
                }
            }
        }
    }
}
