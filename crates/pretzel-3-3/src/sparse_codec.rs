//! Public sparse-control codec. Encoding runs only after irreversible admission.
#[cfg(test)]
use super::write;
use super::{read, zeros};
fn exceptions(field: &[u8], capacity: usize, out: &mut [usize]) -> Result<usize, ()> {
    let count = usize::from(field[0]);
    if count > capacity {
        return Err(());
    }
    if !zeros(&field[1..], count * 10) {
        return Err(());
    }
    let mut previous = None;
    for i in 0..count {
        let at = read(&field[1..], 10 * i, 10) as usize;
        if at >= 768 || previous.is_some_and(|p| at <= p) {
            return Err(());
        }
        out[i] = at;
        previous = Some(at);
    }
    Ok(count)
}
pub(super) fn decode_head(bytes: &[u8], head: &mut [i32; 1024]) -> Result<(), ()> {
    if bytes.len() != 981 {
        return Err(());
    }
    // SAFETY: NEON is in the baseline of every target this crate builds for (`build.rs` asserts
    // little-endian AArch64 on macOS). `shuffle` and `shifts` are 16-byte locals, each
    // read by one load. `bytes.len() == 981` is checked above; the 32 loads of 16 bytes start at `6
    // * block <= 186` and end at byte 201 at most. The stores write four `i32` at `block * 8` and
    // at `block * 8 + 4`, which ends at entry 256 of the 1024 entries of `head`. All loads and
    // stores are unaligned forms.
    unsafe {
        use core::arch::aarch64::*;
        let shuffle = [0u8, 1, 0, 1, 1, 2, 2, 3, 3, 4, 3, 4, 4, 5, 5, 6];
        let shifts = [0i16, -6, -4, -2, 0, -6, -4, -2];
        let indices = vld1q_u8(shuffle.as_ptr());
        let shift = vld1q_s16(shifts.as_ptr());
        let mut bad = vdupq_n_u16(0);
        for block in 0..32 {
            // Last load ends at byte 201, inside the checked 981-byte response.
            let packed = vld1q_u8(bytes.as_ptr().add(6 * block));
            let values = vshlq_u16(vreinterpretq_u16_u8(vqtbl1q_u8(packed, indices)), shift);
            let signed = vshrq_n_s16::<10>(vreinterpretq_s16_u16(vshlq_n_u16::<10>(values)));
            bad = vorrq_u16(bad, vceqq_s16(signed, vdupq_n_s16(-32)));
            vst1q_s32(
                head.as_mut_ptr().add(block * 8),
                vmovl_s16(vget_low_s16(signed)),
            );
            vst1q_s32(head.as_mut_ptr().add(block * 8 + 4), vmovl_high_s16(signed));
        }
        if vmaxvq_u16(bad) != 0 {
            return Err(());
        }
    }
    for i in 0..768 {
        head[256 + i] = i32::from(bytes[192 + i] as i8);
    }
    let mut indices = [0usize; 16];
    let n = exceptions(&bytes[960..], 16, &mut indices)?;
    for &i in &indices[..n] {
        let v = &mut head[256 + i];
        if *v == 0 {
            return Err(());
        }
        *v += if *v < 0 { 256 } else { -256 };
    }
    Ok(())
}
pub(super) fn decode_local(bytes: &[u8], local: &mut [u8; 768]) -> Result<(), ()> {
    if bytes.len() != 147 {
        return Err(());
    }
    for i in 0..768 {
        local[i] = (bytes[i / 8] >> (i % 8)) & 1;
    }
    let mut indices = [0usize; 40];
    let n = exceptions(&bytes[96..], 40, &mut indices)?;
    for &i in &indices[..n] {
        local[i] += 2;
    }
    Ok(())
}
#[cfg(test)]
pub(super) fn encode(head: &[i32], local: &[i32; 768], response: &mut [u8], hint: &mut [u8]) {
    assert_eq!(head.len(), 1024);
    assert_eq!(response.len(), 981);
    assert_eq!(hint.len(), 147);
    response.fill(0);
    hint.fill(0);
    for i in 0..256 {
        write(response, i * 6, 6, head[i] as u32);
    }
    let mut count = 0;
    for i in 0..768 {
        let v = head[256 + i];
        response[192 + i] = v as u8;
        if !(-128..=127).contains(&v) {
            write(&mut response[961..], count * 10, 10, i as u32);
            count += 1;
        }
    }
    response[960] = count as u8;
    let mut count = 0;
    for i in 0..768 {
        hint[i / 8] |= ((local[i] & 1) as u8) << (i % 8);
        if local[i] >= 2 {
            write(&mut hint[97..], count * 10, 10, i as u32);
            count += 1;
        }
    }
    hint[96] = count as u8;
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn coefficients_and_canonical_mutations() {
        for value in -255i32..=255 {
            for at in [0, 1, 511, 767] {
                let mut head = [0; 1024];
                for i in 0..256 {
                    head[i] = (i % 63) as i32 - 31;
                }
                head[256 + at] = value;
                let mut local = [0; 768];
                for i in 0..768 {
                    local[i] = (i % 2) as i32;
                }
                for i in 0..40 {
                    local[18 * i] += 2;
                }
                let mut response = [0; 981];
                let mut hint = [0; 147];
                encode(&head, &local, &mut response, &mut hint);
                let mut recovered = [0; 1024];
                let mut indices = [0; 768];
                decode_head(&response, &mut recovered).unwrap();
                decode_local(&hint, &mut indices).unwrap();
                assert_eq!(head, recovered);
                assert_eq!(indices, local.map(|v| v as u8));
            }
        }
        let mut head = [0; 1024];
        let mut bytes = [0; 981];
        bytes[0] = 32;
        assert!(decode_head(&bytes, &mut head).is_err());
        bytes[0] = 0;
        bytes[960] = 17;
        assert!(decode_head(&bytes, &mut head).is_err());
        bytes[960] = 1;
        assert!(decode_head(&bytes, &mut head).is_err());
        let mut hint = [0; 147];
        let mut local = [0; 768];
        hint[96] = 41;
        assert!(decode_local(&hint, &mut local).is_err());
        hint[96] = 0;
        hint[146] = 96;
        assert!(decode_local(&hint, &mut local).is_err());
        hint[146] = 0;
        hint[96] = 2;
        assert!(decode_local(&hint, &mut local).is_err());
    }
    #[test]
    fn rejects_out_of_range_sparse_indices() {
        for at in 768..1024 {
            let mut head = [0; 1024];
            let mut bytes = [0; 981];
            bytes[960] = 1;
            write(&mut bytes[961..], 0, 10, at);
            assert!(decode_head(&bytes, &mut head).is_err());
            let mut hint = [0; 147];
            hint[96] = 1;
            write(&mut hint[97..], 0, 10, at);
            let mut local = [0; 768];
            assert!(decode_local(&hint, &mut local).is_err());
            assert!(super::super::decode_local_planes(&hint).is_err());
        }
    }
}
