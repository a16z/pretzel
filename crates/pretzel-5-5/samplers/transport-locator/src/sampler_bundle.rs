//! Exact eight-bit prefix lookup followed by full-width fixed-round products.
use super::{opaque_mask, tables};
use core::sync::atomic::{compiler_fence, Ordering};

const fn product(a: &[u64; 6], b: &[u64; 6], width: usize) -> [u64; 12] {
    let mut out = [0u64; 12];
    let mut i = 0;
    while i < 6 {
        let mut carry = 0u128;
        let mut j = 0;
        while j < width {
            let z = a[i] as u128 * b[j] as u128 + out[i + j] as u128 + carry;
            out[i + j] = z as u64;
            carry = z >> 64;
            j += 1;
        }
        // The previous row ends at i+width-1, so this limb is still zero.
        out[i + width] = carry as u64;
        i += 1;
    }
    out
}

const fn table() -> [[u8; 256]; 48] {
    let mut out = [[0u8; 256]; 48];
    let mut m = 0;
    while m < 256 {
        let mut a = [0u64; 6];
        let mut seen = m & 1;
        let mut j = 0;
        while j < 6 {
            a[j] = tables::POWERS[0][j] & 0u64.wrapping_sub(seen as u64);
            j += 1;
        }
        let mut i = 1;
        while i < 8 {
            let p = product(&a, &tables::POWERS[i], 6);
            let sm = 0u64.wrapping_sub(seen as u64);
            let bit = (m >> i) & 1;
            let bm = 0u64.wrapping_sub(bit as u64);
            j = 0;
            while j < 6 {
                let candidate = tables::POWERS[i][j] ^ ((p[j + 6] ^ tables::POWERS[i][j]) & sm);
                a[j] ^= (candidate ^ a[j]) & bm;
                j += 1;
            }
            seen |= bit;
            i += 1;
        }
        j = 0;
        while j < 48 {
            out[j][m] = (a[j / 8] >> (8 * (j % 8))) as u8;
            j += 1;
        }
        m += 1;
    }
    out
}

static PREFIX: [[u8; 256]; 48] = table();

pub struct Prefixes([[u64; 6]; 13]);
impl Prefixes {
    /// Return only public zeros; private prefix states are filled in place.
    pub fn zeroed() -> Self {
        Self([[0; 6]; 13])
    }
    pub fn get(&self, lane: usize) -> &[u64; 6] {
        &self.0[lane]
    }
}
impl Drop for Prefixes {
    fn drop(&mut self) {
        for lane in &mut self.0 {
            for x in lane {
                // SAFETY: `x` is a unique reference to an initialized u64 of this owner, so it is
                // valid and aligned for one volatile write.
                unsafe {
                    core::ptr::write_volatile(x, 0);
                }
            }
        }
        compiler_fence(Ordering::SeqCst);
    }
}

/// Populate an already-owned buffer, avoiding a by-value private return copy.
/// The caller installs the erasing owner before this function touches secrets.
pub fn prefix13(m: &[u64; 13], out: &mut Prefixes) {
    out.0 = [[0; 6]; 13];
    // SAFETY: feature: only NEON intrinsics are used; NEON is in the baseline of the AArch64
    // macOS target this crate is built for (the parent build script rejects any other target;
    // this crate has no check of its own). Lengths: `indices` and `bytes` are 16-byte arrays,
    // exactly one `vld1q_u8` or `vst1q_u8` each; every row of `PREFIX` has 256 bytes and `bank <
    // 4`, so the four 16-byte loads at `64 * bank + {0, 16, 32, 48}` end at byte 256 at most.
    // Alignment: the loads and the store are byte-wise and need none. The volatile writes go
    // through unique references to the two local arrays.
    unsafe {
        use core::arch::aarch64::*;
        let mut indices = [0u8; 16];
        let mut bytes = [0u8; 16];
        for (dst, src) in indices.iter_mut().zip(m) {
            *dst = *src as u8;
        }
        let index = vld1q_u8(indices.as_ptr());
        for (plane, row) in PREFIX.iter().enumerate() {
            let mut value = vdupq_n_u8(0);
            for bank in 0..4 {
                let p = row.as_ptr().add(64 * bank);
                let t = uint8x16x4_t(
                    vld1q_u8(p),
                    vld1q_u8(p.add(16)),
                    vld1q_u8(p.add(32)),
                    vld1q_u8(p.add(48)),
                );
                value = vorrq_u8(
                    value,
                    vqtbl4q_u8(t, vsubq_u8(index, vdupq_n_u8((64 * bank) as u8))),
                );
            }
            vst1q_u8(bytes.as_mut_ptr(), value);
            for (lane, byte) in out.0.iter_mut().zip(&bytes) {
                lane[plane / 8] |= (*byte as u64) << (8 * (plane % 8));
            }
        }
        for x in indices.iter_mut().chain(bytes.iter_mut()) {
            core::ptr::write_volatile(x, 0);
        }
        compiler_fence(Ordering::SeqCst);
    }
}

#[allow(clippy::needless_range_loop)]
pub(super) fn power_prefixed(m: u64, prefix: &[u64; 6]) -> [u64; 6] {
    let mut a = *prefix;
    let mut seen = opaque_mask(((m & 255) != 0) as u64);
    for i in 8..29 {
        let powers = &tables::POWERS[i];
        let width = 6;
        let p = product(&a, powers, width);
        let bit = opaque_mask((m >> i) & 1);
        let sm = opaque_mask(0u64.wrapping_sub(opaque_mask(seen)));
        let bm = opaque_mask(0u64.wrapping_sub(opaque_mask(bit)));
        for (j, value) in a.iter_mut().enumerate() {
            let candidate = powers[j] ^ ((p[j + 6] ^ powers[j]) & sm);
            *value ^= (candidate ^ *value) & bm;
        }
        seen |= bit;
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn prefixed_power_matches_fixed_round_power() {
        for high in [0, 1, 0x1fffff, u64::MAX >> 8] {
            for low in 0..256u64 {
                let m = (high << 8) | low;
                let mut p = Prefixes::zeroed();
                prefix13(&[m; 13], &mut p);
                for lane in 0..13 {
                    assert_eq!(power_prefixed(m, p.get(lane)), super::super::power(m));
                }
            }
        }
    }
    #[test]
    fn sampler_bundle_sparse_products_and_owner_retirement() {
        let mut seed = 91u64;
        for (round, width) in [(26, 5), (27, 4), (28, 1)] {
            assert!(tables::POWERS[round][width..].iter().all(|x| *x == 0));
            for trial in 0..4096 {
                let a = core::array::from_fn(|i| {
                    seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                    match trial {
                        0 => 0,
                        1 => u64::MAX,
                        2 => 1 << i,
                        _ => seed,
                    }
                });
                assert_eq!(
                    product(&a, &tables::POWERS[round], width),
                    super::super::mul(&a, &tables::POWERS[round])
                );
            }
        }
        let mut storage = core::mem::MaybeUninit::<Prefixes>::uninit();
        storage.write(Prefixes::zeroed());
        // SAFETY: `storage.write` initialized the slot on the line above.
        prefix13(&[255; 13], unsafe { storage.assume_init_mut() });
        // SAFETY: the slot is initialized and is dropped exactly once here (`MaybeUninit` never
        // drops it again). `Prefixes` is 13 rows of 6 u64 words, so the 78-word view covers exactly
        // the same aligned storage, whose bytes stay initialized integers after the drop.
        unsafe {
            core::ptr::drop_in_place(storage.as_mut_ptr());
            let words = core::slice::from_raw_parts(storage.as_ptr().cast::<u64>(), 78);
            assert!(words.iter().all(|x| *x == 0));
        }
    }
}

#[cfg(test)]
mod prefix_owner_tests {
    use super::*;
    #[test]
    fn in_place_refill_and_unwind_retire_the_same_owner() {
        let mut storage = core::mem::MaybeUninit::new(Prefixes::zeroed());
        // MaybeUninit does not drop its contents. The borrowed guard below does,
        // including on unwind, then the test checks the backing bytes.
        struct Guard<'a>(&'a mut Prefixes);
        impl Drop for Guard<'_> {
            fn drop(&mut self) {
                // SAFETY: the guard holds the only reference to an initialized `Prefixes` whose
                // storage is a `MaybeUninit`, so this is the single drop of that value.
                unsafe {
                    core::ptr::drop_in_place(self.0);
                }
            }
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            // SAFETY: `MaybeUninit::new` initialized the slot.
            let guard = Guard(unsafe { storage.assume_init_mut() });
            for m in [255, 0, 1, 128] {
                prefix13(&[m; 13], guard.0);
                for lane in 0..13 {
                    assert_eq!(*guard.0.get(lane), super::super::power(m));
                }
            }
            panic!("public prefix owner unwind fixture");
        }));
        assert!(result.is_err());
        // SAFETY: `Prefixes` is 13 rows of 6 u64 words, so the 78-word view covers exactly the
        // aligned storage, whose bytes stay initialized integers after the guard dropped the value.
        let words = unsafe { core::slice::from_raw_parts(storage.as_ptr().cast::<u64>(), 78) };
        assert!(words.iter().all(|x| *x == 0));
    }
}
