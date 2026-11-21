//! Preserve the full public table; gather packed entries, then unpack in NEON.
use core::arch::aarch64::*;

#[derive(Clone, Copy)]
pub(crate) struct Tables;
impl Tables {
    #[inline(always)]
    /// # Safety
    /// No additional safety preconditions: this constructs a zero-sized table marker and performs no
    /// unsafe operation.
    pub(crate) unsafe fn new() -> Self {
        Self
    }
}

/// Same total function as the scalar eight-lane recovery, including arbitrary
/// u16 contexts and u8 indices. Invalid or absent entries return (0, 451).
/// Only public values (or values under the accepted-packet release premise) reach
/// this function. It is not a private admission table lookup.
#[inline(always)]
/// # Safety
/// Requires AArch64 NEON. Inputs are initialized registers; arbitrary contexts and indices are allowed
/// because masking restricts each table offset to 0..7681*8. PUBLIC_RECOVERY is an initialized
/// [[u16;8];7681], and local arrays provide eight writable u16 lanes.
pub(crate) unsafe fn recover8(
    x: uint16x8_t,
    indices: uint8x8_t,
    _tables: Tables,
) -> (uint8x8_t, uint16x8_t) {
    // SAFETY: The caller supplies the function safety contract. Requires AArch64 NEON. Inputs are
    // initialized registers; arbitrary contexts and indices are allowed because masking restricts each
    // table offset to 0..7681*8. PUBLIC_RECOVERY is an initialized [[u16;8];7681], and local arrays
    // provide eight writable u16 lanes.
    unsafe {
        let wide = vmovl_u8(indices);
        let valid = vandq_u16(
            vcltq_u16(x, vdupq_n_u16(7681)),
            vcltq_u16(wide, vdupq_n_u16(8)),
        );
        let safe_x = vandq_u16(x, valid);
        let safe_i = vandq_u16(wide, valid);
        let mut contexts = [0u16; 8];
        let mut local = [0u16; 8];
        let mut entries = [0u16; 8];
        vst1q_u16(contexts.as_mut_ptr(), safe_x);
        vst1q_u16(local.as_mut_ptr(), safe_i);
        for i in 0..8 {
            // SAFETY: vector masking maps each invalid lane to (0,0); every
            // other lane satisfies x<7681 and i<8. The table is contiguous u16.
            let offset = usize::from(contexts[i]) * 8 + usize::from(local[i]);
            entries[i] = *super::PUBLIC_RECOVERY.as_ptr().cast::<u16>().add(offset);
        }
        let packed = vld1q_u16(entries.as_ptr());
        let present = vandq_u16(valid, vmvnq_u16(vceqq_u16(packed, vdupq_n_u16(u16::MAX))));
        let labels = vmovn_u16(vandq_u16(vandq_u16(packed, vdupq_n_u16(63)), present));
        let magnitudes = vbslq_u16(present, vshrq_n_u16::<6>(packed), vdupq_n_u16(451));
        (labels, magnitudes)
    }
}

#[cfg(test)]
#[path = "recovery_tests.rs"]
mod tests;
