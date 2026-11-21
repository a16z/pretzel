//! Composite initial proposal with leading-even and direct major laws.
use crate::coretail_major as major;
use core::{
    mem::MaybeUninit,
    sync::atomic::{compiler_fence, Ordering},
};
// Identity value barrier.
// SAFETY: comment-only assembly leaves its initialized register unchanged;
// it accesses no memory/stack and preserves flags. Deliberately not pure.
#[inline(always)]
fn opaque_mask(mut value: u64) -> u64 {
    // SAFETY: the template is an assembler comment, so no instruction is emitted. The only operand
    // is a general-purpose register holding an initialized u64; no memory, stack or flag is
    // touched, as the options state.
    unsafe {
        core::arch::asm!("/* {value} */",value=inout(reg)value,options(nomem,nostack,preserves_flags));
    }
    value
}
pub const ENTROPY_BYTES: usize = 10944;
#[repr(C, align(16))]
pub struct Workspace {
    leading: crate::leading_alias32::Workspace,
    major: major::Workspace,
    values: [i16; 2560],
}
impl Workspace {
    pub fn clear(&mut self) {
        // SAFETY: `self` is a unique reference, so the pointer is valid for writes of
        // `size_of::<Self>()` bytes and nothing else refers to them. Every field is an integer
        // array or a struct of integer arrays, so the all-zero bytes left behind are a valid
        // `Workspace`. `erase` accepts any alignment.
        unsafe {
            crate::retirement::erase(
                (self as *mut Self).cast::<u8>(),
                core::mem::size_of::<Self>(),
            );
        }
        compiler_fence(Ordering::SeqCst);
    }
}
struct Lease<'a>(&'a mut Workspace);
impl Drop for Lease<'_> {
    fn drop(&mut self) {
        self.0.clear();
    }
}
struct EntropyOwner<'a>(&'a mut [u8; ENTROPY_BYTES]);
impl Drop for EntropyOwner<'_> {
    fn drop(&mut self) {
        // SAFETY: the owner holds the only reference to the `ENTROPY_BYTES`-byte array, which is
        // exactly the range erased; zero bytes are valid `u8` values.
        unsafe {
            crate::retirement::erase(self.0.as_mut_ptr(), ENTROPY_BYTES);
        }
        compiler_fence(Ordering::SeqCst);
    }
}
struct OutputOwner<'a> {
    value: &'a mut [i32; 2816],
    released: bool,
}
impl Drop for OutputOwner<'_> {
    fn drop(&mut self) {
        if !self.released {
            for x in &mut self.value[..] {
                // SAFETY: `x` is a unique reference to one `i32` of the output array, valid and
                // aligned for a volatile write.
                unsafe {
                    core::ptr::write_volatile(x, 0);
                }
            }
            compiler_fence(Ordering::SeqCst);
        }
    }
}
#[cfg(test)]
std::thread_local! {static PANIC_AFTER:core::cell::Cell<u8>=const{core::cell::Cell::new(0)};}
#[cfg(test)]
fn checkpoint(stage: u8) {
    PANIC_AFTER.with(|p| {
        if p.get() == stage {
            panic!("injected sampling panic");
        }
    });
}
pub fn generate<E, F: FnOnce(&mut [u8; ENTROPY_BYTES]) -> Result<(), E>>(
    fill: F,
    entropy: &mut [u8; ENTROPY_BYTES],
    storage: &mut MaybeUninit<Workspace>,
    out: &mut [i32; 2816],
) -> Result<bool, E> {
    let mut output = OutputOwner {
        value: out,
        released: false,
    };
    let out = &mut *output.value;
    out.fill(0);
    // SAFETY: `storage` is a unique reference to a `MaybeUninit<Workspace>`, so it is valid for
    // writes of `size_of::<Workspace>()` bytes; a byte fill has no alignment requirement and may
    // target uninitialized memory.
    unsafe {
        storage
            .as_mut_ptr()
            .cast::<u8>()
            .write_bytes(0, core::mem::size_of::<Workspace>());
    }
    // SAFETY: the fill above wrote every byte of the slot with zero, and all-zero bytes are a valid
    // `Workspace` (integer arrays only, at every nesting level).
    let work = Lease(unsafe { storage.assume_init_mut() });
    let tape = EntropyOwner(entropy);
    fill(&mut *tape.0)?;
    let bad_leading = opaque_mask(crate::leading_alias32::sample_owned(
        (&tape.0[..1856]).try_into().unwrap(),
        (&mut out[..256]).try_into().unwrap(),
        &mut work.0.leading,
    ) as u64);
    #[cfg(test)]
    checkpoint(1);
    let bad_major = opaque_mask(major::sample_owned(
        (&tape.0[1856..]).try_into().unwrap(),
        &mut work.0.values,
        &mut work.0.major,
    ) as u64);
    #[cfg(test)]
    checkpoint(2);
    let bad = bad_leading | bad_major;
    let mut keep = 0u32.wrapping_sub((bad ^ 1) as u32);
    // SAFETY: the template is an assembler comment, so no instruction is emitted. The only operand
    // is the 32-bit view of a general-purpose register holding an initialized value; no memory,
    // stack or flag is touched, as the options state.
    unsafe {
        core::arch::asm!("/* {keep:w} */",keep=inout(reg) keep,options(nomem,nostack,preserves_flags));
    }
    for x in &mut out[..256] {
        *x &= keep as i32;
    }
    for i in 0..2560 {
        out[256 + i] = (work.0.values[i] as i32) & keep as i32;
    }
    #[cfg(test)]
    checkpoint(3);
    output.released = true;
    Ok(bad != 0)
}
#[cfg(test)]
mod conditional_tests {
    use super::*;
    fn erased(w: &MaybeUninit<Workspace>) {
        // SAFETY: every caller passes storage that `generate` zero-filled in full and then erased
        // in full through raw byte writes, without moving it, so all `size_of::<Workspace>()` bytes
        // are initialized; `u8` has no alignment requirement.
        let bytes = unsafe {
            core::slice::from_raw_parts(w.as_ptr().cast::<u8>(), core::mem::size_of::<Workspace>())
        };
        assert!(bytes.iter().all(|x| *x == 0));
    }
    // SHA-256 of the records built below; `generators/gen_proposal_fixtures.py` pins the same
    // value for the records its model of this function produces.
    const PIN: &str = "520ad041d762fc6a24cef7af0a6fa0868f97cd9b106e00f01ace9eb24ce5887c";

    /// Input `row` of the fixture set of `generate`; the generators README states the rule.
    fn fixture_input(row: usize) -> [u8; ENTROPY_BYTES] {
        let mut e = [0u8; ENTROPY_BYTES];
        if row < 198 {
            crate::fixture_gen::expand("coretail-composite", row as u32, &mut e[..1856]);
            e[1856..].copy_from_slice(&major::fixture_input(row));
        } else {
            let mut leading_row = row - 198;
            if row >= 214 {
                leading_row = row + 585;
            }
            let leading = crate::leading_alias32::fixture_input(leading_row);
            e[..1856].copy_from_slice(&leading);
            e[1856..].copy_from_slice(&major::fixture_input(0));
        }
        e
    }

    #[test]
    fn independent_composite_fixtures_and_owners() {
        let mut hash = crate::fixture_gen::Records::new();
        let mut owner = Box::<Workspace>::new_uninit();
        let mut entropy = [0; ENTROPY_BYTES];
        let mut output = [0; 2816];
        let mut aborts = Vec::new();
        for row in 0..218 {
            let input = fixture_input(row);
            let mut calls = 0;
            let bad = generate(
                |e| {
                    calls += 1;
                    e.copy_from_slice(&input);
                    Ok::<(), u8>(())
                },
                &mut entropy,
                &mut owner,
                &mut output,
            )
            .unwrap();
            assert_eq!(calls, 1);
            if bad {
                aborts.push(row);
                assert_eq!(output, [0; 2816]);
            }
            hash.update(&input);
            hash.update(&[bad as u8]);
            for value in output {
                hash.update(&value.to_le_bytes());
            }
            hash.end();
            assert_eq!(entropy, [0; ENTROPY_BYTES]);
            erased(&owner);
        }
        // Rows 37, 41, 55 and 69 abort in the major sampler, rows 214 to 217 in the leading one.
        assert_eq!(aborts, [37, 41, 55, 69, 214, 215, 216, 217]);
        hash.check("coretail-composite", PIN);
    }
    #[test]
    fn partial_fill_error_and_unwind_retire() {
        let mut owner = Box::<Workspace>::new_uninit();
        let mut e = [77; ENTROPY_BYTES];
        let mut o = [88; 2816];
        let result = generate(
            |e| {
                e[..997].fill(55);
                Err::<(), u8>(9)
            },
            &mut e,
            &mut owner,
            &mut o,
        );
        assert_eq!(result, Err(9));
        assert_eq!(e, [0; ENTROPY_BYTES]);
        assert_eq!(o, [0; 2816]);
        erased(&owner);
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = generate(
                |e| {
                    e[..991].fill(3);
                    panic!("injected fill panic");
                    #[allow(unreachable_code)]
                    Ok::<(), u8>(())
                },
                &mut e,
                &mut owner,
                &mut o,
            );
        }));
        assert!(panic.is_err());
        assert_eq!(e, [0; ENTROPY_BYTES]);
        assert_eq!(o, [0; 2816]);
        erased(&owner);
    }
    #[test]
    fn sampling_unwind_retires_workspace_entropy_and_output() {
        let fixture = fixture_input(0);
        for stage in 1..=3 {
            let mut owner = Box::<Workspace>::new_uninit();
            let mut e = [0; ENTROPY_BYTES];
            let mut o = [77; 2816];
            PANIC_AFTER.with(|p| p.set(stage));
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = generate(
                    |e| {
                        e.copy_from_slice(&fixture);
                        Ok::<(), u8>(())
                    },
                    &mut e,
                    &mut owner,
                    &mut o,
                );
            }));
            PANIC_AFTER.with(|p| p.set(0));
            assert!(result.is_err());
            assert_eq!(e, [0; ENTROPY_BYTES]);
            assert_eq!(o, [0; 2816]);
            erased(&owner);
        }
    }
}
