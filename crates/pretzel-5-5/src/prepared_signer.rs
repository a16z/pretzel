//! Signer of Pretzel-(5,5), with 1908-byte signatures.
//! The signer does not verify its output before returning it.
use super::*;
pub const RESPONSE_BYTES: usize = crate::signature_codec::HEAD_BYTES;
pub const HINT_BYTES: usize = crate::signature_codec::HINT_BYTES;
pub const SIGNATURE_BYTES: usize = 32 + RESPONSE_BYTES + HINT_BYTES;

// Two-pass reference of `postfilter_residual_fused`, compiled for tests only.
// This parameter set has no hint field (`HINT_BYTES` is 0).
#[cfg(test)]
// Preserve the explicit borrow boundary used by the signer.
#[allow(clippy::needless_borrow)]
fn postfilter_fields(u_labels: &[i32; M * N], xs: &[i32; M * N], r_e: &mut [i32; M * N]) {
    for i in 0..M * N {
        // Canonical center and context put this difference in
        // (-Q, Q). No upper correction is needed after adding Q if negative.
        let difference = quantize::center(u_labels[i]) - xs[i];
        let residue = difference + Q * i32::from(difference < 0);
        r_e[i] = residue - Q * i32::from(residue > Q / 2);
    }
}

// Explicit-label release path: keep canonical xs in registers only.
// Both modular reductions are verbatim from the two-pass oracle.
#[inline(always)]
// Preserve the explicit borrow boundary used by the signer.
#[allow(clippy::needless_borrow)]
fn postfilter_residual_fused(
    u_labels: &[i32; M * N],
    t: &[Poly; M],
    z_e: &[i32],
    r_e: &mut [i32; M * N],
) {
    {
        crate::neon_mod_arith::residual(u_labels, t, z_e, r_e);
    }
}

// The initialized backing is created before its exclusive guard, and never
// moved after the first private write. Only the guard retires the backing.
mod private_z_owner {
    use super::DIM;
    use core::ops::{Deref, DerefMut};

    #[repr(C, align(8))]
    pub(super) struct Backing([i32; DIM]);
    const _: () = {
        assert!(DIM == 2816);
        assert!(core::mem::size_of::<Backing>() == DIM * 4);
        assert!(core::mem::align_of::<Backing>() >= 8);
        assert!(core::mem::size_of::<Backing>().is_multiple_of(8));
    };
    impl Backing {
        pub(super) fn zeroed() -> Self {
            Self([0; DIM])
        }
    }

    pub(super) struct Guard<'a> {
        backing: &'a mut Backing,
    }
    impl<'a> Guard<'a> {
        // Preserve the explicit borrow boundary used by the signer.
        #[allow(clippy::needless_borrow)]
        pub(super) fn new(backing: &'a mut Backing) -> Self {
            Self { backing }
        }
    }
    impl Deref for Guard<'_> {
        type Target = [i32; DIM];
        // Preserve the explicit borrow boundary used by the signer.
        #[allow(clippy::needless_borrow)]
        fn deref(&self) -> &Self::Target {
            &self.backing.0
        }
    }
    impl DerefMut for Guard<'_> {
        // Preserve the explicit borrow boundary used by the signer.
        #[allow(clippy::needless_borrow)]
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.backing.0
        }
    }
    impl Drop for Guard<'_> {
        // Preserve the explicit borrow boundary used by the signer.
        #[allow(clippy::needless_borrow)]
        fn drop(&mut self) {
            // SAFETY: Backing is initialized, has exactly DIM*4 bytes without
            // padding, is at least eight-byte aligned, and is exclusively
            // borrowed through this guard. No references escape that borrow.
            // The helper only writes zero over the full extent (1408 words),
            // never interprets private coefficients, and retains its fences.
            unsafe {
                crate::signer_erase::erase_struct_words(
                    (self.backing as *mut Backing).cast::<u64>(),
                    core::mem::size_of::<Backing>() / 8,
                );
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        fn pattern(i: usize) -> i32 {
            [i32::MIN, i32::MAX, -1, 0, 1, 7680, -7680][i % 7]
                .wrapping_add((i as i32).wrapping_mul(65537))
        }
        #[test]
        // Keep the integer predicate and its signedness explicit.
        #[allow(clippy::manual_is_multiple_of)]
        // Preserve the explicit borrow boundary used by the signer.
        #[allow(clippy::needless_borrow)]
        fn initialized_view_and_full_extent_retirement() {
            let mut backing = Backing::zeroed();
            let ptr = (&mut backing as *mut Backing) as usize;
            assert_eq!(ptr % 8, 0);
            {
                let mut guard = Guard::new(&mut backing);
                assert!(guard.iter().all(|&x| x == 0));
                let mut oracle = [0i32; DIM];
                for i in 0..DIM {
                    guard[i] = pattern(i);
                    oracle[i] = pattern(i);
                }
                assert_eq!(&*guard, &oracle);
                for i in 0..DIM {
                    guard[i] = guard[i].wrapping_add(i as i32);
                }
                for i in 0..DIM {
                    assert_eq!(guard[i], oracle[i].wrapping_add(i as i32));
                }
                assert_eq!(guard.as_ptr() as usize, ptr);
                // Dirty both endpoint words explicitly; Drop must cover both.
                guard[0] = -1;
                guard[DIM - 1] = i32::MIN;
            }
            assert!(backing.0.iter().all(|&x| x == 0));
        }
        #[test]
        // Preserve the explicit borrow boundary used by the signer.
        #[allow(clippy::needless_borrow)]
        fn normal_rejection_and_error_retire_same_extent() {
            // Preserve the explicit borrow boundary used by the signer.
            #[allow(clippy::needless_borrow)]
            fn attempt(backing: &mut Backing, outcome: u8) -> Result<bool, ()> {
                let mut z = Guard::new(backing);
                for i in 0..DIM {
                    z[i] = pattern(i);
                }
                match outcome {
                    0 => Ok(true),
                    1 => Ok(false),
                    _ => Err(()),
                }
            }
            let mut backing = Backing::zeroed();
            for outcome in 0..3 {
                let expected = match outcome {
                    0 => Ok(true),
                    1 => Ok(false),
                    _ => Err(()),
                };
                assert_eq!(attempt(&mut backing, outcome), expected);
                assert!(backing.0.iter().all(|&x| x == 0));
            }
        }
        #[test]
        // Preserve the explicit borrow boundary used by the signer.
        #[allow(clippy::needless_borrow)]
        fn unwind_retains_guard_before_private_write() {
            let mut backing = Backing::zeroed();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut z = Guard::new(&mut backing);
                for i in 0..DIM {
                    z[i] = pattern(i);
                }
                panic!("private z guard test");
            }));
            assert!(result.is_err());
            assert!(backing.0.iter().all(|&x| x == 0));
        }
    }
}

#[cfg(test)]
mod signer_tests {
    use super::*;
    #[test]
    // Preserve the explicit borrow boundary used by the signer.
    #[allow(clippy::needless_borrow)]
    fn zero_head_passes_the_caps_and_out_of_range_coefficients_fail() {
        // The zero head passes the caps; coefficient
        // +/-289 is a mathematical coefficient-cap failure.
        let mut z = [0i32; N * (ELL + 1)];
        let residual = [0i32; M * N];
        assert_eq!(check_caps_ct(&z, &residual), u64::MAX);
        for bad in [-289, 289, i32::MIN, i32::MAX] {
            z[0] = bad;
            assert_ne!(check_caps_ct(&z, &residual), u64::MAX);
        }
    }
}

#[cfg(test)]
mod fused_residual_tests {
    use super::*;
    #[test]
    // Preserve the explicit borrow boundary used by the signer.
    #[allow(clippy::needless_borrow)]
    fn fused_matches_two_pass_boundaries_and_abort_masks() {
        #[repr(C)]
        struct Guard {
            before: [i32; 4],
            values: [i32; M * N],
            after: [i32; 4],
        }
        let mut out = Guard {
            before: [0x13579; 4],
            values: [0; M * N],
            after: [0x24680; 4],
        };
        let mut labels = [0; M * N];
        let mut t = [Poly([0; N]); M];
        let mut errors = [0; M * N];
        let mut xs = [0; M * N];
        let mut legacy = [0; M * N];
        let head = [0; N + ELL * N];
        let edge = [-Q + 1, -1420, -1292, -1, 0, 1, 1292, 1420, Q - 1];
        for case in 0..256usize {
            for j in 0..M * N {
                labels[j] = ((j + case) % LQ as usize) as i32;
                errors[j] = edge[(j + case) % edge.len()];
                let v = match (j + case) % 4 {
                    0 => 0,
                    1 => Q - 1,
                    _ => ((j * 719 + case * 43) % Q as usize) as i32,
                };
                t[j / N].0[j % N] = v;
                xs[j] = crate::ct::reduce_once(v - errors[j], Q);
                assert_eq!(xs[j], (v - errors[j]).rem_euclid(Q));
            }
            let saved_t = t;
            let saved_e = errors;
            let saved_labels = labels;
            postfilter_fields(&labels, &xs, &mut legacy);
            postfilter_residual_fused(&labels, &t, &errors, &mut out.values);
            assert_eq!(out.values, legacy);
            assert_eq!(t, saved_t);
            assert_eq!(errors, saved_e);
            assert_eq!(labels, saved_labels);
            assert_eq!(out.before, [0x13579; 4]);
            assert_eq!(out.after, [0x24680; 4]);
            for j in 0..M * N {
                assert_eq!(
                    out.values[j],
                    quantize::center_mod_q(quantize::center(labels[j]) - xs[j])
                );
            }
            let a = !check_caps_ct(&head, &legacy);
            let b = !check_caps_ct(&head, &out.values);
            for prior in [0, u64::MAX] {
                assert_eq!(prior | a, prior | b);
            }
        }
    }
}

#[cfg(test)]
mod caller_owned_commitment_tests {
    use super::*;
    #[test]
    // Preserve the explicit borrow boundary used by the signer.
    #[allow(clippy::needless_borrow)]
    fn commitment_destination_stays_in_lease_and_erases_on_unwind() {
        // This binding is consumed only by an alternate selector.
        #[allow(unused_variables)]
        let mut scratch = SigningScratch::new();
        let ptr;
        {
            let mut lease = scratch.lease();
            ptr = lease.commitment.as_ptr();
            for row in &mut lease.commitment {
                row.0.fill(123);
            }
        }
        assert!(scratch.is_erased());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut lease = scratch.lease();
            assert_eq!(ptr, lease.commitment.as_ptr());
            for row in &mut lease.commitment {
                row.0.fill(-321);
            }
            panic!("commitment lease unwind");
        }));
        assert!(result.is_err());
        assert!(scratch.is_erased());
    }
}

/// Transport bound of one attempt: forwards to `transport_queue::bound_batch` with the lower
/// endpoint of the context's lambda.
// Preserve the explicit borrow boundary used by the signer.
#[allow(clippy::needless_borrow)]
pub(crate) fn transport_bound_batch(
    ctx: &Ctx,
    hp: &crate::transport_queue::Prepared,
    slots: &crate::ct_slots::Positions<'_>,
    deferred: &mut crate::ct_deferred::Deferred,
    packed: &crate::ct_gram_registers::Packed,
    abort: u64,
) -> u64 {
    crate::transport_queue::bound_batch(hp, slots, &ctx.theta.lambda.lo, abort, deferred, packed)
}

#[cfg(test)]
#[path = "sign_tests.rs"]
mod sign_tests;

/// High-precision signing from serialized key bytes. The outer guard
/// covers preparation, its returned-value moves, signing and every local drop.
pub fn sign_with_context_and_stats(
    ctx: &Ctx,
    sk: &[u8],
    context: &[u8],
    msg: &[u8],
) -> Result<(Vec<u8>, u32), Error> {
    super::with_signing_guard(|| {
        let prepared = PreparedSk::new(sk)?;
        #[cfg(all(test, target_os = "macos"))]
        crate::timing_state::test_support::checkpoint("sign-prepared-return");
        let mut scratch = SigningScratch::new();
        sign_prepared_with_scratch(ctx, &prepared, &mut scratch, context, msg)
    })
}

/// High-precision signer with caller-owned erased scratch.
// Preserve the explicit borrow boundary used by the signer.
#[allow(clippy::needless_borrow)]
pub fn sign_prepared_with_scratch(
    ctx: &Ctx,
    psk: &PreparedSk,
    scratch: &mut SigningScratch,
    context: &[u8],
    msg: &[u8],
) -> Result<(Vec<u8>, u32), Error> {
    // With the feature `stack-wipe` this frame holds the stack scrub of the signer,
    // under a timing guard of its own so that the scrub completes before the
    // caller's timing state is restored. Without the feature it only calls the
    // signing body, which enters the timing guard itself.
    #[cfg(all(feature = "stack-wipe", target_os = "macos"))]
    let _timing_state = crate::timing_state::Guard::enter()?;
    #[cfg(feature = "stack-wipe")]
    let _stack_scrub = crate::signer_erase::StackScrub::<{ crate::ct_erase::SIGN_SCRUB_WORDS }>;
    sign_prepared_using(ctx, psk, scratch, context, msg, &mut OsEntropy)
}
struct PacketOwner<'a> {
    value: &'a mut [u8],
    keep: bool,
}
impl Drop for PacketOwner<'_> {
    fn drop(&mut self) {
        if !self.keep {
            self.value.zeroize();
        }
    }
}

// With the feature `stack-wipe` the signing body is out of line, so that its
// frame lies below the frame that holds the scrub. Without the feature it
// carries no inlining attribute.
#[cfg_attr(feature = "stack-wipe", inline(never))]
#[allow(unreachable_code)]
// Preserve the explicit borrow boundary used by the signer.
#[allow(clippy::needless_borrow)]
fn sign_prepared_using(
    ctx: &Ctx,
    psk: &PreparedSk,
    scratch: &mut SigningScratch,
    context: &[u8],
    msg: &[u8],
    rng: &mut impl EntropySource,
) -> Result<(Vec<u8>, u32), Error> {
    // Enter the signer timing-state scope before any private-key
    // preparation. The guard restores the prior thread state on every exit.
    #[cfg(target_os = "macos")]
    let _timing_state = crate::timing_state::Guard::enter()?;
    let hp = &psk.secret.transport_prepared;
    let mu = psk.ppk.message_rep(context, msg);
    // Allocate before private candidate work. Accepted output is released
    // without verification.
    let mut signature = Zeroizing::new(vec![0u8; SIGNATURE_BYTES]);
    for retry in 0..MAX_ATTEMPTS {
        let accepted = {
            let (mut buffers, mut lease) = scratch.lease_pair();
            let entropy = random64(rng)?;
            let mut packet = PacketOwner {
                value: &mut signature,
                keep: false,
            };
            let ok = sign_attempt_into(
                ctx,
                &psk.secret.key,
                &psk.ppk,
                &mu,
                hp,
                &mut lease,
                &entropy,
                retry,
                &mut buffers,
                packet.value,
            )?;
            #[cfg(test)]
            let ok = sign_tests::controlled_outcome(retry, ok);
            packet.keep = ok;
            ok
        };
        if accepted {
            #[cfg(test)]
            sign_tests::maybe_corrupt_release(&mut signature);
            return Ok((std::mem::take(&mut *signature), retry + 1));
        }
    }
    Err(Error::SignFailed)
}
#[allow(unreachable_code)]
// Keep the kernel interface and explicit independent inputs.
#[allow(clippy::too_many_arguments)]
// Preserve the explicit borrow boundary used by the signer.
#[allow(clippy::needless_borrow)]
fn sign_attempt_into(
    ctx: &Ctx,
    key: &ParsedSk,
    ppk: &PreparedPk,
    mu: &[u8; 64],
    hp: &crate::transport_queue::Prepared,
    lease: &mut crate::attempt_tape::Lease<'_>,
    entropy: &[u8; 64],
    retry: u32,
    buffers: &mut crate::scratch::Buffers,
    sig_final: &mut [u8],
) -> Result<bool, Error> {
    // These imports are used only by the reference paths.
    #[allow(unused_imports)]
    use crate::ct::{ct_select_i32, ct_select_u64, reduce_once};
    // These imports are used only by the reference paths.
    #[allow(unused_imports)]
    use crate::gauss::Cdt;
    // Every workspace of the attempt lives in the caller's erased scratch: no
    // heap allocation between the entry and the public outcome. `Ok(true)`
    // means the encoded signature is in the caller-owned packet.
    #[allow(unused_variables)]
    // This binding is consumed only by an alternate selector.
    #[allow(unused_variables)]
    let crate::scratch::Buffers {
        labels: u_labels,
        label_bytes: ub,
        xs,
        hints: hs,
        residual: r_e,
        dither_records,
        dither_next,
        slot_records,
        slot_next,
        draws,
        classified,
        sig: _,
        commitment,
    } = buffers;

    let mat = &ppk.mat;
    let mut rho = [0u8; SALT_BYTES];
    let retry_bytes = retry.to_le_bytes();
    let mut salt_stream = Xof::new(
        crate::attempt_tape::DOMAIN,
        &[b"salt", &key.prf, mu, &retry_bytes, entropy],
    );
    salt_stream.fill(&mut rho);
    drop(salt_stream);
    let delta = ppk.static_dither();
    let mut abort = 0u64;
    let mut z_backing = private_z_owner::Backing::zeroed();
    let mut z = private_z_owner::Guard::new(&mut z_backing);
    let pending = lease
        .proposal(
            &key.prf,
            mu,
            retry,
            |seed| {
                seed.copy_from_slice(entropy);
                Ok::<(), core::convert::Infallible>(())
            },
            &mut z,
            &mut abort,
        )
        .unwrap();

    let t = {
        // Proposal support: leading <=168 (the tie path reads an 11-bit table field),
        // secret <=1149, error <=1462; failures are zero.
        mat.apply_noncore_bounded_into(&z, delta, commitment);
        commitment
    };
    // Same reduction and quantization, consumed in one fixed traversal.
    // Preserve corrected t for postfilters and both label owners.
    for (r, tp) in t.iter_mut().enumerate() {
        for i in 0..N {
            let j = r * N + i;
            let e = z[ERR + j];
            debug_assert!(e.unsigned_abs() < Q as u32);
            let v = reduce_once(tp.0[i] + e, Q);
            tp.0[i] = v;
            let label = quantize::q_label(v);
            u_labels[j] = label;
            ub[j] = label as u8;
        }
    }
    let c = challenge::fold(&ppk.challenge_bytes(mu, &rho, ub));
    let mut correlations = crate::correlation::State::empty();
    key.correlations.start_into(&z, &mut correlations);
    {
        let slots = pending.slots(&c, slot_records, slot_next, correlations.row());
        let mut deferred =
            crate::ct_deferred::Deferred::new(correlations.row(), &key.correlations.packed_gram);
        abort = transport_bound_batch(
            ctx,
            hp,
            &slots,
            &mut deferred,
            &key.correlations.packed_gram,
            abort,
        );
        deferred.materialize_challenge(&c, correlations.updates_mut());
    }
    // Exactly 128 unit updates; every coefficient lies in [-128,128].
    key.correlations
        .finish_noncore_bounded(&correlations, &mut z);

    // postfilters
    let z_h = &z[..N + ELL * N];
    let z_e = &z[ERR..];
    postfilter_residual_fused(u_labels, &t, z_e, r_e);
    abort |= !check_caps_ct(z_h, r_e);
    let mut local = Zeroizing::new([0i32; 1280]);
    {
        abort |= !crate::signature_codec::capacity_mask(z_h, u_labels, r_e, &mut local);
    }

    // Both fields are packed directly into the signature buffer
    // (signature_codec::encode_admitted), after the check of the abort mask
    // below. The single abort bit per attempt is the
    // public attempt outcome.
    let sig = &mut sig_final[..SIGNATURE_BYTES];
    sig[..SALT_BYTES].copy_from_slice(&rho);
    {
        let (resp, hint) = sig[SALT_BYTES..].split_at_mut(RESPONSE_BYTES);
        // Every contributor sets the mask to
        // zero or to all ones; any nonzero value rejects the attempt.
        {
            if crate::ct::opaque_mask(abort) != 0 {
                return Ok(false);
            }
            let encoded = {
                crate::signature_codec::encode_admitted(z_h, &local, resp, hint);
                true
            };
            // Core caps imply fixed packing fits. Defensive failure still
            // rejects rather than panicking.
            if !encoded {
                return Ok(false);
            }
        }
    }
    if crate::ct::opaque_mask(abort) != 0 {
        return Ok(false);
    }
    Ok(true)
}

#[cfg(feature = "conformance")]
#[path = "conformance_replay.rs"]
pub mod conformance_replay;

#[cfg(test)]
pub(super) fn keyprep_test_sign(
    ctx: &Ctx,
    psk: &PreparedSk,
    scratch: &mut SigningScratch,
    context: &[u8],
    msg: &[u8],
    rng: &mut impl EntropySource,
) -> Result<(Vec<u8>, u32), Error> {
    #[cfg(feature = "stack-wipe")]
    let _scrub = crate::signer_erase::StackScrub::<{ crate::ct_erase::SIGN_SCRUB_WORDS }>;
    sign_prepared_using(ctx, psk, scratch, context, msg, rng)
}
