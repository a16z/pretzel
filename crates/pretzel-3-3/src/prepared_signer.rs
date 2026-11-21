//! The signer of this crate: signatures of `SIGNATURE_BYTES` bytes.
use super::*;
#[path = "sign_sparse_pack.rs"]
mod sparse_pack;
pub const RESPONSE_BYTES: usize = crate::signature_codec::HEAD_BYTES;
pub const HINT_BYTES: usize = crate::signature_codec::HINT_BYTES;
pub const SIGNATURE_BYTES: usize = 32 + RESPONSE_BYTES + HINT_BYTES;
const _: () = {
    assert!(RESP_FIELD_BYTES == 1174);
    assert!(HINT_FIELD_BYTES == 113);
    assert!(SIG_BYTES == 1319);
};

/// Signs with a prepared secret key and the caller's scratch, using OS entropy.
/// The matching verifier is `verifier::PreparedVerifier`.
pub fn sign_prepared_with_scratch(
    ctx: &Ctx,
    psk: &PreparedSk,
    scratch: &mut SigningScratch,
    context: &[u8],
    msg: &[u8],
) -> Result<(Vec<u8>, u32), Error> {
    sign_prepared_using_scratch(ctx, psk, context, msg, &mut OsEntropy, scratch)
}
/// Default API retains only erased scratch capacity per thread between calls.
/// Keys, entropy and stream state are never cached. Cold/reentrant/TLS-unavailable
/// calls allocate locally; per-attempt erasure and the caller-owned API remain.
pub fn sign_prepared_with_context_and_stats(
    ctx: &Ctx,
    psk: &PreparedSk,
    context: &[u8],
    msg: &[u8],
) -> Result<(Vec<u8>, u32), Error> {
    sign_prepared_cached_using(ctx, psk, context, msg, &mut OsEntropy)
}

// Only erased allocation capacity crosses calls. No key, entropy, transcript,
// stream cursor or signature is cached. Taking ownership ends the TLS borrow
// before signing or allocation. A cold, nested or unavailable-TLS call falls
// back to its own scratch.
std::thread_local! {
    static ERASED_SCRATCH_CACHE: std::cell::RefCell<Option<SigningScratch>> =
        const { std::cell::RefCell::new(None) };
}

fn sign_prepared_cached_using(
    ctx: &Ctx,
    psk: &PreparedSk,
    context: &[u8],
    msg: &[u8],
    rng: &mut impl EntropySource,
) -> Result<(Vec<u8>, u32), Error> {
    let cached = ERASED_SCRATCH_CACHE
        .try_with(|cell| cell.try_borrow_mut().ok().and_then(|mut slot| slot.take()))
        .ok()
        .flatten();
    // Allocate only after the TLS/RefCell access has ended.
    let mut scratch = cached.unwrap_or_else(SigningScratch::new);
    let result = sign_prepared_using_scratch(ctx, psk, context, msg, rng, &mut scratch);
    // Normal Ok and Err paths return an erased owner: every attempt lease is
    // dropped before the signer returns; before its first lease scratch is
    // untouched. PrefixPool residents are ErasedWords. On panic this code is
    // not reached: ordinary local Drop erases/frees scratch, never caches it.
    let mut clean = Some(scratch);
    let _ = ERASED_SCRATCH_CACHE.try_with(|cell| {
        if let Ok(mut slot) = cell.try_borrow_mut() {
            if slot.is_none() {
                *slot = clean.take();
            }
        }
    });
    // Nested calls may have populated the slot; teardown/borrow access may
    // fail. Destruction of our unused owner is always outside the TLS borrow.
    drop(clean);
    result
}

// The const REFERENCE_PACK oracle is instantiated true only by unit tests.
// REFERENCE_PACK dispatch is compiled out entirely in production.

// The only caller of the retry loop outside unit tests. Without the Cargo
// feature `stack-wipe` it only calls the retry loop, which enters the timing
// guard itself.
//
// With the feature it is the frame that holds the stack scrub. The retry loop
// is then out of line, so its frame, the frame of each attempt and the frames of
// their callees lie below this one, inside the extent that the scrub zeroes.
// Locals are dropped in reverse order of declaration: the scrub runs after the
// signing body has returned or unwound, and the timing guard declared before it
// is restored only after the scrub. When the guard cannot be entered the
// function returns before any private work and without a scrub. Not erased:
// registers, this frame, the frames of its callers and anything deeper than the
// extent.
pub(super) fn sign_prepared_using_scratch(
    ctx: &Ctx,
    psk: &PreparedSk,
    context: &[u8],
    msg: &[u8],
    rng: &mut impl EntropySource,
    scratch: &mut SigningScratch,
) -> Result<(Vec<u8>, u32), Error> {
    #[cfg(feature = "stack-wipe")]
    let _timing_state = crate::timing_state::Guard::enter()?;
    #[cfg(feature = "stack-wipe")]
    let _stack_scrub = crate::ct_erase::StackScrub::<{ crate::ct_erase::SIGN_SCRUB_WORDS }>;
    sign_with_policy::<false>(ctx, psk, context, msg, rng, scratch)
}

// With the feature `stack-wipe`, out of line in every instantiation: an inlined
// copy would put this frame inside the frame that holds the scrub, where it is
// not erased. Without the feature it carries no inlining attribute.
#[cfg_attr(feature = "stack-wipe", inline(never))]
fn sign_with_policy<const REFERENCE_PACK: bool>(
    ctx: &Ctx,
    psk: &PreparedSk,
    context: &[u8],
    msg: &[u8],
    rng: &mut impl EntropySource,
    scratch: &mut SigningScratch,
) -> Result<(Vec<u8>, u32), Error> {
    // Own the calling thread's timing state before loading prepared secrets.
    // Drop restores it on return, entropy failure, exhaustion and unwinding.
    let _timing_state = crate::timing_state::Guard::enter()?;
    let key = &psk.secret.key;
    let mu = stage!(12, psk.ppk.message_rep(context, msg));
    // The returned signature is the only heap object of the constant-time
    // path; it is allocated once here, before the first attempt, and filled
    // from the erased staging buffer after the public abort decision.
    let mut signature = Zeroizing::new(vec![0u8; SIGNATURE_BYTES]);
    for attempt in 0u32..MAX_ATTEMPTS {
        let sig = {
            // Lease exists before entropy acquisition. All exits, including an
            // entropy-source panic, erase its full initialized extent. Dropped
            // before the next attempt.
            let mut buffers = scratch.lease();
            let entropy = stage!(0, random32(rng)?);
            let sig = {
                let (buffers, pool) = buffers.with_pool();
                let mut randomness = stage!(
                    13,
                    AttemptRandomness::from_prefixes_pooled(
                        &psk.secret.prefixes,
                        &mu,
                        attempt,
                        &entropy,
                        pool
                    )
                );
                let accepted = sign_attempt::<REFERENCE_PACK>(
                    ctx,
                    key,
                    &psk.ppk,
                    &mu,
                    &mut randomness,
                    buffers,
                );
                // Erase the tape prefixes and hand their storage back to the pool
                // before the streams are dropped (no free per attempt).
                randomness.recycle(pool);
                drop(randomness);
                if accepted? {
                    signature.copy_from_slice(&buffers.sig[..SIGNATURE_BYTES]);
                    Some(std::mem::take(&mut *signature))
                } else {
                    None
                }
            };
            sig
        };
        if let Some(sig) = sig {
            return Ok((sig, attempt + 1));
        }
    }
    Err(Error::SignFailed)
}

// Two-pass reference of `postfilter_residual_fused`, compiled for tests only.
// The signature has no hint values: the residual cap implies that every
// reconstructed hint has magnitude at most 2 (test
// `exhaustive_residual_implies_discarded_hint_bound`).
#[cfg(test)]
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
fn postfilter_residual_fused(
    u_labels: &[i32; M * N],
    t: &[Poly; M],
    z_e: &[i32],
    r_e: &mut [i32; M * N],
) {
    for r in 0..M {
        for i in 0..N {
            let j = r * N + i;
            let e = z_e[j];
            debug_assert!(e.unsigned_abs() < Q as u32);
            let x = crate::ct::reduce_once(t[r].0[i] - e, Q);
            let difference = quantize::center(u_labels[j]) - x;
            let residue = difference + Q * i32::from(difference < 0);
            r_e[j] = residue - Q * i32::from(residue > Q / 2);
        }
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
        assert!(DIM == 1792);
        assert!(core::mem::size_of::<Backing>() == DIM * 4);
        assert!(core::mem::align_of::<Backing>() >= 8);
        assert!(core::mem::size_of::<Backing>() % 8 == 0);
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
        pub(super) fn new(backing: &'a mut Backing) -> Self {
            Self { backing }
        }
    }
    impl Deref for Guard<'_> {
        type Target = [i32; DIM];
        fn deref(&self) -> &Self::Target {
            &self.backing.0
        }
    }
    impl DerefMut for Guard<'_> {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.backing.0
        }
    }
    impl Drop for Guard<'_> {
        fn drop(&mut self) {
            // SAFETY: Backing is initialized, has exactly DIM*4 bytes without
            // padding, is at least eight-byte aligned, and is exclusively
            // borrowed through this guard. No references escape that borrow.
            // The helper only writes zero over the full extent (896 words),
            // never interprets private coefficients, and retains its fences.
            unsafe {
                crate::ct_erase::erase_struct_words(
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
        fn normal_rejection_and_error_retire_same_extent() {
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

#[inline(never)]
fn sign_attempt<const REFERENCE_PACK: bool>(
    ctx: &Ctx,
    key: &ParsedSk,
    ppk: &PreparedPk,
    mu: &[u8; 64],
    randomness: &mut AttemptRandomness,
    buffers: &mut crate::scratch::Buffers,
) -> Result<bool, Error> {
    #[cfg(test)]
    use crate::ct::ct_select_i32;
    use crate::ct::reduce_once;
    // Every workspace of the attempt lives in the caller's erased scratch: no
    // heap allocation between the entry and the public outcome.
    // `Ok(true)` means the encoded signature is in `buffers.sig`.
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
        sig,
        commitment,
    } = buffers;

    let mat = &ppk.mat;
    let rho = randomness.rho;

    let delta = ppk.static_dither();

    let mut abort = 0u64; // later private-sampler/transport failures still accumulate
    let mut z_backing = private_z_owner::Backing::zeroed();
    let mut z = private_z_owner::Guard::new(&mut z_backing);
    stage!(2, {
        // One stream at a time through the same two workspaces (`dither_records` and
        // `dither_next`), erased with the lease.
        {
            // Dither outputs are owned values; its workspaces are now free.
            abort |= ctx.cdt_lead.sample_rare_into(
                &mut randomness.lead,
                &mut z[..SEC],
                dither_records,
                dither_next,
            );
            abort |= ctx.cdt_sec.sample_rare_into(
                &mut randomness.secret,
                &mut z[SEC..ERR],
                dither_records,
                dither_next,
            );
            abort |= ctx.cdt_err.sample_rare_into(
                &mut randomness.error,
                &mut z[ERR..],
                dither_records,
                dither_next,
            );
        }
    });

    let t = {
        stage!(3, mat.apply_into(&z, delta, commitment));
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
    let c = stage!(4, challenge::fold(&ppk.challenge_bytes(mu, &rho, ub)));
    let mut correlations = crate::correlation::State::empty();
    stage!(18, key.correlations.start_into(&z, &mut correlations));
    #[cfg(test)]
    let mut direct = Zeroizing::new(*z);
    stage!(5, {
        let slots = crate::ct_slots::Positions::new_with_base(
            &c,
            &mut randomness.transport,
            slot_records,
            slot_next,
            correlations.row(),
        );
        let mut deferred = crate::ct_deferred::Deferred::new(&key.correlations.packed_gram);
        let mut interval_x = Zeroizing::new([0i64; 128]);
        let mut interval_checks = crate::ct_interval_transport::DeferredChecks::new();
        {
            abort |= 0u64.wrapping_sub(crate::ct_interval_transport::prepare(
                &slots,
                &mut interval_x,
            ));
        }
        #[cfg(test)]
        let (native_abort, native_deferred, native_checks) = {
            let mut d = crate::ct_deferred::Deferred::new(&key.correlations.packed_gram);
            let mut checks = crate::ct_interval_transport::DeferredChecks::new();
            let a = key.interval.batch(
                &slots,
                &interval_x,
                &ctx.theta.lambda.lo,
                abort,
                &mut d,
                &mut checks,
                &key.correlations.packed_gram,
            );
            (a, d, checks)
        };
        #[cfg(not(test))]
        {
            abort = key.interval.batch(
                &slots,
                &interval_x,
                &ctx.theta.lambda.lo,
                abort,
                &mut deferred,
                &mut interval_checks,
                &key.correlations.packed_gram,
            );
        }
        #[cfg(test)]
        for slot in 0..72 {
            let (j, active, u) = slots.get(slot);
            let a = deferred.dot_with_base(&key.correlations.packed_gram, j, slots.base_word(slot));
            #[cfg(test)]
            assert_eq!(a, transport::dot_rotated(&direct, &key.s_flat, j as usize));
            let (minus, plus, other) = {
                key.interval
                    .decide_deferred(a, interval_x[slot], &u, active, &mut interval_checks)
            };
            abort |= other & active;
            {
                // Exactly one role uses this coin: real for the active prefix,
                // dummy for its complement. All 72 comparisons are executed.
                let dummy_fail = !crate::ct::ct_lt_fx(&u, &ctx.theta.lambda.lo);
                abort |= dummy_fail & !crate::ct::opaque_mask(active);
            }
            let mut sign = ct_select_i32(minus, -1, 0);
            sign = ct_select_i32(plus, 1, sign);
            sign = ct_select_i32(abort, 0, sign);
            sign = ct_select_i32(active, sign, 0);
            deferred.record(slot, j, sign);
            #[cfg(test)]
            transport::add_rotated(&mut direct, &key.s_flat, j as usize, sign);
        }
        #[cfg(test)]
        {
            assert_eq!(abort, native_abort, "native batch abort");
            assert_eq!(deferred.idx, native_deferred.idx, "native batch indices");
            assert_eq!(deferred.sgn8, native_deferred.sgn8, "native batch signs");
            assert_eq!(
                deferred.recorded, native_deferred.recorded,
                "native batch public count"
            );
            assert_eq!(
                interval_checks, native_checks,
                "native batch full deferred queue"
            );
        }
        {
            abort |= key.interval.finish(&interval_checks);
            abort = crate::ct::opaque_mask(abort);
        }
        deferred.materialize_updates(correlations.updates_mut());
    });

    key.correlations.finish(&correlations, &mut z);
    #[cfg(test)]
    assert_eq!(*z, *direct);

    // postfilters
    let z_h = &z[..N + ELL * N];
    let z_e = &z[ERR..];
    postfilter_residual_fused(u_labels, t, z_e, r_e);
    abort |= !stage!(8, check_caps_ct(z_h, r_e));
    let mut local = Zeroizing::new([0i32; 768]);
    {
        abort |= !crate::signature_codec::capacity_mask(z_h, u_labels, r_e, &mut local);
    }

    // Serialization of both fields directly into the signature buffer. The single abort bit per
    // attempt is the public attempt outcome and the release boundary: the test on it
    // below returns before any packing. Past that test the attempt is released, and
    // `sparse_pack::encode` does work that depends on the values it packs. The packer has no
    // failure return; `signature_codec::capacity_mask` above folds the bounds of both exception
    // lists (16 and `EXCEPTIONS` entries) into the abort mask.
    let sig = &mut sig[..SIGNATURE_BYTES];
    sig[..SALT_BYTES].copy_from_slice(&rho);
    {
        let (resp, hint) = sig[SALT_BYTES..].split_at_mut(RESPONSE_BYTES);
        {
            // Any nonzero mask aborts the attempt.
            if crate::ct::opaque_mask(abort) != 0 {
                return Ok(false);
            }
            #[cfg(test)]
            if REFERENCE_PACK {
                sparse_pack::encode_reference(z_h, &local, resp, hint);
            } else {
                sparse_pack::encode(z_h, &local, resp, hint);
            }
            #[cfg(not(test))]
            sparse_pack::encode(z_h, &local, resp, hint);
        }
    }
    // The abort test is repeated before the attempt is reported as accepted.
    if crate::ct::opaque_mask(abort) != 0 {
        return Ok(false);
    }
    Ok(true)
}

#[cfg(test)]
mod signer_tests {
    use super::*;
    struct Tape {
        x: Xof,
        calls: usize,
    }
    impl Tape {
        fn new(seed: &[u8]) -> Self {
            Self {
                x: Xof::new(b"PHASE909-FIXED-TEST-TAPE", &[seed]),
                calls: 0,
            }
        }
    }
    impl EntropySource for Tape {
        fn fill(&mut self, out: &mut [u8]) -> Result<(), crate::EntropyError> {
            self.calls += 1;
            self.x.fill(out);
            Ok(())
        }
    }
    #[test]
    fn retained_abort_and_codec_only_gate_truth_table() {
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
    #[test]
    fn direct_four_signer_owner_extent_and_entropy_exits() {
        assert_eq!(crate::scratch::SIG_PAD, 3104);
        // Pinned static layout: 1034 u32 records include the vector
        // tail/rank slots. Relative to 1024 records this adds exactly 40 bytes.
        // The local private-z owner is outside Buffers and changes no field.
        assert_eq!(crate::scratch::RECORD_WORDS, 1034);
        assert_eq!(core::mem::size_of::<crate::scratch::Buffers>(), 42568);
        let ctx = Ctx::new();
        let kp = keygen_with_entropy(&ctx, &mut Tape::new(b"cleanup-key")).unwrap();
        let sk = PreparedSk::new(&kp.sk).unwrap();
        let mut scratch = SigningScratch::new();
        struct Fail;
        impl EntropySource for Fail {
            fn fill(&mut self, _: &mut [u8]) -> Result<(), crate::EntropyError> {
                Err(crate::EntropyError)
            }
        }
        scratch.poison();
        assert!(sign_prepared_using_scratch(&ctx, &sk, b"", b"", &mut Fail, &mut scratch).is_err());
        assert!(scratch.is_erased());
        struct Panic;
        impl EntropySource for Panic {
            fn fill(&mut self, _: &mut [u8]) -> Result<(), crate::EntropyError> {
                panic!("phase909 entropy fixture")
            }
        }
        scratch.poison();
        let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = sign_prepared_using_scratch(&ctx, &sk, b"", b"", &mut Panic, &mut scratch);
        }));
        assert!(failed.is_err());
        assert!(scratch.is_erased());
        // The stack scrub, seen through its completion event. Every call below is a call of
        // `sign_prepared_using_scratch`, the function that holds the scrub when the crate
        // has the Cargo feature `stack-wipe`, made with the timing flag clear and set at entry.
        // The key was prepared above, outside the recording, and nothing else on this path
        // records an event. With the feature the scrub's event is therefore required to be the
        // only one: observed once, with the timing flag set. Without the feature no stack range
        // is wiped and no event at all may be observed.
        use crate::timing_state::test_support::record;
        let scrubbed_once: &[(&str, bool)] = if cfg!(feature = "stack-wipe") {
            &[("stack-scrub", true)]
        } else {
            &[]
        };
        for set_at_entry in [false, true] {
            // A signature is returned.
            let run = record(set_at_entry, 0, || {
                let mut tape = Tape::new(b"cleanup-sign");
                sign_prepared_using_scratch(&ctx, &sk, b"", b"", &mut tape, &mut scratch)
            });
            assert!(run.value.unwrap().is_ok());
            assert_eq!(run.events, scrubbed_once);
            assert!(run.restored);
            // The entropy source returns an error inside the first attempt.
            scratch.poison();
            let run = record(set_at_entry, 0, || {
                sign_prepared_using_scratch(&ctx, &sk, b"", b"", &mut Fail, &mut scratch)
            });
            assert_eq!(run.value.unwrap(), Err(Error::RngFailure));
            assert_eq!(run.events, scrubbed_once);
            assert!(run.restored);
            assert!(scratch.is_erased());
            // The entropy source panics inside the first attempt and the signer unwinds.
            scratch.poison();
            let run = record(set_at_entry, 0, || {
                sign_prepared_using_scratch(&ctx, &sk, b"", b"", &mut Panic, &mut scratch)
            });
            assert!(run.value.is_err());
            assert_eq!(run.events, scrubbed_once);
            assert!(run.restored);
            assert!(scratch.is_erased());
        }
        // The timing guard cannot be entered, in either of the two injected ways: the function
        // returns before any scrub is declared, in both configurations, so no event is observed,
        // no entropy is drawn (the source would panic) and the scratch is not touched.
        for (set_at_entry, guard_failure) in [(false, 1), (false, 2), (true, 1), (true, 2)] {
            scratch.poison();
            let run = record(set_at_entry, guard_failure, || {
                sign_prepared_using_scratch(&ctx, &sk, b"", b"", &mut Panic, &mut scratch)
            });
            assert_eq!(run.value.unwrap(), Err(Error::TimingProtectionUnavailable));
            assert!(run.events.is_empty(), "{:?}", run.events);
            assert!(run.restored);
            assert!(!scratch.is_erased());
        }
    }
}

#[cfg(test)]
mod discarded_hint_tests {
    use super::*;
    #[test]
    fn exhaustive_residual_implies_discarded_hint_bound() {
        let mut accepted = 0;
        let mut maximum = 0;
        for x in 0..Q {
            for u in 0..LQ {
                let r = quantize::center_mod_q(quantize::center(u) - x);
                let d = (u - quantize::q_label(x)).rem_euclid(LQ);
                let h = d - LQ * i32::from(d > LQ / 2);
                if r.unsigned_abs() <= CAP_INF_RES as u32 {
                    assert!(h.abs() <= 2);
                    assert!(h.abs() <= HINT_MAX);
                    accepted += 1;
                    maximum = maximum.max(h.abs());
                }
            }
        }
        assert_eq!((accepted, maximum), (30702, 2));
    }
}

#[cfg(test)]
mod fused_residual_tests {
    use super::*;
    #[test]
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
        let edge = [-Q + 1, -1483, -1355, -1, 0, 1, 1355, 1483, Q - 1];
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
mod erased_default_cache_tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    struct Tape {
        x: Xof,
        calls: usize,
    }
    impl Tape {
        fn new(seed: &[u8]) -> Self {
            Self {
                x: Xof::new(b"ERASED-DEFAULT-CACHE-TEST", &[seed]),
                calls: 0,
            }
        }
    }
    impl EntropySource for Tape {
        fn fill(&mut self, out: &mut [u8]) -> Result<(), crate::EntropyError> {
            self.calls += 1;
            self.x.fill(out);
            Ok(())
        }
    }
    struct Fail;
    impl EntropySource for Fail {
        fn fill(&mut self, _: &mut [u8]) -> Result<(), crate::EntropyError> {
            Err(crate::EntropyError)
        }
    }
    struct Panic;
    impl EntropySource for Panic {
        fn fill(&mut self, _: &mut [u8]) -> Result<(), crate::EntropyError> {
            panic!("cache entropy panic")
        }
    }
    fn key(ctx: &Ctx, seed: &[u8]) -> PreparedSk {
        let kp = keygen_with_entropy(ctx, &mut Tape::new(seed)).unwrap();
        PreparedSk::new(&kp.sk).unwrap()
    }
    fn clear() {
        let old = ERASED_SCRATCH_CACHE.with(|cell| cell.borrow_mut().take());
        drop(old);
    }
    fn cached_address() -> Option<usize> {
        ERASED_SCRATCH_CACHE.with(|cell| {
            let mut slot = cell.borrow_mut();
            slot.as_mut().map(|s| {
                assert!(s.is_erased());
                let lease = s.lease();
                (&*lease as *const crate::scratch::Buffers) as usize
            })
        })
    }
    fn compare(ctx: &Ctx, sk: &PreparedSk, context: &[u8], msg: &[u8], seed: &[u8]) {
        let (mut a, mut b) = (Tape::new(seed), Tape::new(seed));
        let mut explicit = SigningScratch::new();
        let expected = sign_prepared_using_scratch(ctx, sk, context, msg, &mut a, &mut explicit);
        let actual = sign_prepared_cached_using(ctx, sk, context, msg, &mut b);
        assert_eq!(actual, expected);
        assert!(actual.is_ok());
        assert_eq!(a.calls, b.calls);
        let (mut aa, mut bb) = ([0; 64], [0; 64]);
        a.x.fill(&mut aa);
        b.x.fill(&mut bb);
        assert_eq!(aa, bb);
        assert!(explicit.is_erased());
        assert!(cached_address().is_some());
    }
    #[test]
    fn cold_warm_keys_messages_match_explicit_tape_and_continuation() {
        clear();
        assert_eq!(cached_address(), None);
        let ctx = Ctx::new();
        let keys = [key(&ctx, b"a"), key(&ctx, b"b")];
        let mut address = None;
        for i in 0..8usize {
            let msg = vec![i as u8; [0, 32, 136, 1024][i % 4]];
            let context = if i % 2 == 0 {
                &b""[..]
            } else {
                &b"cache-context"[..]
            };
            compare(&ctx, &keys[i % 2], context, &msg, &[i as u8]);
            let now = cached_address();
            if let Some(a) = address {
                assert_eq!(now, Some(a));
            } else {
                address = now;
            }
        }
        clear();
    }
    #[test]
    fn normal_error_retains_clean_owner_panic_drops_then_reuse_succeeds() {
        clear();
        let ctx = Ctx::new();
        let sk = key(&ctx, b"exits");
        assert_eq!(
            sign_prepared_cached_using(&ctx, &sk, b"", b"", &mut Fail),
            Err(Error::RngFailure)
        );
        let address = cached_address().unwrap();
        assert_eq!(
            sign_prepared_cached_using(&ctx, &sk, b"", b"", &mut Fail),
            Err(Error::RngFailure)
        );
        assert_eq!(cached_address(), Some(address));
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = sign_prepared_cached_using(&ctx, &sk, b"", b"", &mut Panic);
        }));
        assert!(panic.is_err());
        assert_eq!(cached_address(), None);
        compare(&ctx, &sk, b"", b"after-panic", b"after-panic");
        clear();
    }
    #[test]
    fn nested_entropy_call_fills_slot_without_overwriting_inner_owner() {
        clear();
        let ctx = Ctx::new();
        let sk = key(&ctx, b"nested");
        struct Nested<'a> {
            ctx: &'a Ctx,
            sk: &'a PreparedSk,
            tape: Tape,
            inner: Option<usize>,
        }
        impl EntropySource for Nested<'_> {
            fn fill(&mut self, out: &mut [u8]) -> Result<(), crate::EntropyError> {
                if self.inner.is_none() {
                    assert_eq!(cached_address(), None);
                    assert_eq!(
                        sign_prepared_cached_using(
                            self.ctx,
                            self.sk,
                            b"",
                            b"nested-inner",
                            &mut Fail
                        ),
                        Err(Error::RngFailure)
                    );
                    self.inner = cached_address();
                    assert!(self.inner.is_some());
                }
                self.tape.fill(out)
            }
        }
        let mut nested = Nested {
            ctx: &ctx,
            sk: &sk,
            tape: Tape::new(b"outer"),
            inner: None,
        };
        let mut tape = Tape::new(b"outer");
        let mut explicit = SigningScratch::new();
        let expected =
            sign_prepared_using_scratch(&ctx, &sk, b"", b"outer", &mut tape, &mut explicit);
        let actual = sign_prepared_cached_using(&ctx, &sk, b"", b"outer", &mut nested);
        assert_eq!(actual, expected);
        assert!(actual.is_ok());
        assert_eq!(cached_address(), nested.inner);
        assert_eq!(tape.calls, nested.tape.calls);
        let (mut a, mut b) = ([0; 64], [0; 64]);
        tape.x.fill(&mut a);
        nested.tape.x.fill(&mut b);
        assert_eq!(a, b);
        clear();
    }
    #[test]
    fn unavailable_borrow_uses_local_fallback_and_preserves_slot() {
        clear();
        let ctx = Ctx::new();
        let sk = key(&ctx, b"borrow");
        assert_eq!(
            sign_prepared_cached_using(&ctx, &sk, b"", b"", &mut Fail),
            Err(Error::RngFailure)
        );
        let address = cached_address();
        ERASED_SCRATCH_CACHE.with(|cell| {
            let slot = cell.borrow_mut();
            assert_eq!(
                sign_prepared_cached_using(&ctx, &sk, b"", b"", &mut Fail),
                Err(Error::RngFailure)
            );
            assert!(slot.as_ref().unwrap().is_erased());
        });
        assert_eq!(cached_address(), address);
        compare(&ctx, &sk, b"", b"after-borrow", b"after-borrow");
        clear();
    }
    #[test]
    fn live_threads_keep_distinct_clean_owners() {
        clear();
        let gate = Arc::new(Barrier::new(3));
        let (tx, rx) = std::sync::mpsc::channel();
        let mut threads = Vec::new();
        for i in 0..2u8 {
            let gate = gate.clone();
            let tx = tx.clone();
            threads.push(std::thread::spawn(move || {
                assert_eq!(cached_address(), None);
                let ctx = Ctx::new();
                let sk = key(&ctx, &[i]);
                assert_eq!(
                    sign_prepared_cached_using(&ctx, &sk, b"", b"", &mut Fail),
                    Err(Error::RngFailure)
                );
                tx.send(cached_address().unwrap()).unwrap();
                gate.wait();
                assert!(cached_address().is_some());
            }));
        }
        let a = rx.recv().unwrap();
        let b = rx.recv().unwrap();
        assert_ne!(a, b);
        assert_eq!(cached_address(), None);
        gate.wait();
        for thread in threads {
            thread.join().unwrap();
        }
    }
}

#[cfg(test)]
std::thread_local! { pub(super) static COMMITMENT_RETURN_ORACLE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
#[cfg(test)]
mod caller_owned_commitment_tests {
    use super::*;
    struct Tape {
        x: Xof,
        calls: usize,
    }
    impl Tape {
        fn new(seed: &[u8]) -> Self {
            Self {
                x: Xof::new(b"CALLER-OWNED-COMMITMENT-TEST", &[seed]),
                calls: 0,
            }
        }
    }
    impl EntropySource for Tape {
        fn fill(&mut self, out: &mut [u8]) -> Result<(), crate::EntropyError> {
            self.calls += 1;
            self.x.fill(out);
            Ok(())
        }
    }
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            COMMITMENT_RETURN_ORACLE.with(|v| v.set(false));
        }
    }
    fn compare(ctx: &Ctx, sk: &PreparedSk, seed: &[u8]) {
        let (mut a, mut b) = (Tape::new(seed), Tape::new(seed));
        let (mut sa, mut sb) = (SigningScratch::new(), SigningScratch::new());
        let _reset = Reset;
        COMMITMENT_RETURN_ORACLE.with(|v| v.set(true));
        let old = sign_with_policy::<false>(ctx, sk, b"ctx", seed, &mut a, &mut sa);
        COMMITMENT_RETURN_ORACLE.with(|v| v.set(false));
        let new = sign_with_policy::<false>(ctx, sk, b"ctx", seed, &mut b, &mut sb);
        assert_eq!(old, new);
        assert!(new.is_ok());
        assert_eq!(a.calls, b.calls);
        let (mut x, mut y) = ([0; 64], [0; 64]);
        a.x.fill(&mut x);
        b.x.fill(&mut y);
        assert_eq!(x, y);
        assert!(sa.is_erased());
        assert!(sb.is_erased());
    }
    #[test]
    fn complete_signatures_retry_counts_and_entropy_suffix_match_return_oracle() {
        let ctx = Ctx::new();
        let kp = keygen_with_entropy(&ctx, &mut Tape::new(b"key")).unwrap();
        let sk = PreparedSk::new(&kp.sk).unwrap();
        for i in 0..8u64 {
            compare(&ctx, &sk, &i.to_le_bytes());
        }
    }
    #[test]
    fn commitment_destination_stays_in_lease_and_erases_on_unwind() {
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

// Public-fixture replay is absent from production builds.
#[cfg(feature = "conformance")]
include!("../conformance/known_answer_replay.rs");
