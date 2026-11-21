//! Exact integer correlations, not arithmetic in the signature's public ring.
//! Internal contract: canonical ternary shell key; bounded Gaussian mask;
//! at most 128 signed monomial updates. The signer's transform (`aux32_initial.rs`)
//! works modulo 516809729 and states there the condition for exact reconstruction.

use crate::params::{N, PROPOSAL_SHELL_HI as SHELL_HI, PROPOSAL_W0 as W0};
use crate::transport::Vector;

use zeroize::{Zeroize, ZeroizeOnDrop};

type PreparedSpectra<'a> = (
    &'a [crate::compact_ring::CompactPoly; crate::params::ELL + 1],
    &'a [crate::compact_ring::CompactPoly; crate::params::M],
);

pub struct Key {
    initial: crate::aux32_initial::Key,
    gram: [i64; N],
    pub(crate) packed_gram: crate::ct_gram_registers::Packed,
    /// gram2[k] = -gram[k] for k < N, gram[k - N] for k >= N, so that the
    /// rotated update a[j] += sign * gram2[j - i + N] is one contiguous axpy.
    /// |gram[k]| <= E(s) <= SHELL_HI < 2^18 and |a[j]| <= SHELL_DOT_BOUND < 2^31
    /// hold, so i32 lanes cannot overflow.
    gram2: [i32; 2 * N],
    spectra_q: [crate::compact_ring::CompactPoly; 8],
}
impl Drop for Key {
    fn drop(&mut self) {
        self.gram.zeroize();
        self.packed_gram.erase();
        self.gram2.zeroize();
        for p in self.spectra_q.iter_mut() {
            p.zeroize();
        }
        #[cfg(all(
            test,
            any(target_os = "linux", target_os = "macos"),
            target_arch = "aarch64"
        ))]
        crate::timing_state::test_support::observe_erasure("correlation-spectra-erased", || {
            self.spectra_q.iter().all(|p| p.0.iter().all(|&x| x == 0))
        });
    }
}
impl ZeroizeOnDrop for Key {}
impl Key {
    /// Test oracle: G[|k|] with the negacyclic sign, k in 0..=255.
    #[cfg(test)]
    pub(crate) fn gram_entry(&self, k: u64) -> i64 {
        self.gram[k as usize]
    }
    #[cfg(test)]
    pub(crate) fn new(s: &Vector) -> Self {
        Self::build(s, None)
    }
    pub(crate) fn from_prepared_spectra(
        s: &Vector,
        cols: &[crate::compact_ring::CompactPoly; crate::params::ELL + 1],
        errors: &[crate::compact_ring::CompactPoly; crate::params::M],
    ) -> Self {
        Self::build(s, Some((cols, errors)))
    }
    fn build(s: &Vector, supplied: Option<PreparedSpectra<'_>>) -> Self {
        assert_eq!(s[0], 1);
        assert!(s[1..N].iter().all(|&x| x == 0));
        assert!(s[N..].iter().all(|&x| (-1..=1).contains(&x)));
        let energy = crate::transport::energy(s);
        assert!((W0..=SHELL_HI).contains(&energy));
        let mut key = Self {
            initial: crate::aux32_initial::Key::empty(),
            gram: [0; N],
            packed_gram: crate::ct_gram_registers::Packed::empty(),
            gram2: [0; 2 * N],
            spectra_q: [crate::compact_ring::CompactPoly::ZERO; 8],
        };
        // The Key owns every secret lane before it is written. In particular,
        // do not materialize a by-value array of supplied secret spectra here.
        if let Some((cols, errors)) = supplied {
            for (destination, source) in
                key.spectra_q.iter_mut().zip(cols[1..].iter().chain(errors))
            {
                destination.0.copy_from_slice(&source.0);
                #[cfg(all(
                    test,
                    any(target_os = "linux", target_os = "macos"),
                    target_arch = "aarch64"
                ))]
                crate::timing_state::test_support::checkpoint("correlation-spectra-copy");
            }
        } else {
            for (k, spectrum) in key.spectra_q.iter_mut().enumerate() {
                spectrum.forward_from_i32(&s[(k + 1) * N..(k + 2) * N]);
            }
        }
        #[cfg(all(
            test,
            any(target_os = "linux", target_os = "macos"),
            target_arch = "aarch64"
        ))]
        crate::timing_state::test_support::checkpoint("correlation-spectra-ready");
        key.initial.populate_gram(s, &mut key.gram);
        key.gram[0] += W0 as i64;
        assert!(
            key.gram[0] == energy as i64,
            "invalid Gram weighted squared norm"
        );
        for k in 0..N {
            assert!(
                key.gram[k].unsigned_abs() <= SHELL_HI,
                "gram entry exceeds the shell energy"
            );
            key.gram2[k] = -(key.gram[k] as i32);
            key.gram2[k + N] = key.gram[k] as i32;
        }
        {
            key.packed_gram = crate::ct_gram_registers::Packed::new(&key.gram);
        }
        key
    }
    pub(crate) fn start_into(&self, y: &Vector, state: &mut State) {
        state.d.fill(0);
        self.initial.write_initial(y, &mut state.a);
    }
    #[cfg(test)]
    pub(crate) fn start(&self, y: &Vector) -> State {
        let mut state = State {
            a: [0; N],
            d: [0; N],
        };
        self.initial.write_initial(y, &mut state.a);
        state
    }
    pub(crate) fn finish(&self, state: &State, y: &mut Vector) {
        // Lead block: s_0 = 1, so the update is d itself.
        for j in 0..N {
            y[j] += state.d[j];
        }
        // d * s_k over the public ring; exact by the coefficient bound.
        // Exactness needs sum_i |d_i| < q/2 (at most 128 unit updates in the
        // signer; tests may repeat an index, so the bound is on the L1 norm).
        let mut d = zeroize::Zeroizing::new(crate::compact_ring::CompactPoly::ZERO);
        let l1: i64 = state.d.iter().map(|x| x.unsigned_abs() as i64).sum();
        {
            debug_assert!(
                l1 < crate::params::Q as i64 / 2,
                "deferred update too large for exact reconstruction"
            );
            d.forward_from_i32(&state.d);
        }
        #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
        for k in 0..8 {
            crate::neon::private_update_product_add(
                &d,
                &self.spectra_q[k],
                &mut y[(k + 1) * N..(k + 2) * N],
            );
        }
    }
    #[cfg(test)]
    pub(crate) fn finish_fusion_reference(&self, state: &State, y: &mut Vector) {
        // Lead block: s_0 = 1, so the update is d itself.
        for j in 0..N {
            y[j] += state.d[j];
        }
        // d * s_k over the public ring; exact by the coefficient bound.
        // Exactness needs sum_i |d_i| < q/2 (at most 128 unit updates in the
        // signer; tests may repeat an index, so the bound is on the L1 norm).
        let mut d = zeroize::Zeroizing::new(crate::compact_ring::CompactPoly::ZERO);
        let l1: i64 = state.d.iter().map(|x| x.unsigned_abs() as i64).sum();
        {
            debug_assert!(
                l1 < crate::params::Q as i64 / 2,
                "deferred update too large for exact reconstruction"
            );
            d.forward_from_i32(&state.d);
        }
        for k in 0..8 {
            let mut a = zeroize::Zeroizing::new(crate::compact_ring::pointwise_compact(
                &d,
                &self.spectra_q[k],
            ));
            crate::ring::intt(&mut a);
            for j in 0..N {
                let v = a.0[j];
                let centered = v - crate::params::Q * i32::from(v > crate::params::Q / 2);
                debug_assert!(centered.unsigned_abs() as i64 <= l1);
                y[(k + 1) * N + j] += centered;
            }
        }
    }
}
pub struct State {
    a: [i32; N],
    d: [i32; N],
}
impl Drop for State {
    fn drop(&mut self) {
        self.a.zeroize();
        self.d.zeroize();
    }
}
impl ZeroizeOnDrop for State {}
impl State {
    pub(crate) fn empty() -> Self {
        Self {
            a: [0; N],
            d: [0; N],
        }
    }
    pub(crate) fn row(&self) -> &[i32; N] {
        &self.a
    }
    #[cfg(test)]
    pub(crate) fn updates(&self) -> &[i32; N] {
        &self.d
    }
    pub(crate) fn updates_mut(&mut self) -> &mut [i32; N] {
        &mut self.d
    }
    /// The compact slot's index is secret. Scan every dot; never index by it.
    #[inline(never)]
    #[cfg(test)]
    pub(crate) fn dot_oblivious(&self, index: u64) -> i64 {
        let mut value = 0u64;
        for j in 0..N {
            value |= (self.a[j] as u32 as u64)
                & crate::ct::opaque_mask(crate::ct::ct_eq_u64(index, j as u64));
        }
        value as u32 as i32 as i64
    }
    #[inline(never)]
    #[cfg(test)]
    pub(crate) fn update_oblivious(&mut self, key: &Key, index: u64, sign: i32) {
        #[cfg(target_arch = "aarch64")]
        {
            crate::ct_gram_registers::update(
                &key.packed_gram,
                &mut self.a,
                &mut self.d,
                index,
                sign,
            );
        }
    }

    #[cfg(test)]
    pub(crate) fn dot(&self, j: usize) -> i64 {
        self.a[j] as i64
    }
    #[cfg(test)]
    pub(crate) fn update(&mut self, key: &Key, i: usize, sign: i32) {
        // i and loop indices are public schedule indices.
        // Never skip a zero sign: inactive and post-abort slots keep this work.
        self.d[i] += sign;
        // a[j] += sign * gram2[j - i + N]: for j < i this is -sign*gram[j+N-i],
        // for j >= i it is sign*gram[j-i] (one contiguous i32 axpy).
        let row = &key.gram2[N - i..2 * N - i];
        #[cfg(target_arch = "aarch64")]
        // SAFETY: row is the checked N-element slice and self.a has N=256 elements. j advances by
        // four, so each load/store fits; the mutable self borrow excludes row aliasing. The
        // aarch64/neon cfg supplies NEON.
        unsafe {
            use core::arch::aarch64::*;
            let sv = vdupq_n_s32(sign);
            for j in (0..N).step_by(4) {
                let p = self.a.as_mut_ptr().add(j);
                let g = vld1q_s32(row.as_ptr().add(j));
                vst1q_s32(p, vmlaq_s32(vld1q_s32(p), g, sv));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::DIM;
    use crate::{hashes::Xof, transport};
    #[test]
    fn every_oblivious_rotation_matches_fixed_index_updates() {
        let mut rng = Xof::new(b"LILT-OBLIVIOUS-CORRELATION-TEST-v1", &[]);
        let mut s = [0; DIM];
        s[0] = 1;
        for v in &mut s[N..] {
            *v = (rng.u64() % 3) as i32 - 1;
        }
        let mut end = DIM;
        while transport::energy(&s) > SHELL_HI {
            end -= 1;
            s[end] = 0;
        }
        let key = Key::new(&s);
        for index in 0..N {
            for sign in [-1, 0, 1] {
                let a = core::array::from_fn(|_| (rng.u64() % 2000001) as i32 - 1000000);
                let mut expected = State { a, d: [0; N] };
                let mut actual = State { a, d: [0; N] };
                assert_eq!(actual.dot_oblivious(index as u64), expected.dot(index));
                expected.update(&key, index, sign);
                actual.update_oblivious(&key, index as u64, sign);
                assert_eq!(actual.a, expected.a, "index={index} sign={sign}");
                assert_eq!(actual.d, expected.d);
            }
        }
    }
    #[test]
    fn key_size_is_the_sum_of_its_fields() {
        let expected = core::mem::size_of::<crate::aux32_initial::Key>()
            + core::mem::size_of::<[i64; N]>()
            + core::mem::size_of::<crate::ct_gram_registers::Packed>()
            + core::mem::size_of::<[i32; 2 * N]>()
            + core::mem::size_of::<[crate::compact_ring::CompactPoly; 8]>();
        let align = core::mem::align_of::<Key>();
        assert_eq!(
            core::mem::size_of::<Key>(),
            expected.div_ceil(align) * align
        );
    }
    #[test]
    fn every_correlation_and_deferred_update_matches_direct() {
        let mut rng = Xof::new(b"LILT-CORRELATION-TEST-v1", &[b"public fixtures"]);
        for sample in 0..8 {
            let mut s = [0; DIM];
            s[0] = 1;
            if sample != 0 {
                for x in &mut s[N..] {
                    *x = (rng.u64() % 3) as i32 - 1;
                }
            }
            // Drop the final coefficients until the artificial shell is valid.
            let mut end = DIM;
            while transport::energy(&s) > SHELL_HI {
                end -= 1;
                s[end] = 0;
            }
            // The largest values of the sampler's tables. `aux32_initial` recovers the initial
            // sum only while its tail part stays below half of that module's modulus, which
            // these values do not give for every key in the shell. For the keys and the
            // alternating signs of this test the tail part stays below 23 million.
            let y: Vector = core::array::from_fn(|i| {
                let cap = if i < N {
                    154
                } else if i < 5 * N {
                    1064
                } else {
                    1355
                };
                if (i + sample) % 2 == 0 {
                    cap
                } else {
                    -cap
                }
            });
            let key = Key::new(&s);
            let mut state = key.start(&y);
            let mut direct = y;
            for j in 0..N {
                assert_eq!(key.gram[j], transport::dot_rotated(&s, &s, j));
            }
            for step in 0..=128 {
                for j in 0..N {
                    assert_eq!(
                        state.dot(j),
                        transport::dot_rotated(&direct, &s, j),
                        "sample {sample} step {step} j {j}"
                    );
                }
                if step % 16 == 0 {
                    let mut out = y;
                    key.finish(&state, &mut out);
                    assert_eq!(out, direct, "sample {sample} step {step}");
                }
                if step == 128 {
                    break;
                }
                let j = if sample == 1 {
                    255
                } else {
                    (step * 73 + sample) % N
                };
                let sign = if sample == 2 || step > 120 {
                    0
                } else if step % 3 == 0 {
                    -1
                } else {
                    1
                };
                state.update(&key, j, sign);
                transport::add_rotated(&mut direct, &s, j, sign);
            }
        }
    }
}

#[cfg(test)]
mod finish_update_tests {
    use super::*;
    use crate::params::{DIM, Q};
    #[test]
    fn private_fusion_finish_matches_exact_original_at_update_boundaries() {
        let mut cases = 0usize;
        for key_case in 0..4 {
            let mut secret = [0i32; DIM];
            secret[0] = 1;
            if key_case != 0 {
                for i in N..DIM {
                    secret[i] = match key_case {
                        1 => {
                            if i % 5 == 0 {
                                1
                            } else {
                                0
                            }
                        }
                        2 => {
                            if i % 5 == 0 {
                                -1
                            } else {
                                0
                            }
                        }
                        _ => ((i * 17 + 3) % 3) as i32 - 1,
                    };
                }
            }
            let mut end = DIM;
            while crate::transport::energy(&secret) > SHELL_HI {
                end -= 1;
                secret[end] = 0;
            }
            let key = Key::new(&secret);
            for update_case in 0..8 {
                let mut state = State {
                    a: [0; N],
                    d: [0; N],
                };
                match update_case {
                    0 => {}
                    1 => state.d[0] = 1,
                    2 => state.d[255] = -1,
                    3 => state.d[0] = 128,
                    4 => state.d[255] = -128,
                    5 => {
                        for i in 0..128 {
                            state.d[i] = 1;
                        }
                    }
                    6 => {
                        for i in 0..128 {
                            state.d[2 * i] = if i % 2 == 0 { 1 } else { -1 };
                        }
                    }
                    _ => {
                        for i in 0..128 {
                            state.d[(i * 73) % N] = if i % 3 == 0 { -1 } else { 1 };
                        }
                    }
                }
                let before_d = state.d;
                let before_a = state.a;
                for response_case in 0..5 {
                    let input: Vector = core::array::from_fn(|i| match response_case {
                        0 => 0,
                        1 => {
                            if i < N {
                                154
                            } else if i < 5 * N {
                                1064
                            } else {
                                1355
                            }
                        }
                        2 => {
                            if i < N {
                                -154
                            } else if i < 5 * N {
                                -1064
                            } else {
                                -1355
                            }
                        }
                        3 => {
                            if i % 2 == 0 {
                                32767
                            } else {
                                -32767
                            }
                        }
                        _ => (i * 173 % ((2 * Q) as usize)) as i32 - Q,
                    });
                    let mut expected = input;
                    key.finish_fusion_reference(&state, &mut expected);
                    let mut actual = input;
                    key.finish(&state, &mut actual);
                    assert_eq!(
                        actual, expected,
                        "key {key_case}, update {update_case}, response {response_case}"
                    );
                    assert_eq!(state.d, before_d);
                    assert_eq!(state.a, before_a);
                    cases += 1;
                }
            }
        }
        assert_eq!(cases, 160);
    }
}
