//! Exact integer correlations, not arithmetic in the signature's public ring.
//! Internal contract: canonical ternary shell key; bounded Gaussian mask;
//! at most 128 signed monomial updates. The signer's transform (`aux32_initial.rs`) works
//! modulo 516809729 and states its condition for unique centered reconstruction there.
use crate::params::{ELL, M, N, PROPOSAL_SHELL_HI as SHELL_HI, PROPOSAL_W0 as W0};
use crate::transport::Vector;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub struct Key {
    initial: crate::aux32_initial::Key,
    /// The secret vector, kept in test builds for the direct statement of the correlations.
    #[cfg(test)]
    secret: Vector,
    gram: [i64; N],
    pub(crate) packed_gram: crate::ct_gram_registers::Packed,
    spectra_q: [crate::compact_ring::CompactPoly; ELL + M],
}
impl Drop for Key {
    fn drop(&mut self) {
        #[cfg(test)]
        self.secret.zeroize();
        self.gram.zeroize();
        self.packed_gram.erase();
        for p in self.spectra_q.iter_mut() {
            p.zeroize();
        }
    }
}
impl ZeroizeOnDrop for Key {}
impl Key {
    /// Test oracle: G[|k|] with the negacyclic sign, k in 0..=255.
    #[cfg(test)]
    pub(crate) fn gram_entry(&self, k: u64) -> i64 {
        self.gram[k as usize]
    }
    pub(crate) fn new(s: &Vector) -> Self {
        assert_eq!(s[0], 1);
        assert!(s[1..N].iter().all(|&x| x == 0));
        assert!(s[N..].iter().all(|&x| (-1..=1).contains(&x)));
        let energy = crate::transport::energy(s);
        assert!((W0..=SHELL_HI).contains(&energy));
        let mut key = Self {
            initial: crate::aux32_initial::Key::empty(),
            #[cfg(test)]
            secret: *s,
            gram: [0; N],
            packed_gram: crate::ct_gram_registers::Packed::empty(),
            spectra_q: [crate::compact_ring::CompactPoly::ZERO; ELL + M],
        };
        // Populate the private spectra directly within the Key owner.
        for k in 0..ELL + M {
            key.spectra_q[k].forward_from_i32(&s[(k + 1) * N..(k + 2) * N]);
        }
        key.initial.populate_gram(s, &mut key.gram);
        key.gram[0] += W0 as i64;
        #[cfg(test)]
        {
            for j in 0..N {
                assert!(
                    key.gram[j] == crate::transport::dot_rotated(s, s, j),
                    "Gram differs from the direct rotated product"
                );
            }
        }
        assert!(
            key.gram[0] == energy as i64,
            "invalid Gram weighted squared norm"
        );
        for k in 0..N {
            assert!(
                key.gram[k].unsigned_abs() <= SHELL_HI,
                "gram entry exceeds the shell energy"
            );
        }
        {
            key.packed_gram = crate::ct_gram_registers::Packed::new(&key.gram);
        }
        key
    }
    pub(crate) fn start_into(&self, y: &Vector, state: &mut State) {
        state.d.fill(0);
        self.initial.write_initial(y, &mut state.a);
        #[cfg(test)]
        {
            let mut original = State {
                a: [0; N],
                d: [0; N],
            };
            self.write_reference_into(y, &mut original);
            assert_eq!(state.a, original.a);
        }
    }
    #[cfg(test)]
    pub(crate) fn start(&self, y: &Vector) -> State {
        let mut state = State {
            a: [0; N],
            d: [0; N],
        };
        self.initial.write_initial(y, &mut state.a);
        #[cfg(test)]
        {
            let mut original = State {
                a: [0; N],
                d: [0; N],
            };
            self.write_reference_into(y, &mut original);
            assert_eq!(state.a, original.a);
        }
        state
    }
    /// Test statement of the initial row: the weighted product with every rotation of the secret.
    #[cfg(test)]
    fn write_reference_into(&self, y: &Vector, state: &mut State) {
        for j in 0..N {
            let v = crate::transport::dot_rotated(y, &self.secret, j);
            debug_assert!(v.unsigned_abs() <= crate::params::SHELL_DOT_BOUND);
            state.a[j] = v as i32;
        }
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
        for k in 0..ELL + M {
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
        for k in 0..ELL + M {
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
    #[cfg(test)]
    #[inline(never)]
    pub(crate) fn dot_oblivious(&self, index: u64) -> i64 {
        let mut value = 0u64;
        for j in 0..N {
            value |= (self.a[j] as u32 as u64)
                & crate::ct::opaque_mask(crate::ct::ct_eq_u64(index, j as u64));
        }
        value as u32 as i32 as i64
    }
    #[cfg(test)]
    #[inline(never)]
    pub(crate) fn update_oblivious(&mut self, key: &Key, index: u64, sign: i32) {
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
        // a[j] += sign * G[j - i] with the negacyclic sign: for j < i this is
        // -sign*gram[j+N-i], for j >= i it is sign*gram[j-i]. |gram[k]| <= SHELL_HI < 2^18,
        // so the entry fits an i32; the arithmetic wraps as the i32 lanes of the signer do.
        for j in 0..N {
            let g = if j >= i {
                key.gram[j - i]
            } else {
                -key.gram[j + N - i]
            };
            self.a[j] = self.a[j].wrapping_add(sign.wrapping_mul(g as i32));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{DIM, WE, WS};
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
    // Independent integer oracle: no transport helpers. Every tail block carries nonzero data.
    #[test]
    fn dimension_complete_integer_oracle() {
        let mut s = [0i32; DIM];
        s[0] = 1;
        for block in 1..=ELL + M {
            s[block * N] = 1;
            s[block * N + N - 1] = -1;
            s[block * N + (17 * block) % (N - 2) + 1] = 1;
        }
        let dot = |left: &Vector, right: &Vector, shift: usize| -> i64 {
            let mut sum = 0i64;
            for block in 0..=ELL + M {
                let w = if block == 0 {
                    W0
                } else if block <= ELL {
                    WS
                } else {
                    WE
                };
                for j in 0..N {
                    let rotated = if j >= shift {
                        right[block * N + j - shift]
                    } else {
                        -right[block * N + j + N - shift]
                    };
                    sum += w as i64 * left[block * N + j] as i64 * rotated as i64;
                }
            }
            sum
        };
        let key = Key::new(&s);
        let y: Vector = core::array::from_fn(|i| (i % 7) as i32 - 3);
        let mut state = key.start(&y);
        for j in 0..N {
            assert_eq!(key.gram[j], dot(&s, &s, j), "Gram shift {j}");
            assert_eq!(state.dot(j), dot(&y, &s, j), "initial shift {j}");
        }
        let mut expected = y;
        for (shift, sign) in [(0usize, 1i32), (N - 1, -1), (37, 1)] {
            state.update(&key, shift, sign);
            for block in 0..=ELL + M {
                for j in 0..N {
                    expected[block * N + j] += sign
                        * if j >= shift {
                            s[block * N + j - shift]
                        } else {
                            -s[block * N + j + N - shift]
                        };
                }
            }
            for j in 0..N {
                assert_eq!(state.dot(j), dot(&expected, &s, j));
            }
        }
        let mut actual = y;
        key.finish(&state, &mut actual);
        assert_eq!(
            actual, expected,
            "production finish must update every tail block"
        );
        let mut fusion = y;
        key.finish_fusion_reference(&state, &mut fusion);
        assert_eq!(fusion, expected);
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
            let y: Vector = core::array::from_fn(|i| {
                let cap = if i < N {
                    154
                } else if i < (1 + ELL) * N {
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
                            } else if i < (1 + ELL) * N {
                                1064
                            } else {
                                1355
                            }
                        }
                        2 => {
                            if i < N {
                                -154
                            } else if i < (1 + ELL) * N {
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
