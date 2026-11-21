//! Rank-3 compact public verifier with native matrix/dither framing.
use super::*;
#[path = "public_challenge.rs"]
mod public_challenge;
pub struct PreparedVerifier;
impl PreparedVerifier {
    pub fn new(_ctx: &Ctx) -> Result<Self, Error> {
        Ok(Self)
    }
    pub fn verify_serialized_complete(
        &self,
        raw: &[u8],
        context: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        let pk = PreparedPk::new(raw)?;
        self.verify(&pk, context, message, signature)
    }
    pub fn verify(
        &self,
        pk: &PreparedPk,
        context: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        use crate::signature_codec as codec;
        if signature.len() != codec::SIGNATURE_BYTES {
            return Err(Error::SignatureLength);
        }
        let mut head = [0i32; 1024];
        let decoded =
            codec::decode_head_borrowed(&signature[32..32 + codec::HEAD_BYTES], &mut head)
                .map_err(|_| Error::Decode)?;
        let local = codec::decode_local_planes(&signature[32 + codec::HEAD_BYTES..])
            .map_err(|_| Error::Decode)?;
        let mut labels = [core::mem::MaybeUninit::uninit(); 768];
        {
            let packed = pk.mat.compact_residual_caps_uninit(
                &decoded,
                pk.static_dither(),
                &local,
                &mut labels,
            )?;
            {
                let head = public_head_packed(&decoded);
                if head >> 32 > CAP_EUC2_HEAD
                    || packed >> 32 > CAP_EUC2_RES
                    || (head as u32 as u64) + (packed as u32 as u64) > CAP_Q20
                {
                    return Err(Error::CapExceeded);
                }
            }
        }
        // SAFETY: every row wrote all labels before compact_residual_caps_uninit returned success.
        // MaybeUninit<u8> has u8 layout; the shared borrow stays within the live array.
        let labels = unsafe { &*labels.as_ptr().cast::<[u8; 768]>() };
        let salt = signature[..32].try_into().unwrap();
        let digest = {
            let mu = pk.prefixes.verify_message_rep(context, message);
            pk.prefixes.verify_challenge_bytes(&mu, &salt, &labels[..])
        };
        if !public_challenge::matches(head[..N].try_into().unwrap(), &digest) {
            return Err(Error::ChallengeMismatch);
        }
        Ok(())
    }
    pub fn verify_reference(
        &self,
        pk: &PreparedPk,
        context: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        use crate::signature_codec as codec;
        if signature.len() != codec::SIGNATURE_BYTES {
            return Err(Error::SignatureLength);
        }
        let mut head = [0i32; 1024];
        let mut local = [0u8; 768];
        codec::decode_head_scalar(&signature[32..32 + codec::HEAD_BYTES], &mut head)
            .map_err(|_| Error::Decode)?;
        codec::decode_local(&signature[32 + codec::HEAD_BYTES..], &mut local)
            .map_err(|_| Error::Decode)?;
        let mut relation = [Poly::ZERO; M];
        pk.mat
            .apply_public_into(&head, pk.static_dither(), &mut relation);
        let mut labels = [0u8; 768];
        let mut hn = 0u64;
        let mut rn = 0u64;
        let mut score = 0u64;
        for &v in &head {
            let a = v.unsigned_abs() as usize;
            hn += (a * a) as u64;
            score += u64::from(W_HEAD[a]);
        }
        if hn > CAP_EUC2_HEAD {
            return Err(Error::CapExceeded);
        }
        for i in 0..768 {
            let (u, r) = codec::recover(relation[i / N].0[i % N], local[i])
                .map_err(|_| Error::CapExceeded)?;
            labels[i] = u;
            let a = r.unsigned_abs() as usize;
            rn += (a * a) as u64;
            score += u64::from(W_RES[a]);
        }
        if rn > CAP_EUC2_RES || score > CAP_Q20 {
            return Err(Error::CapExceeded);
        }
        let c = challenge::parity_of(head[..N].try_into().unwrap());
        if !challenge::in_c255(&c) {
            return Err(Error::ChallengeMismatch);
        }
        let mu = pk.message_rep(context, message);
        let salt = signature[..32].try_into().unwrap();
        if c != challenge::fold(&pk.challenge_bytes(&mu, &salt, &labels)) {
            return Err(Error::ChallengeMismatch);
        }
        Ok(())
    }
}

const fn compact_residual_table() -> [u64; 452] {
    let mut out = [0; 452];
    let mut i = 0;
    while i < 452 {
        out[i] = ((i * i) as u64) << 32 | W_RES[i] as u64;
        i += 1;
    }
    out
}
static COMPACT_RESIDUAL_CAPS: [u64; 452] = compact_residual_table();
impl MatrixAh {
    // Preserve the initialized-buffer entrypoint used by the certificate test.
    #[cfg(test)]
    fn compact_residual_caps(
        &self,
        decoded: &crate::signature_codec::DecodedHead<'_>,
        delta: &[Poly; M],
        local: &crate::signature_codec::DecodedLocalPlanes,
        labels: &mut [u8; 768],
    ) -> Result<u64, Error> {
        // SAFETY: u8 and MaybeUninit<u8> have identical size and alignment. The
        // exclusive reborrow lasts only for this call. The callee only stores valid
        // bytes, never uninitialized values, so labels stays initialized on success,
        // error and unwind, including any bytes the callee has not yet overwritten.
        let labels = unsafe {
            &mut *labels
                .as_mut_ptr()
                .cast::<[core::mem::MaybeUninit<u8>; 768]>()
        };
        self.compact_residual_caps_uninit(decoded, delta, local, labels)
    }
    fn compact_residual_caps_uninit(
        &self,
        decoded: &crate::signature_codec::DecodedHead<'_>,
        delta: &[Poly; M],
        local: &crate::signature_codec::DecodedLocalPlanes,
        labels: &mut [core::mem::MaybeUninit<u8>; 768],
    ) -> Result<u64, Error> {
        let cols = core::array::from_fn(|c| crate::neon::public_response_ntt::forward(decoded, c));
        let mut sum = 0u64;
        let mut bad = false;
        for row in 0..M {
            let indices = local.row(row);
            let output = (&mut labels[row * N..(row + 1) * N]).try_into().unwrap();
            match crate::neon::public_compact_row_caps(
                &self.rows[row],
                &cols,
                &delta[row],
                indices,
                output,
                &COMPACT_RESIDUAL_CAPS,
            ) {
                Some(v) => sum += v,
                None => bad = true,
            }
        }
        if bad {
            Err(Error::CapExceeded)
        } else {
            Ok(sum)
        }
    }
}

#[cfg(test)]
const fn public_head_table() -> [u64; 289] {
    let mut out = [0; 289];
    let mut i = 0;
    while i < 289 {
        out[i] = ((i * i) as u64) << 32 | W_HEAD[i] as u64;
        i += 1;
    }
    out
}
#[cfg(test)]
static PUBLIC_HEAD_PACKED: [u64; 289] = public_head_table();
#[cfg(test)]
fn public_head_packed_reference(head: &crate::signature_codec::DecodedHead<'_>) -> u64 {
    // Successful decoding establishes |z_i|<=288. Four independent accumulators
    // expose load parallelism; indexing remains checked. No low-word carry:
    // 1024*max(W_HEAD)<2^32; sum(z_i^2)<=1024*288^2<2^32.
    let mut sums = [0u64; 4];
    for values in head.values().chunks_exact(4) {
        for j in 0..4 {
            sums[j] += PUBLIC_HEAD_PACKED[values[j].unsigned_abs() as usize];
        }
    }
    sums.into_iter().sum()
}

#[cfg(test)]
#[path = "public_verify_tests.rs"]
mod public_verify_tests;

#[path = "signed_head_caps.rs"]
mod signed_head_caps;
fn public_head_packed(head: &crate::signature_codec::DecodedHead<'_>) -> u64 {
    signed_head_caps::packed(head)
}
#[cfg(test)]
#[test]
fn public_wire_sizes() {
    assert_eq!(crate::signature_codec::SIGNATURE_BYTES, 1160);
    assert_eq!(
        crate::params::PK_BYTES + crate::direct_ntt_profile::PROFILE.len(),
        1326
    );
}

#[cfg(test)]
#[path = "row_certificate_tests.rs"]
mod row_certificate_tests;
