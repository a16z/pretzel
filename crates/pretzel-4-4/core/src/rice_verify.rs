//! Rank-4 compact public verifier with native matrix/dither framing.
use super::*;

#[path = "rice_public_challenge.rs"]
mod public_challenge;
pub struct PreparedRice;
impl PreparedRice {
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
        use crate::rice_codec as codec;
        if signature.len() != codec::SIGNATURE_BYTES {
            return Err(Error::SignatureLength);
        }
        let mut head = [0i32; 1280];
        let decoded =
            codec::decode_head_borrowed(&signature[32..32 + codec::HEAD_BYTES], &mut head)
                .map_err(|_| Error::Decode)?;
        let local = codec::decode_local_planes(&signature[32 + codec::HEAD_BYTES..])
            .map_err(|_| Error::Decode)?;
        let mut labels = [0u8; 1024];
        {
            let packed =
                pk.mat
                    .compact_residual_caps(&decoded, pk.static_dither(), &local, &mut labels)?;
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
        let salt = signature[..32].try_into().unwrap();
        let digest = {
            let mu = pk.prefixes.verify_message_rep(context, message);
            pk.prefixes.verify_challenge_bytes(&mu, &salt, &labels)
        };
        if !public_challenge::matches(head[..N].try_into().unwrap(), &digest) {
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
    fn compact_residual_caps(
        &self,
        decoded: &crate::rice_codec::DecodedRiceHead<'_>,
        delta: &[Poly; M],
        local: &crate::rice_codec::DecodedLocalPlanes,
        labels: &mut [u8; 1024],
    ) -> Result<u64, Error> {
        let mut cols = [crate::compact_ring::CompactPoly::ZERO; ELL + 1];
        for (c, col) in cols.iter_mut().enumerate() {
            #[cfg(target_arch = "aarch64")]
            crate::neon::public_response_ntt::forward(decoded, c, &mut col.0);
        }
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
fn public_head_packed_reference(head: &crate::rice_codec::DecodedRiceHead<'_>) -> u64 {
    // Successful decoding establishes |z_i|<=288. Four independent accumulators
    // expose load parallelism; indexing remains checked. No low-word carry:
    // 1280*max(W_HEAD)=650885120<2^32; sum(z_i^2)<=106168320<2^32.
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

fn public_head_packed(head: &crate::rice_codec::DecodedRiceHead<'_>) -> u64 {
    signed_head_caps::packed(head)
}

#[cfg(test)]
#[path = "row_certificate_tests.rs"]
mod row_certificate_tests;
