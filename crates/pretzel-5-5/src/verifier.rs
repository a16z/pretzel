//! Rank-5 compact public verifier with native matrix/dither framing.
//! 1908-byte codec with absolute-label hashing.
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
        self.verify_public_using_message_rep(pk, signature, || {
            {
                pk.prefixes.verify_message_rep(context, message)
            }
        })
    }
    // Internal release check only. The signer supplies the representative already
    // computed from this same prepared key, context and immutable message.
    // This retains every signature check, but is not an independent rehash for
    // detecting faults in the original message-representative computation.
    #[allow(dead_code)]
    pub(super) fn verify_with_message_rep(
        &self,
        pk: &PreparedPk,
        mu: &[u8; 64],
        signature: &[u8],
    ) -> Result<(), Error> {
        self.verify_using_message_rep(pk, signature, || *mu)
    }
    // Explicit dereference documents the borrowed owner at this boundary.
    #[allow(clippy::explicit_auto_deref)]
    fn verify_using_message_rep(
        &self,
        pk: &PreparedPk,
        signature: &[u8],
        message_rep: impl FnOnce() -> [u8; 64],
    ) -> Result<(), Error> {
        use crate::signature_codec as codec;
        if signature.len() != codec::SIGNATURE_BYTES {
            return Err(Error::SignatureLength);
        }
        let mut head = crate::ct_erase::zeroed_owners::I32::<1536>::zero();
        let (decoded, local) = codec::decode_fields_borrowed(&signature[32..], &mut *head)
            .map_err(|_| Error::Decode)?;
        let mut labels = PublicLabelsOwner([0u8; 1280]);
        let local = LocalPlanesOwner(local);
        {
            let packed = pk.mat.compact_residual_caps(
                &decoded,
                pk.static_dither(),
                &local.0,
                &mut *labels,
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
        let salt = signature[..32].try_into().unwrap();
        let mu = message_rep();
        let digest = pk.prefixes.verify_challenge_bytes(&mu, &salt, &*labels);
        if !public_challenge::matches(head[..N].try_into().unwrap(), &digest) {
            return Err(Error::ChallengeMismatch);
        }
        Ok(())
    }
    // Public entry has its own body so optional signing release verification
    // keeps the shared helper, erasing owners and complete call graph.
    fn verify_public_using_message_rep(
        &self,
        pk: &PreparedPk,
        signature: &[u8],
        message_rep: impl FnOnce() -> [u8; 64],
    ) -> Result<(), Error> {
        use crate::signature_codec as codec;
        if signature.len() != codec::SIGNATURE_BYTES {
            return Err(Error::SignatureLength);
        }
        // These buffers contain only caller-supplied public signature data.
        let mut head = [0i32; 1536];
        let (decoded, local) = codec::decode_fields_borrowed(&signature[32..], &mut head)
            .map_err(|_| Error::Decode)?;
        let mut labels = [0u8; 1280];
        {
            let packed = pk.mat.compact_residual_caps_public(
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
        let salt = signature[..32].try_into().unwrap();
        let mu = message_rep();
        let digest = pk.prefixes.verify_challenge_bytes(&mu, &salt, &labels);
        if !public_challenge::matches(head[..N].try_into().unwrap(), &digest) {
            return Err(Error::ChallengeMismatch);
        }
        Ok(())
    }
    // Explicit dereference documents the borrowed owner at this boundary.
    #[allow(clippy::explicit_auto_deref)]
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
        let mut head = crate::ct_erase::zeroed_owners::I32::<1536>::zero();
        let mut local = [0u8; 1280];
        codec::decode_fields(&signature[32..], &mut *head, &mut local)
            .map_err(|_| Error::Decode)?;
        let mut relation = [Poly::ZERO; M];
        pk.mat
            .apply_public_into(&*head, pk.static_dither(), &mut relation);
        let mut labels = [0u8; 1280];
        let mut hn = 0u64;
        let mut rn = 0u64;
        let mut score = 0u64;
        for &v in &*head {
            let a = v.unsigned_abs() as usize;
            hn += (a * a) as u64;
            score += u64::from(W_HEAD[a]);
        }
        if hn > CAP_EUC2_HEAD {
            return Err(Error::CapExceeded);
        }
        for i in 0..1280 {
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

// Signing release-check and test-reference owners keep full erasure.
// These buffers are erased with word stores.
#[repr(C, align(8))]
struct PublicLabelsOwner([u8; 1280]);
impl core::ops::Deref for PublicLabelsOwner {
    type Target = [u8; 1280];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl core::ops::DerefMut for PublicLabelsOwner {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl PublicLabelsOwner {
    fn erase(&mut self) {
        // SAFETY: repr(C, align(8)), first field, 1280 initialized bytes,
        // exclusive owner borrow. The buffer size is a multiple of eight.
        unsafe { erase_public_bytes_1280(self.0.as_mut_ptr()) };
    }
}
impl Drop for PublicLabelsOwner {
    fn drop(&mut self) {
        self.erase();
    }
}

// All-zero bytes are valid for the codec-private [[u8; 256]; 5] field.
#[repr(C, align(8))]
struct LocalPlanesOwner(crate::signature_codec::DecodedLocalPlanes);
const _: () = assert!(core::mem::size_of::<crate::signature_codec::DecodedLocalPlanes>() == 1280);
impl Drop for LocalPlanesOwner {
    fn drop(&mut self) {
        // SAFETY: the repr(C) first field is at offset zero and the enclosing
        // owner is aligned to eight. The size assertion covers all 1280 bytes;
        // the exclusive borrow prevents access through the decoded byte view.
        unsafe {
            erase_public_bytes_1280(
                (&mut self.0 as *mut crate::signature_codec::DecodedLocalPlanes).cast(),
            )
        };
    }
}

/// Erase 1280 initialized public bytes at an eight-byte-aligned exclusive pointer.
/// Zeroize on u64 retains its volatile stores and compiler fence, and every bit
/// pattern is valid for u64. The temporary word view does not escape this call.
/// # Safety
/// bytes must point to 1280 initialized writable bytes in one live allocation, aligned to u64 and
/// exclusively borrowed for the call. Reinterpreting those bytes as 160 u64 values must not invalidate
/// any live non-integer fields.
unsafe fn erase_public_bytes_1280(bytes: *mut u8) {
    debug_assert_eq!((bytes as usize) % core::mem::align_of::<u64>(), 0);
    // SAFETY: The caller supplies the function safety contract: bytes must point to 1280 initialized
    // writable bytes in one live allocation, aligned to u64 and exclusively borrowed for the call.
    // Reinterpreting those bytes as 160 u64 values must not invalidate any live non-integer fields.
    let words = unsafe { core::slice::from_raw_parts_mut(bytes.cast::<u64>(), 160) };
    zeroize::Zeroize::zeroize(words);
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
    // Explicit dereference documents the borrowed owner at this boundary.
    #[allow(clippy::explicit_auto_deref)]
    fn compact_residual_caps(
        &self,
        decoded: &crate::signature_codec::DecodedHead<'_>,
        delta: &[Poly; M],
        local: &crate::signature_codec::DecodedLocalPlanes,
        labels: &mut [u8; 1280],
    ) -> Result<u64, Error> {
        let mut cols = zeroize::Zeroizing::new([crate::compact_ring::CompactPoly::ZERO; ELL + 1]);
        for c in 0..ELL + 1 {
            decoded.write_canonical_column(c, &mut cols[c].0);
            cols[c].forward_canonical();
        }
        let mut sum = 0u64;
        let mut bad = false;
        for row in 0..M {
            let indices = local.row(row);
            let output = (&mut labels[row * N..(row + 1) * N]).try_into().unwrap();
            match crate::neon::public_compact_row_caps(
                &self.rows[row],
                &*cols,
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

    // Public response columns do not need the signing path's erasing owner.
    fn compact_residual_caps_public(
        &self,
        decoded: &crate::signature_codec::DecodedHead<'_>,
        delta: &[Poly; M],
        local: &crate::signature_codec::DecodedLocalPlanes,
        labels: &mut [u8; 1280],
    ) -> Result<u64, Error> {
        let mut cols = [crate::compact_ring::CompactPoly::ZERO; ELL + 1];
        for (c, col) in cols.iter_mut().enumerate() {
            crate::neon::public_response_ntt::forward(decoded, c, &mut col.0);
        }
        let mut sum = 0u64;
        let mut bad = false;
        for row in 0..M {
            let indices = local.row(row);
            let output = (&mut labels[row * N..(row + 1) * N]).try_into().unwrap();
            match crate::neon::public_compact_row_caps_fused(
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
    // 1536*max(W_HEAD)=781062144<2^32; sum(z_i^2)<=127401984<2^32.
    let mut sums = [0u64; 4];
    for values in head.values().chunks_exact(4) {
        for j in 0..4 {
            sums[j] += PUBLIC_HEAD_PACKED[values[j].unsigned_abs() as usize];
        }
    }
    sums.into_iter().sum()
}

fn public_head_packed(head: &crate::signature_codec::DecodedHead<'_>) -> u64 {
    signed_head_caps::packed(head)
}
// Exercise the selected verifier's decoder, head scorer and fused recovery
// on arbitrary public contexts. The zero relation makes delta the context.
#[cfg(test)]
pub(crate) fn certificate_public_stats(
    bytes: &[u8],
    contexts: &[i32; 1280],
) -> Result<(u64, u64), Error> {
    let mut head = Box::new([0i32; 1536]);
    let (decoded, local) = crate::signature_codec::decode_fields_borrowed(bytes, &mut head)
        .map_err(|_| Error::Decode)?;
    let matrix = MatrixAh {
        rows: [[crate::compact_ring::CompactPoly::ZERO; ELL + 1]; M],
    };
    let delta = core::array::from_fn(|r| Poly(core::array::from_fn(|i| contexts[r * N + i])));
    let mut labels = Box::new([0u8; 1280]);
    let residual = matrix.compact_residual_caps(&decoded, &delta, &local, &mut labels)?;
    Ok((public_head_packed(&decoded), residual))
}

#[cfg(test)]
#[path = "public_verify_tests.rs"]
mod public_verify_tests;
#[path = "signed_head_caps.rs"]
mod signed_head_caps;

#[cfg(test)]
mod public_word_erase_tests {
    use super::*;

    #[repr(C)]
    struct Guarded {
        before: u64,
        owner: PublicLabelsOwner,
        after: u64,
    }

    #[test]
    fn public_word_erase_covers_buffer_and_preserves_canaries() {
        assert_eq!(core::mem::size_of::<PublicLabelsOwner>(), 1280);
        assert!(core::mem::align_of::<PublicLabelsOwner>() >= 8);
        for byte in [0, 1, 0x55, 0xaa, 0xff] {
            let mut guarded = Guarded {
                before: 0x123456789abcdef0,
                owner: PublicLabelsOwner([byte; 1280]),
                after: 0xfedcba9876543210,
            };
            guarded.owner.erase();
            assert_eq!(*guarded.owner, [0; 1280]);
            assert_eq!(guarded.before, 0x123456789abcdef0);
            assert_eq!(guarded.after, 0xfedcba9876543210);
        }
    }

    #[test]
    fn public_local_owner_word_alignment_and_full_erase() {
        assert_eq!(core::mem::size_of::<LocalPlanesOwner>(), 1280);
        assert!(core::mem::align_of::<LocalPlanesOwner>() >= 8);
        let mut head = [0; 1536];
        let (_, local) = crate::signature_codec::decode_fields_borrowed(
            &[0; crate::signature_codec::HEAD_BYTES],
            &mut head,
        )
        .unwrap();
        let mut owner = LocalPlanesOwner(local);
        // The representation is exactly initialized byte storage. Set every byte
        // to nonzero, then exercise the same helper as the owner's destructor.
        let ptr = (&mut owner.0 as *mut crate::signature_codec::DecodedLocalPlanes).cast::<u8>();
        unsafe {
            core::slice::from_raw_parts_mut(ptr, 1280).fill(0xa5);
            erase_public_bytes_1280(ptr);
            assert!(core::slice::from_raw_parts(ptr, 1280)
                .iter()
                .all(|&b| b == 0));
        }
    }
}
