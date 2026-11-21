//! Sizes of a fixed-work prefix of the uniform-dither expansion: `CANDIDATES` 13-bit words,
//! routed in a network of `NETWORK` records. `NETWORK` is the length in words of
//! `Buffers::dither_next` (`scratch.rs`), a workspace of the mask sampler.
use crate::params::{M, N};

pub(crate) const CANDIDATES: usize = 1280;
pub(crate) const NETWORK: usize = 2048;
const _: () = assert!(M * N == 1024 && CANDIDATES <= NETWORK && NETWORK.is_power_of_two());
