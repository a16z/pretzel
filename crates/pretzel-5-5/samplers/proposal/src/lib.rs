//! Proposal sampling for the high-precision signer.
//! `conditional_initial` supplies its initial proposal.
// Index loops stay explicit in fixed-time arithmetic so that the access pattern is visible to review.
#![allow(clippy::needless_range_loop)]
// Size and alignment assertions keep their explicit remainder tests; arithmetic is not rewritten for style.
#![allow(clippy::manual_is_multiple_of)]
// Shift, mask and sum expressions keep their written grouping; arithmetic on secret paths is not rewritten for style.
#![allow(clippy::precedence)]
// Workspaces and owners are built by `new` only; a `Default` implementation would add an entry point that nothing uses.
#![allow(clippy::new_without_default)]
pub mod simd_lookup;

pub mod conditional_initial;
pub mod main_kernel;

pub mod leading_alias32;

pub mod stream_compact;

pub mod coretail_main;

pub mod coretail_middle;

pub mod coretail_final;

pub mod coretail_major;

mod retirement;

#[cfg(test)]
mod fixture_gen;
