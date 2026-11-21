//! Separate context for key generation. The signer uses scheme::Ctx.
use super::{Ctx, Error, Keypair};
use crate::{gauss::Cdt, params::*, theta::ThetaCtx, EntropySource};
pub struct KeygenCtx {
    tables: std::sync::OnceLock<Ctx>,
}
impl KeygenCtx {
    pub fn new() -> Self {
        Self {
            tables: std::sync::OnceLock::new(),
        }
    }
    pub fn write_parameter_snapshot(&self, out: &mut impl std::io::Write) -> std::io::Result<()> {
        self.tables
            .get_or_init(Self::build)
            .write_parameter_snapshot(out)
    }
    fn build() -> Ctx {
        let theta = ThetaCtx::new();
        let cdt_lead = Cdt::keygen_from_static(PROPOSAL_W0, true);
        let cdt_sec = Cdt::keygen_from_static(WS, false);
        let cdt_err = Cdt::keygen_from_static(WE, false);
        Ctx {
            theta,
            cdt_lead,
            cdt_sec,
            cdt_err,
        }
    }
}
impl Default for KeygenCtx {
    fn default() -> Self {
        Self::new()
    }
}
pub fn keygen_with_entropy(
    _ctx: &KeygenCtx,
    rng: &mut impl EntropySource,
) -> Result<Keypair, Error> {
    let _timing_state = crate::timing_state::Guard::enter()?;
    // Reverse drop order keeps the scrub inside the timing-protected scope.
    #[cfg(feature = "stack-wipe")]
    let _stack_scrub = crate::ct_erase::StackScrub::<{ crate::ct_erase::KEYGEN_SCRUB_WORDS }>;
    super::keygen_inner(rng)
}
#[cfg(test)]
mod tests {
    use super::{Ctx, KeygenCtx};
    #[test]
    fn keygen_init_same_snapshot() {
        let lazy = KeygenCtx::new();
        assert!(lazy.tables.get().is_none());
        let mut got = Vec::new();
        lazy.write_parameter_snapshot(&mut got).unwrap();
        let mut want = Vec::new();
        Ctx::new().write_parameter_snapshot(&mut want).unwrap();
        assert_eq!(got, want);
    }
}
