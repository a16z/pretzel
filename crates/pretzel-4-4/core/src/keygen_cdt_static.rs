//! Keygen Gaussian CDT samplers from static data instead of the theta model.
//!
//! Child module `gauss::keygen_static_cdt`. The data file
//! `src/keygen_cdt_static_data.rs` holds values taken from
//! the runtime construction of the same tree: per table the symbol values, the 192-bit boundary prefixes
//! (`bounds3`), the normalizer enclosure `z`, its 192-bit prefix `z3` and `draw_bits`. Cold tables are not
//! retained: these, the alias built from them and the lazy
//! fields are all a `Cdt` keeps; the cumulative, prefix and plane tables are computed and discarded by the
//! runtime and are rebuilt by the lazy fallback if ever used. The alias is built by
//! `Alias::new` on the stored bounds, and the collapsed-bounds check runs on it. The test
//! below compares every retained field and every alias field with the runtime construction.
use super::Cdt;
use crate::fixed::{Fx, Iv, LIMBS};

/// One CDT table as static data (the runtime outputs).
pub(crate) struct KgCdt {
    pub(crate) w: u64,
    pub(crate) even: bool,
    pub(crate) values: &'static [i32],
    pub(crate) bounds3: &'static [[u64; 3]],
    pub(crate) z3: [u64; 3],
    pub(crate) z_lo: [u64; LIMBS],
    pub(crate) z_hi: [u64; LIMBS],
    pub(crate) draw_bits: usize,
}

include!("keygen_cdt_static_data.rs");

fn table(w: u64, even_only: bool) -> &'static KgCdt {
    [&KEYGEN_CDT_LEAD, &KEYGEN_CDT_SEC, &KEYGEN_CDT_ERR]
        .into_iter()
        .find(|t| t.w == w && t.even == even_only)
        .expect("Static keygen CDT: no static table for this weight")
}

impl Cdt {
    /// The table for weight w from the static data; equal to `Cdt::new(&ThetaCtx::new(), w, even_only)`.
    pub(crate) fn keygen_from_static(w: u64, even_only: bool) -> Cdt {
        let d = table(w, even_only);
        let bounds3 = d.bounds3;
        let z3 = d.z3;
        #[cfg(target_arch = "aarch64")]
        let _ = crate::ct_collapsed_alias::prepare(bounds3, z3);
        let alias = crate::ct_alias::Alias::new(bounds3, z3);
        Cdt {
            values: d.values.to_vec(),
            stride: if even_only { 2 } else { 1 },
            alias,
            z3,
            z: Iv {
                lo: Fx(d.z_lo),
                hi: Fx(d.z_hi),
            },
            draw_bits: d.draw_bits,
            lazy_weight: w,
            lazy_even: even_only,
            cold: std::sync::OnceLock::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Cdt, ThetaCtx};
    use crate::params::{PROPOSAL_W0, WE, WS};

    fn same_alias(a: &Cdt, b: &Cdt) -> bool {
        match (&a.alias, &b.alias) {
            (Some(x), Some(y)) => x.same_fields(y),
            (None, None) => true,
            _ => false,
        }
    }

    #[test]
    fn keygen_init_static_cdt_equals_runtime() {
        let theta = ThetaCtx::new();
        for (w, even) in [(PROPOSAL_W0, true), (WS, false), (WE, false)] {
            let runtime = Cdt::new(&theta, w, even);
            let fixed = Cdt::keygen_from_static(w, even);
            assert_eq!(runtime.values, fixed.values, "values");
            assert_eq!(runtime.stride, fixed.stride, "stride");
            assert_eq!(runtime.z3, fixed.z3, "z3");
            assert_eq!((runtime.z.lo, runtime.z.hi), (fixed.z.lo, fixed.z.hi), "z");
            assert_eq!(runtime.draw_bits, fixed.draw_bits, "draw_bits");
            assert_eq!(
                (runtime.lazy_weight, runtime.lazy_even),
                (fixed.lazy_weight, fixed.lazy_even),
                "lazy fields"
            );
            assert!(
                runtime.cold.get().is_none() && fixed.cold.get().is_none(),
                "cold tables not retained"
            );
            assert!(same_alias(&runtime, &fixed), "alias");
            let retained = Cdt::new_with_cold(&theta, w, even, true);
            let cold = retained.cold.get().expect("retained cold tables");
            assert_eq!(
                cold.bounds3.as_slice(),
                super::table(w, even).bounds3,
                "bounds3"
            );
        }
    }
}
