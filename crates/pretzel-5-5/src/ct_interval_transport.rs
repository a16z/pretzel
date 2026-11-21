const _: () = {
    assert!(
        crate::params::PROPOSAL_SHELL_LO >= 131557 && crate::params::PROPOSAL_SHELL_HI <= 292635
    );
    assert!(crate::params::ENV_NUM == 65586 && crate::params::ENV_DEN == 65536);
    assert!(
        crate::params::N == 256
            && crate::params::PROPOSAL_W0 == 9216
            && crate::params::WS == 196
            && crate::params::WE == 121
    );
    let expected = [
        0x56cfb663778c15fbu64,
        0xb98cacf9f483e3c1,
        0x3b3b1e5aa8bcd882,
        0xfffff0ed5689f620,
    ];
    let mut i = 0;
    while i < 4 {
        assert!(crate::params::THETA_NUM_LIMBS[i] == expected[i]);
        i += 1;
    }
};

use zeroize::Zeroize;

// SAFETY: contract of the wrapper in `interval-erased-wrapper.S`, which calls
// `pretzel55_interval_prepare_key_impl` (`interval-transport.c`) with its arguments unchanged
// and then clears a fixed range of stack below its frame. The C function writes 35 rows of three
// `u64` at `out` and at most 12 `i64` at `coarse`; `b` is a value. It keeps no pointer.
extern "C" {
    fn pretzel55_interval_prepare_key(out: *mut u64, coarse: *mut i64, b: u64);
}

pub(crate) struct Prepared {
    coeff: [[u64; 3]; 35],
    coarse: [i64; 12],
}
impl Drop for Prepared {
    fn drop(&mut self) {
        self.coeff.zeroize();
        self.coarse.zeroize();
    }
}
impl Prepared {
    pub(crate) fn coarse_coefficients(&self) -> &[i64; 12] {
        &self.coarse
    }

    pub(crate) fn new(b: u64) -> Self {
        assert!(
            (131557..=292635).contains(&b),
            "Pretzel-(5,5) interval shell"
        );
        let mut value = Self {
            coeff: [[0; 3]; 35],
            coarse: [0; 12],
        };
        // SAFETY: `value.coeff` is `[[u64; 3]; 35]` and `value.coarse` is `[i64; 12]`, which cover
        // what the routine writes; they are distinct fields of a local.
        unsafe {
            pretzel55_interval_prepare_key(
                value.coeff.as_mut_ptr().cast(),
                value.coarse.as_mut_ptr(),
                b,
            );
        }
        value
    }
}

#[cfg(test)]
mod prepared_contract_tests {
    use super::*;
    #[test]
    // Keep the explicit lane order and index schedule of the kernel and its oracle.
    #[allow(clippy::needless_range_loop)]
    fn coefficients_match_recorded_fixture() {
        let data = include_bytes!("coarse-coefficient-fixtures.bin");
        for record in data.chunks_exact(8 + 35 * 24) {
            let b = u64::from_le_bytes(record[..8].try_into().unwrap());
            let actual = Prepared::new(b);
            for (i, words) in actual.coeff.iter().enumerate() {
                for j in 0..3 {
                    let offset = 8 + 24 * i + 8 * j;
                    let expected =
                        u64::from_le_bytes(record[offset..offset + 8].try_into().unwrap());
                    assert_eq!(words[j], expected, "b={b}, coefficient={i}, limb={j}");
                }
            }
        }
        assert_eq!(data.len(), 8 * (8 + 35 * 24));
    }
}

#[cfg(test)]
#[path = "centered10_tests.rs"]
mod centered10_tests;
