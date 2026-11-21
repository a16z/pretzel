//! Exercise the actual packing constructor on public valid and invalid inputs.
#![allow(dead_code, unexpected_cfgs)]

mod params {
    // The upper key-shell bound of Pretzel-(4,4); no secret key is used by these controls.
    pub const SHELL_HI: u64 = 244_553;
}
#[path = "../../core/src/ct_gram_registers.rs"]
mod packed;

fn panic_text(gram: &[i64; 256]) -> String {
    let result = std::panic::catch_unwind(|| packed::Packed::new(gram));
    let payload = match result {
        Ok(_) => panic!("invalid public control was accepted"),
        Err(payload) => payload,
    };
    if let Some(text) = payload.downcast_ref::<&str>() {
        text.to_string()
    } else if let Some(text) = payload.downcast_ref::<String>() {
        text.clone()
    } else {
        panic!("unexpected non-string diagnostic");
    }
}

#[test]
fn midpoint_failure_never_formats_the_private_operand() {
    for value in [1, -1, 271828, i64::MIN, i64::MAX] {
        let mut gram = [0i64; 256];
        gram[128] = value;
        assert_eq!(panic_text(&gram), "invalid Gram midpoint");
    }
}

#[test]
fn symmetry_failure_never_formats_either_private_operand() {
    for index in 1..128 {
        for value in [-244553, -65536, -1, 1, 65535, 244553] {
            let mut gram = [0i64; 256];
            gram[index] = value;
            gram[256 - index] = -value + 1;
            assert_eq!(panic_text(&gram), "invalid Gram symmetry");
        }
    }
}

#[test]
fn valid_boundary_rows_still_reconstruct_every_coefficient() {
    for value in [-244553, -196608, -65536, -1, 0, 1, 65535, 196608, 244553] {
        let mut gram = [0i64; 256];
        gram[0] = params::SHELL_HI as i64;
        for index in 1..128 {
            gram[index] = value;
            gram[256 - index] = -value;
        }
        let row = packed::Packed::new(&gram);
        for index in 0..128 {
            let high = ((row.high[index / 2] >> ((index & 1) * 4)) & 15) as i32;
            let restored = (((high << 28) >> 12) | row.low[index] as i32) as i64;
            assert_eq!(restored, gram[index]);
        }
    }
}
