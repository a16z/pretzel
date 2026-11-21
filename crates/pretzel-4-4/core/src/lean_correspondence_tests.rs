//! Lean-to-Rust correspondence for the transport components of this crate.
//! Renders public, deterministic vectors from the production functions and
//! compares them byte for byte with `kat/transport_vectors.txt`, the vectors
//! printed by a Lean model of these components that is not in this repository.

use crate::hashes::Xof;
use crate::params::*;
use crate::{challenge, ct_slots, theta, transport};
use std::fmt::{Display, Write};

fn csv<T: Display>(xs: impl IntoIterator<Item = T>) -> String {
    xs.into_iter()
        .map(|x| x.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

fn line(out: &mut String, key: &str, value: impl Display) {
    writeln!(out, "{key}={value}").unwrap();
}

fn parity(z: &transport::Vector) -> String {
    challenge::parity_of(z[..N].try_into().unwrap())
        .iter()
        .map(|b| if *b { '1' } else { '0' })
        .collect()
}

fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}

/// Lean: PretzelTransport.Correspondence.vectors.
fn render() -> String {
    let mut out = String::new();
    let theta = theta::ThetaCtx::new();
    line(&mut out, "format", "pretzel-correspondence-v1");
    line(&mut out, "shape", csv([N, DIM / N, M, ELL, Q as usize]));
    assert_eq!(ELL, M);
    let weights: Vec<_> = (0..DIM / N)
        .map(|r| {
            let mut basis = [0; DIM];
            basis[r * N] = 1;
            transport::energy(&basis)
        })
        .collect();
    line(&mut out, "weights", csv(weights));
    line(&mut out, "key-window", csv([SHELL_LO, SHELL_HI]));
    line(
        &mut out,
        "proposal-window",
        csv([PROPOSAL_SHELL_LO, PROPOSAL_SHELL_HI]),
    );
    let d = gcd(ENV_NUM, ENV_DEN);
    line(
        &mut out,
        "envelope",
        format!("{}/{}", ENV_NUM / d, ENV_DEN / d),
    );
    line(&mut out, "theta-limbs", csv(THETA_NUM_LIMBS));
    line(&mut out, "theta-q384", csv(theta::theta_fx().0));
    line(&mut out, "inv-envelope-lo", csv(theta.inv_m.lo.0));
    line(&mut out, "inv-envelope-hi", csv(theta.inv_m.hi.0));

    // Public, deterministic inputs. No signing key or secret random tape is read.
    let z: transport::Vector = core::array::from_fn(|i| (i % 11) as i32 - 5);
    let s: transport::Vector = core::array::from_fn(|i| {
        if i < N {
            i32::from(i == 0)
        } else {
            i32::from((i / N) % 2 == 0)
        }
    });
    line(&mut out, "secret-energy", transport::energy(&s));
    line(&mut out, "response-energy", transport::energy(&z));
    line(&mut out, "response-parity", parity(&z));
    assert!((SHELL_LO..=SHELL_HI).contains(&transport::key_energy(&s)));
    let sparse = transport::SparseSecret::new(&s);
    for j in [0, 1, 127, 255] {
        let mut rotated = [0; DIM];
        transport::add_rotated(&mut rotated, &s, j, 1);
        let mut minus = z;
        let mut plus = z;
        transport::add_rotated(&mut minus, &s, j, -1);
        transport::add_rotated(&mut plus, &s, j, 1);
        let mut sparse_minus = z;
        let mut sparse_plus = z;
        transport::add_rotated_sparse(&mut sparse_minus, &sparse, j, -1);
        transport::add_rotated_sparse(&mut sparse_plus, &sparse, j, 1);
        assert_eq!(minus, sparse_minus);
        assert_eq!(plus, sparse_plus);
        let dot = transport::dot_rotated(&z, &s, j);
        assert_eq!(dot, transport::dot_rotated_sparse(&z, &sparse, j));
        let prefix = format!("rotation/{j}/");
        line(&mut out, &format!("{prefix}dot"), dot);
        line(
            &mut out,
            &format!("{prefix}energy"),
            transport::energy(&rotated),
        );
        line(&mut out, &format!("{prefix}minus"), csv(minus));
        line(&mut out, &format!("{prefix}plus"), csv(plus));
        line(&mut out, &format!("{prefix}parity-minus"), parity(&minus));
        line(&mut out, &format!("{prefix}parity-plus"), parity(&plus));
    }
    for w in [0, 1, 127, 128, 129, 254, 255] {
        for last in [false, true] {
            let c = core::array::from_fn(|i| if i == N - 1 { last } else { i < w });
            let prefix = format!("challenge/{w}/{}/", usize::from(last));
            line(&mut out, &format!("{prefix}weight"), challenge::weight(&c));
            line(
                &mut out,
                &format!("{prefix}valid"),
                usize::from(challenge::in_c255(&c)),
            );
            if challenge::in_c255(&c) {
                let mut records = [[0; ct_slots::WORDS]; ct_slots::FIRST_ROWS];
                let mut next = [[0; ct_slots::WORDS]; ct_slots::SECOND_ROWS];
                let mut rng = Xof::new(b"pretzel-lean-public-vectors-v1", &[]);
                let slots = ct_slots::Positions::new(&c, &mut rng, &mut records, &mut next);
                let mut positions = Vec::new();
                let mut dummies = 0;
                let mut saw_dummy = false;
                for slot in 0..128 {
                    let (j, active, _) = slots.get(slot);
                    if active == 0 {
                        dummies += 1;
                        saw_dummy = true;
                    } else {
                        assert!(!saw_dummy, "real steps must precede dummies");
                        positions.push(j);
                    }
                }
                line(&mut out, &format!("{prefix}positions"), csv(positions));
                line(&mut out, &format!("{prefix}dummies"), dummies);
            }
        }
    }
    out
}

#[test]
fn lean_vectors_match_production_components() {
    let expected = include_str!("../../kat/transport_vectors.txt");
    assert_eq!(
        render().as_bytes(),
        expected.as_bytes(),
        "Lean/Rust vector bytes differ"
    );
}
