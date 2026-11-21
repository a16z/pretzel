//! Pretzel side of the comparison (see README.md beside this file).
//!
//! Built outside the workspace against one Pretzel crate of this repository,
//! linked under the name `scheme`, with the features that the script selects. Only items
//! that the crate root exports are used, so the same file serves the three
//! parameter sets.
//!
//! Arguments: OPERATION CALLS WARMUP. The process makes a fresh key pair with
//! operating-system entropy, checks one signature both ways, then times CALLS
//! calls of one operation after WARMUP unmeasured calls and prints one line.
//! Thread CPU time is read around every call; the message has 32 bytes and the
//! context is empty.
//!
//!   keygen                    `keygen` (operating-system entropy); the returned key is
//!                             imported, used and verified outside the timed interval
//!   prepare_pk                `PreparedPk::new` and the release of the prepared key
//!   sign                      `sign_prepared_with_scratch`: prepared key, caller workspace
//!   verify                    `verify_prepared`
//!   verify_with_preparation   `verify` on the serialized public key
use scheme::{Ctx, PreparedPk, PreparedSk, SigningScratch};
use std::hint::black_box;

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
compile_error!("This driver requires Apple silicon macOS");

/// `struct timespec` of arm64 macOS.
#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}
extern "C" {
    fn clock_gettime(clock_id: u32, tp: *mut Timespec) -> i32;
    fn clock_gettime_nsec_np(clock_id: u32) -> u64;
}
const CLOCK_UPTIME_RAW: u32 = 8;
const CLOCK_THREAD_CPUTIME_ID: u32 = 16;

fn cpu_ns() -> u64 {
    let mut t = Timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: the pointer names a live, writable timespec of the platform's layout.
    let status = unsafe { clock_gettime(CLOCK_THREAD_CPUTIME_ID, &mut t) };
    assert_eq!(status, 0, "thread clock");
    t.tv_sec as u64 * 1_000_000_000 + t.tv_nsec as u64
}
fn wall_ns() -> u64 {
    // SAFETY: plain libSystem call with a constant clock identifier.
    let value = unsafe { clock_gettime_nsec_np(CLOCK_UPTIME_RAW) };
    assert_ne!(value, 0, "uptime clock");
    value
}
/// Thread CPU time starts first and stops last.
fn timed<T>(f: impl FnOnce() -> T) -> (T, u64, u64) {
    let cpu = cpu_ns();
    let wall = wall_ns();
    let result = black_box(f());
    let wall = wall_ns() - wall;
    let cpu = cpu_ns() - cpu;
    (result, cpu, wall)
}

type Signed = Result<(Vec<u8>, u32), scheme::Error>;

const OPERATIONS: [&str; 5] = [
    "keygen",
    "prepare_pk",
    "sign",
    "verify",
    "verify_with_preparation",
];

fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert_eq!(args.len(), 4, "OPERATION CALLS WARMUP");
    let op = args[1].as_str();
    assert!(OPERATIONS.contains(&op), "unknown operation");
    let calls: usize = args[2].parse().expect("CALLS");
    let warmup: usize = args[3].parse().expect("WARMUP");
    assert!(calls > 0 && calls <= 100_000 && warmup <= 1024, "counts");

    let ctx = Ctx::new();
    // Any error, including missing timing protection, ends the process.
    let pair = scheme::keygen(&ctx).expect("first key generation");
    let pk_owned: Vec<u8> = pair.pk.clone();
    let sk_owned: Vec<u8> = pair.sk.to_vec();
    let pk_bytes: &[u8] = &pk_owned;
    let sk_bytes: &[u8] = &sk_owned;
    assert_eq!(pk_bytes.len(), scheme::PUBLIC_KEY_BYTES, "public key size");
    assert_eq!(sk_bytes.len(), scheme::SECRET_KEY_BYTES, "secret key size");
    let sk = PreparedSk::new(sk_bytes).expect("secret key preparation");
    let pk = PreparedPk::new(pk_bytes).expect("public key preparation");
    let mut scratch = SigningScratch::new();
    let msg_array = [43u8; 32];
    let other_array = [44u8; 32];
    let msg: &[u8] = &msg_array;
    let other: &[u8] = &other_array;
    let empty: &[u8] = &[];

    let guard: Signed = scheme::sign_prepared_with_scratch(&ctx, &sk, &mut scratch, empty, msg);
    let (fixture_owned, _) = guard.expect("first signature");
    let fixture: &[u8] = &fixture_owned;
    assert_eq!(fixture.len(), scheme::SIGNATURE_BYTES, "signature size");
    scheme::verify_prepared(&ctx, &pk, msg, fixture).expect("first signature, prepared key");
    scheme::verify(&ctx, pk_bytes, msg, fixture).expect("first signature, serialized key");
    assert!(scheme::verify_prepared(&ctx, &pk, other, fixture).is_err(), "changed message accepted");
    assert!(scheme::verify(&ctx, pk_bytes, other, fixture).is_err(), "changed message accepted");

    let mut samples: Vec<u64> = Vec::with_capacity(calls);
    let mut wall_total = 0u64;
    let mut attempts_total = 0u64;
    for round in 0..calls + warmup {
        let (cpu, wall, attempts): (u64, u64, u32) = match op {
            "keygen" => {
                let (result, cpu, wall) = timed(|| scheme::keygen(black_box(&ctx)));
                let new_pair = result.expect("key generation");
                // The returned key is checked outside the timed interval.
                assert_eq!(new_pair.pk.len(), scheme::PUBLIC_KEY_BYTES);
                let new_sk_owned: Vec<u8> = new_pair.sk.to_vec();
                let new_sk = PreparedSk::new(&new_sk_owned).expect("generated key import");
                let signed: Signed =
                    scheme::sign_prepared_with_scratch(&ctx, &new_sk, &mut scratch, empty, msg);
                let (sig, _) = signed.expect("generated key sign");
                assert_eq!(sig.len(), scheme::SIGNATURE_BYTES);
                scheme::verify(&ctx, &new_pair.pk, msg, &sig).expect("generated key verify");
                (cpu, wall, 1)
            }
            "prepare_pk" => {
                let (result, cpu, wall) =
                    timed(|| PreparedPk::new(black_box(pk_bytes)).map(drop));
                result.expect("public key preparation");
                (cpu, wall, 1)
            }
            "sign" => {
                let (result, cpu, wall) = timed(|| -> Signed {
                    scheme::sign_prepared_with_scratch(
                        &ctx,
                        black_box(&sk),
                        &mut scratch,
                        empty,
                        black_box(msg),
                    )
                });
                let (sig, attempts) = result.expect("sign");
                assert_eq!(sig.len(), scheme::SIGNATURE_BYTES);
                scheme::verify_prepared(&ctx, &pk, msg, &sig).expect("measured signature verify");
                (cpu, wall, attempts)
            }
            "verify" => {
                let (result, cpu, wall) = timed(|| {
                    scheme::verify_prepared(&ctx, black_box(&pk), msg, black_box(fixture))
                });
                result.expect("verification");
                (cpu, wall, 1)
            }
            "verify_with_preparation" => {
                let (result, cpu, wall) =
                    timed(|| scheme::verify(&ctx, black_box(pk_bytes), msg, black_box(fixture)));
                result.expect("verification with preparation");
                (cpu, wall, 1)
            }
            _ => unreachable!(),
        };
        if round >= warmup {
            samples.push(cpu);
            wall_total += wall;
            attempts_total += u64::from(attempts);
        }
    }
    let cpu_total: u64 = samples.iter().sum();
    samples.sort_unstable();
    let median = samples[calls / 2];
    let least = samples[0];
    // Fields: operation, calls, CPU ns total, wall ns total, median CPU ns, least CPU ns,
    // signing attempts (calls for the other operations).
    println!("bench\t{op}\t{calls}\t{cpu_total}\t{wall_total}\t{median}\t{least}\t{attempts_total}");
}
