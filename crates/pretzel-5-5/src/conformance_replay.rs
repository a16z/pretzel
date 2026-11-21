//! Deterministic release-build replay using public test entropy only.
//! Included inside prepared_signer solely for the conformance feature.
//! This transcript contains public test keys/signatures, never secret keys.
use super::*;
use crate::scheme::verifier::PreparedVerifier;

const KEYS: usize = 4;
const CASES: usize = 32;
const UNWIND_MARKER: &str = "public conformance entropy unwind";

#[derive(Clone, Copy)]
enum Fault {
    Error,
    Unwind,
}
impl Fault {
    fn name(self) -> &'static str {
        match self {
            Self::Error => "partial_entropy_error",
            Self::Unwind => "partial_entropy_unwind",
        }
    }
}

struct Tape {
    x: Xof,
    requests: Vec<usize>,
    written: Vec<usize>,
    fault: Option<(usize, Fault)>,
    reached: bool,
}
impl Tape {
    fn new(domain: &[u8], key: usize, case: usize) -> Self {
        Self {
            x: Xof::new(
                domain,
                &[&(key as u64).to_le_bytes(), &(case as u64).to_le_bytes()],
            ),
            requests: Vec::new(),
            written: Vec::new(),
            fault: None,
            reached: false,
        }
    }
    fn signing(key: usize, case: usize) -> Self {
        Self::new(b"PRETZEL-RL5-SPEED-CONFORMANCE-SIGN-v1", key, case)
    }
    fn next64(&mut self) -> [u8; 64] {
        // This observation does not count as a call by the signing algorithm.
        self.x.bytes::<64>()
    }
}
impl EntropySource for Tape {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), crate::EntropyError> {
        let call = self.requests.len();
        self.requests.push(out.len());
        if let Some((fail_call, fault)) = self.fault {
            if call == fail_call {
                let partial = out.len().min(17);
                self.x.fill(&mut out[..partial]);
                self.written.push(partial);
                self.reached = true;
                match fault {
                    Fault::Error => return Err(crate::EntropyError),
                    // Resume an ordinary unwind without a panic hook. This
                    // keeps expected fault output independent of source paths
                    // and leaves the process-global hook untouched.
                    Fault::Unwind => std::panic::resume_unwind(Box::new(UNWIND_MARKER)),
                }
            }
        }
        self.x.fill(out);
        self.written.push(out.len());
        Ok(())
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        result.push(DIGITS[(byte >> 4) as usize] as char);
        result.push(DIGITS[(byte & 15) as usize] as char);
    }
    result
}

fn inputs(key: usize, case: usize) -> (Vec<u8>, Vec<u8>) {
    let context = match case % 3 {
        0 => Vec::new(),
        1 => b"speed-conformance".to_vec(),
        _ => vec![0, 255, key as u8, case as u8],
    };
    // Vary independently of context so all nine combinations occur.
    let length = [0, 32, 4096][(case / 3) % 3];
    let mut message = vec![0u8; length];
    Xof::new(
        b"PRETZEL-RL5-SPEED-CONFORMANCE-MESSAGE-v1",
        &[&(key as u64).to_le_bytes(), &(case as u64).to_le_bytes()],
    )
    .fill(&mut message);
    (context, message)
}

fn verify_case(
    verifier: &PreparedVerifier,
    key: &PreparedSk,
    context: &[u8],
    message: &[u8],
    signature: &[u8],
) {
    assert_eq!(signature.len(), 1908);
    verifier
        .verify(&key.ppk, context, message, signature)
        .unwrap();
    verifier
        .verify_reference(&key.ppk, context, message, signature)
        .unwrap();
    verifier
        .verify_serialized_complete(key.public_key(), context, message, signature)
        .unwrap();
    let mut wrong_message = message.to_vec();
    if wrong_message.is_empty() {
        wrong_message.push(1);
    } else {
        wrong_message[0] ^= 1;
    }
    let mut wrong_context = context.to_vec();
    wrong_context.push(1);
    for (changed_context, changed_message) in [
        (context, wrong_message.as_slice()),
        (wrong_context.as_slice(), message),
    ] {
        assert!(verifier
            .verify(&key.ppk, changed_context, changed_message, signature)
            .is_err());
        assert!(verifier
            .verify_reference(&key.ppk, changed_context, changed_message, signature)
            .is_err());
        assert!(verifier
            .verify_serialized_complete(
                key.public_key(),
                changed_context,
                changed_message,
                signature
            )
            .is_err());
    }
}

struct Expected {
    case: usize,
    signature: Vec<u8>,
    attempts: u32,
    requests: Vec<usize>,
    next64: [u8; 64],
}

fn failure_and_recovery(
    ctx: &Ctx,
    verifier: &PreparedVerifier,
    key: &PreparedSk,
    scratch: &mut SigningScratch,
    key_index: usize,
    expected: &Expected,
    fail_call: usize,
    fault: Fault,
) {
    let (context, message) = inputs(key_index, expected.case);
    let mut tape = Tape::signing(key_index, expected.case);
    tape.fault = Some((fail_call, fault));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        sign_prepared_using(ctx, key, scratch, &context, &message, &mut tape)
    }));
    assert!(tape.reached, "a naturally reached entropy call is required");
    match (fault, result) {
        (Fault::Error, Ok(Err(Error::RngFailure))) => {}
        (Fault::Unwind, Err(payload)) => {
            assert_eq!(
                payload.downcast_ref::<&'static str>().copied(),
                Some(UNWIND_MARKER)
            );
        }
        _ => panic!("fault injection returned an unexpected outcome"),
    }
    assert_eq!(tape.requests, vec![64; fail_call + 1]);
    assert_eq!(tape.written.last(), Some(&17));
    assert!(scratch.is_erased());
    let next = tape.next64();
    println!(
        "{{\"operation\":\"fault\",\"key\":{key_index},\"case\":{},\"kind\":\"{}\",\"fail_call\":{fail_call},\"reached\":true,\"entropy_fill_count\":{},\"entropy_fill_sizes\":{:?},\"entropy_written_sizes\":{:?},\"next64_hex\":\"{}\",\"scratch_erased\":true}}",
        expected.case, fault.name(), tape.requests.len(), tape.requests, tape.written, hex(&next)
    );

    // Reuse the same scratch after the failure. Replay must match the earlier
    // clean call in bytes, retry count, entropy requests and stream position.
    let mut recovery = Tape::signing(key_index, expected.case);
    let (signature, attempts) =
        sign_prepared_using(ctx, key, scratch, &context, &message, &mut recovery).unwrap();
    let next = recovery.next64();
    assert_eq!(signature, expected.signature);
    assert_eq!(attempts, expected.attempts);
    assert_eq!(recovery.requests, expected.requests);
    assert_eq!(next, expected.next64);
    assert!(scratch.is_erased());
    verify_case(verifier, key, &context, &message, &signature);
    println!(
        "{{\"operation\":\"recovery\",\"key\":{key_index},\"case\":{},\"after\":\"{}\",\"fail_call\":{fail_call},\"attempts\":{attempts},\"entropy_fill_count\":{},\"entropy_fill_sizes\":{:?},\"next64_hex\":\"{}\",\"signature_hex\":\"{}\",\"scratch_erased\":true}}",
        expected.case, fault.name(), recovery.requests.len(), recovery.requests, hex(&next), hex(&signature)
    );
}

pub fn run() {
    assert!(cfg!(target_os = "macos"), "supported on macOS AArch64 only");
    assert!(
        cfg!(panic = "unwind"),
        "unwind cleanup gate requires panic=unwind"
    );
    assert!(
        !cfg!(test),
        "this gate must use the release signer without test outcome hooks"
    );
    println!("{{\"operation\":\"metadata\",\"schema\":1,\"profile\":\"PZSP5-R5-N0001\",\"keys\":4,\"cases_per_key\":32,\"signature_bytes\":1908,\"public_test_fixtures\":true,\"timings\":false,\"forced_outcomes\":false}}");
    let ctx = Ctx::new();
    let verifier = PreparedVerifier::new(&ctx).unwrap();
    let mut scratch = SigningScratch::new();
    let mut late_keys = 0usize;
    let mut faults = 0usize;
    for key_index in 0..KEYS {
        let mut entropy = Tape::new(b"PRETZEL-RL5-SPEED-CONFORMANCE-KEY-v1", key_index, 0);
        let pair = keygen_with_entropy(&ctx, &mut entropy).unwrap();
        let key = PreparedSk::new(&pair.sk).unwrap();
        assert_eq!(key.public_key(), pair.pk.as_slice());
        assert_eq!(pair.pk.len(), 2158);
        let next = entropy.next64();
        println!(
            "{{\"operation\":\"key\",\"key\":{key_index},\"seed_index\":{key_index},\"public_key_hex\":\"{}\",\"entropy_fill_count\":{},\"entropy_fill_sizes\":{:?},\"next64_hex\":\"{}\"}}",
            hex(&pair.pk), entropy.requests.len(), entropy.requests, hex(&next)
        );
        let mut first = None;
        let mut natural_retry = None;
        for case in 0..CASES {
            let (context, message) = inputs(key_index, case);
            let mut tape = Tape::signing(key_index, case);
            let (signature, attempts) =
                sign_prepared_using(&ctx, &key, &mut scratch, &context, &message, &mut tape)
                    .unwrap();
            assert!(attempts > 0);
            assert_eq!(tape.requests, vec![64; attempts as usize]);
            assert_eq!(tape.requests, tape.written);
            assert!(scratch.is_erased());
            verify_case(&verifier, &key, &context, &message, &signature);
            let next64 = tape.next64();
            println!(
                "{{\"operation\":\"case\",\"key\":{key_index},\"case\":{case},\"context_hex\":\"{}\",\"message_hex\":\"{}\",\"signature_hex\":\"{}\",\"attempts\":{attempts},\"entropy_fill_count\":{},\"entropy_fill_sizes\":{:?},\"next64_hex\":\"{}\",\"scratch_erased\":true,\"public_and_reference_verifiers\":true,\"negative_controls\":6}}",
                hex(&context), hex(&message), hex(&signature), tape.requests.len(), tape.requests, hex(&next64)
            );
            if case == 0 || (attempts > 1 && natural_retry.is_none()) {
                let expected = Expected {
                    case,
                    signature,
                    attempts,
                    requests: tape.requests,
                    next64,
                };
                if case == 0 {
                    first = Some(expected);
                    if attempts > 1 {
                        let original = first.as_ref().unwrap();
                        natural_retry = Some(Expected {
                            case: original.case,
                            signature: original.signature.clone(),
                            attempts: original.attempts,
                            requests: original.requests.clone(),
                            next64: original.next64,
                        });
                    }
                } else {
                    natural_retry = Some(expected);
                }
            }
        }
        for fault in [Fault::Error, Fault::Unwind] {
            failure_and_recovery(
                &ctx,
                &verifier,
                &key,
                &mut scratch,
                key_index,
                first.as_ref().unwrap(),
                0,
                fault,
            );
            faults += 1;
        }
        if let Some(expected) = natural_retry {
            late_keys += 1;
            for fault in [Fault::Error, Fault::Unwind] {
                failure_and_recovery(
                    &ctx,
                    &verifier,
                    &key,
                    &mut scratch,
                    key_index,
                    &expected,
                    1,
                    fault,
                );
                faults += 1;
            }
        } else {
            println!("{{\"operation\":\"coverage\",\"key\":{key_index},\"late_entropy_call_reached\":false}}");
        }
    }
    assert!(
        late_keys > 0,
        "no natural retry occurred: late-failure coverage is incomplete"
    );
    println!("{{\"operation\":\"complete\",\"keys\":{KEYS},\"cases\":{},\"faults\":{faults},\"recoveries\":{faults},\"keys_with_natural_retry\":{late_keys},\"status\":\"PASS\"}}", KEYS * CASES);
}
