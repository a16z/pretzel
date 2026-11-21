// Tests of the owner that erases a signature buffer unless the signature is released.
use super::super::PacketOwner;
#[test]
fn packet_owner_success_rejection_and_unwind() {
    for keep in [false, true] {
        let mut value = [0x51u8; 1908];
        {
            let _guard = PacketOwner {
                value: &mut value,
                keep,
            };
        }
        assert_eq!(value, if keep { [0x51; 1908] } else { [0; 1908] });
    }
    let mut value = [0x71u8; 1908];
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let guard = PacketOwner {
            value: &mut value,
            keep: false,
        };
        guard.value[..91].fill(0x95);
        panic!("packet public unwind fixture");
    }));
    assert!(result.is_err());
    assert_eq!(value, [0; 1908]);
}

#[test]
fn packet_owner_partial_error() {
    fn fail(value: &mut [u8]) -> Result<(), ()> {
        let guard = PacketOwner { value, keep: false };
        guard.value[..17].fill(0x91);
        Err(())?;
        Ok(())
    }
    let mut value = [0x51; 1908];
    assert_eq!(fail(&mut value), Err(()));
    assert_eq!(value, [0; 1908]);
}
