use super::*;
#[test]
fn resident_pair_final_state_and_output_canaries() {
    assert!(available());
    let mut state = 0xa435_1298_76cdu64;
    for _ in 0..64 {
        let mut pair = [0u64; 50];
        for word in &mut pair {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *word = state;
        }
        let mut want_pair = pair;
        let mut a = [0xa5u8; 8546];
        let mut b = [0x5au8; 2402];
        let mut c = [0x33u8; 6146];
        let mut expected_a = [0; 8544];
        let mut expected_b = [0; 8544];
        for block in 0..63 {
            permute_scalar(&mut want_pair);
            store_balanced_segment(&want_pair, 0, block * RATE, 0, &mut expected_a);
            store_balanced_segment(&want_pair, 1, block * RATE, 0, &mut expected_b);
        }
        unsafe {
            sign_prefix_shake::squeeze(
                &mut pair,
                (&mut a[1..8545]).try_into().unwrap(),
                (&mut b[1..2401]).try_into().unwrap(),
                (&mut c[1..6145]).try_into().unwrap(),
            );
        }
        assert_eq!(pair, want_pair);
        assert_eq!(&a[1..8545], &expected_a);
        assert_eq!(&b[1..2401], &expected_b[..2400]);
        assert_eq!(&c[1..6145], &expected_b[2400..]);
        assert_eq!(
            (a[0], a[8545], b[0], b[2401], c[0], c[6145]),
            (0xa5, 0xa5, 0x5a, 0x5a, 0x33, 0x33)
        );
    }
}
