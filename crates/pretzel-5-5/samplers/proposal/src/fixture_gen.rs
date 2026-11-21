//! Helpers of the tests that rebuild the fixture sets: SHA-256, the seeded expansion and bit
//! access. The rules are stated in `../../generators/README.md`; the generator beside that file
//! computes the same bytes in Python. This module is compiled for tests only.

/// Largest `x` below `2^40` with `x^power <= n`, for `power` 2 or 3.
fn root(n: u128, power: u32) -> u128 {
    let mut low = 0u128;
    let mut high = 1u128 << 40;
    while high - low > 1 {
        let middle = (low + high) / 2;
        if middle.pow(power) <= n {
            low = middle;
        } else {
            high = middle;
        }
    }
    low
}

/// The initial state and the round constants of SHA-256: the first 32 fractional bits of the
/// square roots of the first 8 primes and of the cube roots of the first 64 primes.
fn constants() -> &'static ([u32; 8], [u32; 64]) {
    static CELL: std::sync::OnceLock<([u32; 8], [u32; 64])> = std::sync::OnceLock::new();
    CELL.get_or_init(|| {
        let mut primes = [0u128; 64];
        let mut count = 0;
        let mut n = 2u128;
        while count < 64 {
            if (2..n).all(|d| n % d != 0) {
                primes[count] = n;
                count += 1;
            }
            n += 1;
        }
        let mut state = [0u32; 8];
        let mut k = [0u32; 64];
        for i in 0..8 {
            state[i] = root(primes[i] << 64, 2) as u32;
        }
        for i in 0..64 {
            k[i] = root(primes[i] << 96, 3) as u32;
        }
        (state, k)
    })
}

/// SHA-256 (FIPS 180-4), checked below against the standard test vectors.
pub(crate) struct Sha256 {
    state: [u32; 8],
    block: [u8; 64],
    filled: usize,
    length: u64,
}

impl Sha256 {
    pub(crate) fn new() -> Self {
        Self {
            state: constants().0,
            block: [0; 64],
            filled: 0,
            length: 0,
        }
    }

    fn compress(&mut self) {
        let k = &constants().1;
        let mut w = [0u32; 64];
        for i in 0..16 {
            let b = &self.block[4 * i..4 * i + 4];
            w[i] = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        }
        for i in 16..64 {
            let x = w[i - 15];
            let y = w[i - 2];
            let s0 = x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3);
            let s1 = y.rotate_right(17) ^ y.rotate_right(19) ^ (y >> 10);
            let t = w[i - 16].wrapping_add(s0);
            w[i] = t.wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let mut v = self.state;
        for i in 0..64 {
            let [a, b, c, d, e, f, g, h] = v;
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = h.wrapping_add(s1).wrapping_add(ch);
            let t1 = t1.wrapping_add(k[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let top = t1.wrapping_add(s0).wrapping_add(maj);
            let low = d.wrapping_add(t1);
            v = [top, a, b, c, low, e, f, g];
        }
        for i in 0..8 {
            self.state[i] = self.state[i].wrapping_add(v[i]);
        }
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        for byte in data {
            self.block[self.filled] = *byte;
            self.filled += 1;
            if self.filled == 64 {
                self.compress();
                self.filled = 0;
            }
        }
        self.length += data.len() as u64;
    }

    pub(crate) fn finish(mut self) -> [u8; 32] {
        let bits = self.length * 8;
        self.update(&[0x80]);
        while self.filled != 56 {
            self.update(&[0]);
        }
        self.update(&bits.to_be_bytes());
        let mut out = [0u8; 32];
        for i in 0..8 {
            out[4 * i..4 * i + 4].copy_from_slice(&self.state[i].to_be_bytes());
        }
        out
    }

    /// The digest in lower-case hexadecimal, the form in which the tests pin it.
    pub(crate) fn hex(self) -> String {
        let mut out = String::new();
        for byte in self.finish() {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }
}

/// The records of one set: the hash of the whole set, and a short hash of every record. When the
/// set hash differs from its pin, `check` prints the short hashes, to be compared with the output
/// of `gen_proposal_fixtures.py --record-hashes`, which locates the first record that differs.
pub(crate) struct Records {
    all: Sha256,
    one: Sha256,
    short: Vec<String>,
}

impl Records {
    pub(crate) fn new() -> Self {
        Self {
            all: Sha256::new(),
            one: Sha256::new(),
            short: Vec::new(),
        }
    }

    /// Appends bytes to the current record.
    pub(crate) fn update(&mut self, data: &[u8]) {
        self.all.update(data);
        self.one.update(data);
    }

    /// Ends the current record.
    pub(crate) fn end(&mut self) {
        let one = core::mem::replace(&mut self.one, Sha256::new());
        let digest = one.hex();
        self.short.push(digest[..8].to_string());
    }

    /// Panics unless the SHA-256 of all records is `pin`.
    pub(crate) fn check(self, name: &str, pin: &str) {
        let digest = self.all.hex();
        if digest != pin {
            for (index, short) in self.short.iter().enumerate() {
                eprintln!("{name} record {index} {short}");
            }
            panic!("{name}: the set hash is {digest}");
        }
    }
}

/// SHA-256 in counter mode. Block `i` is the hash of the label, one zero byte, and `seed` and `i`
/// as 32-bit little-endian words; `out` receives the leading bytes of block 0, block 1, ...
pub(crate) fn expand(label: &str, seed: u32, out: &mut [u8]) {
    for (counter, chunk) in out.chunks_mut(32).enumerate() {
        let mut hash = Sha256::new();
        hash.update(label.as_bytes());
        hash.update(&[0]);
        hash.update(&seed.to_le_bytes());
        hash.update(&(counter as u32).to_le_bytes());
        let block = hash.finish();
        chunk.copy_from_slice(&block[..chunk.len()]);
    }
}

/// The values 0, `cut - 1`, `cut`, `cut + 1` and `top` that lie in `[0, top]`, increasing, once
/// each.
pub(crate) fn boundary(cut: u64, top: u64) -> Vec<u64> {
    let mut out = vec![0];
    for value in [cut.wrapping_sub(1), cut, cut.wrapping_add(1), top] {
        if value <= top && !out.contains(&value) {
            out.push(value);
        }
    }
    out.sort_unstable();
    out
}

/// Bit `index` of a big-endian bit string.
pub(crate) fn bit(data: &[u8], index: usize) -> u8 {
    (data[index / 8] >> (7 - index % 8)) & 1
}

pub(crate) fn set_bit(data: &mut [u8], index: usize, value: u8) {
    let mask = 1u8 << (7 - index % 8);
    data[index / 8] &= !mask;
    if value != 0 {
        data[index / 8] |= mask;
    }
}

/// Adds 1 (`delta > 0`) or subtracts 1 from a big-endian number, modulo its width.
pub(crate) fn step(word: &mut [u8], delta: i32) {
    for byte in word.iter_mut().rev() {
        if delta > 0 {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        } else {
            *byte = byte.wrapping_sub(1);
            if *byte != 255 {
                break;
            }
        }
    }
}

mod tests {
    use super::*;

    const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const TWO_BLOCKS: &str = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";
    const MILLION: &str = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";
    // SHA-256 of `expand("coretail-major", 7, ..)` over 9088 bytes, computed with Python's hashlib.
    const EXPANDED: &str = "f86428e969c7bffd3b72993d3afe1157b794c9e8900280d87623cf4cf55e1271";

    fn hex(data: &[u8]) -> String {
        let mut hash = Sha256::new();
        hash.update(data);
        hash.hex()
    }

    #[test]
    fn sha256_standard_vectors() {
        assert_eq!(hex(b""), EMPTY);
        assert_eq!(hex(b"abc"), ABC);
        let message = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        assert_eq!(hex(message), TWO_BLOCKS);
        assert_eq!(hex(&vec![b'a'; 1_000_000]), MILLION);
        // The same message in pieces of uneven length.
        let mut hash = Sha256::new();
        for piece in message.chunks(7) {
            hash.update(piece);
        }
        assert_eq!(hash.hex(), TWO_BLOCKS);
    }

    #[test]
    fn expansion_and_helpers() {
        let mut short = [0u8; 4];
        expand("abc", 0, &mut short);
        assert_eq!(short, [0xaa, 0x6d, 0x11, 0xd0]);
        let mut long = [0u8; 9088];
        expand("coretail-major", 7, &mut long);
        assert_eq!(hex(&long), EXPANDED);
        assert_eq!(boundary(0, 9), [0, 1, 9]);
        assert_eq!(boundary(9, 9), [0, 8, 9]);
        assert_eq!(boundary(5, 9), [0, 4, 5, 6, 9]);
        let mut data = [0u8; 2];
        set_bit(&mut data, 0, 1);
        set_bit(&mut data, 15, 1);
        assert_eq!(data, [0x80, 0x01]);
        assert_eq!((bit(&data, 0), bit(&data, 1)), (1, 0));
        step(&mut data, 1);
        assert_eq!(data, [0x80, 0x02]);
        let mut zero = [0u8; 2];
        step(&mut zero, -1);
        assert_eq!(zero, [0xff, 0xff]);
        step(&mut zero, 1);
        assert_eq!(zero, [0, 0]);
        let mut records = Records::new();
        records.update(b"a");
        records.update(b"bc");
        records.end();
        assert_eq!(records.short, ["ba7816bf"]);
        records.check("abc", ABC);
    }
}
