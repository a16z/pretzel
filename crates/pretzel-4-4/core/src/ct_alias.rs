//! Exact paired alias law for the projected CDF. Public table preparation may
//! branch. The signing lookup scans every public block; its private indices
//! select vector-register bytes only.
use crate::ct::{ct_eq_u64, ct_lt_limbs_be, ct_lt_u64, ct_select_u64};
use zeroize::Zeroizing;

/// Exact strict-above mask. Materialize the full subtraction before the
/// single permitted redraw branch. A Boolean combination of less/equal let
/// the compiler distinguish equality among accepted uniforms.
#[inline(always)]
pub(crate) fn above_normalizer(u: &[u64; 3], z: &[u64; 3]) -> u64 {
    #[cfg(target_arch = "aarch64")]
    {
        let mask: u64;
        // SAFETY: register-only full-width subtraction, no memory or stack.
        // The early scratch output cannot overlap unread inputs. The final
        // output is assigned after every input has been consumed. NZCV is
        // intentionally clobbered; no operand affects an instruction address.
        // SAFETY: The aarch64 cfg guards this register-only subtraction chain. Early scratch cannot
        // overlap unread inputs, the late mask is assigned after all inputs, and flag effects are
        // declared.
        unsafe {
            core::arch::asm!(
                "subs {tmp}, {z2}, {u2}",
                "sbcs {tmp}, {z1}, {u1}",
                "sbcs {tmp}, {z0}, {u0}",
                "csetm {mask}, lo",
                z0=in(reg) z[0], z1=in(reg) z[1], z2=in(reg) z[2],
                u0=in(reg) u[0], u1=in(reg) u[1], u2=in(reg) u[2],
                tmp=out(reg) _, mask=lateout(reg) mask,
                options(nomem, nostack),
            );
        }
        mask
    }
}

pub(crate) type AliasWords<const N: usize> = crate::ct_erase::Words<N>;

pub(crate) fn new_words<const N: usize>(len: usize) -> AliasWords<N> {
    crate::ct_erase::Words::new(len)
}

#[cfg(any(test, not(target_arch = "aarch64")))]
type Block = [[u32; 16]; 8];
// The ARM byte-plane path never reads the duplicate word layout. Preserve
// the full layout for portable fallback and independent unit-test oracles.
#[cfg(all(not(test), target_arch = "aarch64"))]
type Blocks = usize;
#[cfg(not(all(not(test), target_arch = "aarch64")))]
type Blocks = Vec<Block>;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Wide([u64; 4]); // Little endian, public preparation only.
impl PartialOrd for Wide {
    fn partial_cmp(&self, b: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(b))
    }
}
impl Ord for Wide {
    fn cmp(&self, b: &Self) -> core::cmp::Ordering {
        self.0.iter().rev().cmp(b.0.iter().rev())
    }
}
impl Wide {
    const ZERO: Self = Self([0; 4]);
    fn word(x: u64) -> Self {
        Self([x, 0, 0, 0])
    }
    fn from_be(x: [u64; 3]) -> Self {
        Self([x[2], x[1], x[0], 0])
    }
    fn be(self) -> [u64; 3] {
        assert_eq!(self.0[3], 0);
        [self.0[2], self.0[1], self.0[0]]
    }
    fn add(self, b: Self) -> Self {
        let mut r = [0; 4];
        let mut carry = 0u128;
        for i in 0..4 {
            let t = self.0[i] as u128 + b.0[i] as u128 + carry;
            r[i] = t as u64;
            carry = t >> 64;
        }
        assert_eq!(carry, 0);
        Self(r)
    }
    fn sub(self, b: Self) -> Self {
        assert!(self >= b);
        let mut r = [0; 4];
        let mut borrow = false;
        for i in 0..4 {
            let (v, a) = self.0[i].overflowing_sub(b.0[i]);
            let (v, c) = v.overflowing_sub(borrow as u64);
            r[i] = v;
            borrow = a | c;
        }
        assert!(!borrow);
        Self(r)
    }
    fn scale(self, k: u32) -> Self {
        assert!(k <= 15);
        let mut r = self;
        for _ in 0..k {
            r = r.add(r);
        }
        r
    }
}
#[derive(Clone, Copy)]
struct Category {
    mass: Wide,
    tag: u64,
}
#[derive(Clone, Copy)]
struct Row {
    threshold: [u64; 3],
    metadata: u64,
}

pub(crate) struct Alias {
    blocks: Blocks,
    /// Byte-plane copy of the same rows: region A holds
    /// bytes 0..15 of every row (limbs 0 and 1 of the threshold), region B
    /// bytes 16..31 (limb 2 and the metadata), each as 256 bytes per public
    /// block of 16 rows: plane j of block b is the 16 bytes j of rows 16b..16b+15.
    planes: Vec<u8>,
    /// Compact layout (30-byte rows): the primary tag is derived from the
    /// public shape (`pairs`, `bounds`), the private row index and a per-row
    /// count of dropped zero-mass pairs; the metadata shrinks to 6 bytes
    /// (alias tag 15 bits, phase k+1, cap k+2, primary flip 1, dropped 8).
    /// Requires the regular Gaussian shape and k <= 10.
    compact: bool,
    pairs: usize,
    bounds: usize,
    k: u32,
}
impl Alias {
    fn prepare_blocks(rows: &[Row]) -> Blocks {
        #[cfg(all(not(test), target_arch = "aarch64"))]
        {
            rows.len().div_ceil(16)
        }
        #[cfg(not(all(not(test), target_arch = "aarch64")))]
        {
            let mut blocks = vec![[[0; 16]; 8]; rows.len().div_ceil(16)];
            for (i, r) in rows.iter().enumerate() {
                for (j, v) in r
                    .threshold
                    .iter()
                    .chain(core::iter::once(&r.metadata))
                    .enumerate()
                {
                    blocks[i / 16][2 * j][i % 16] = *v as u32;
                    blocks[i / 16][2 * j + 1][i % 16] = (*v >> 32) as u32;
                }
            }
            blocks
        }
    }
    #[inline(always)]
    fn block_count(&self) -> usize {
        #[cfg(all(not(test), target_arch = "aarch64"))]
        {
            self.blocks
        }
        #[cfg(not(all(not(test), target_arch = "aarch64")))]
        {
            self.blocks.len()
        }
    }
    /// Unsupported public shapes return `None`. No private
    /// value influences this preparation decision or the resulting layout.
    pub(crate) fn new(bounds: &[[u64; 3]], z: [u64; 3]) -> Option<Self> {
        if bounds.is_empty()
            || bounds.len() % 2 == 0
            || bounds.len() >= 4096
            || !bounds.windows(2).all(|w| w[0] <= w[1])
            || *bounds.last()? > z
        {
            return None;
        }
        let total = Wide::from_be(z).add(Wide::word(1));
        if total.0[3] != 0 {
            return None;
        }
        let mut cats = Vec::new();
        let mut add = |mass: Wide, base: usize, pair: bool, flip: bool, tie: bool| {
            if mass != Wide::ZERO {
                cats.push(Category {
                    mass,
                    tag: base as u64
                        | ((pair as u64) << 12)
                        | ((flip as u64) << 13)
                        | ((tie as u64) << 14),
                });
            }
        };
        add(Wide::from_be(bounds[0]), 0, false, false, false);
        for i in (0..bounds.len().saturating_sub(2)).step_by(2) {
            let lo = Wide::from_be(bounds[i]);
            let mid = Wide::from_be(bounds[i + 1]);
            let hi = Wide::from_be(bounds[i + 2]);
            let a = mid.sub(lo);
            let b = hi.sub(mid);
            if a > b.add(Wide::word(1)) || b > a.add(Wide::word(1)) {
                return None;
            }
            add(hi.sub(lo), i + 1, true, a <= b, true);
        }
        add(
            total.sub(Wide::from_be(*bounds.last()?)),
            bounds.len(),
            false,
            false,
            true,
        );
        let n = cats.len().next_power_of_two();
        let k = n.trailing_zeros();
        if k > 15 {
            return None;
        }
        cats.resize(
            n,
            Category {
                mass: Wide::ZERO,
                tag: 0,
            },
        );
        let mut work: Vec<_> = cats.iter().map(|c| c.mass.scale(k)).collect();
        let mut small: Vec<_> = (0..n).filter(|&i| work[i] < total).collect();
        let mut large: Vec<_> = (0..n).filter(|&i| work[i] >= total).collect();
        let mut rows = vec![
            Row {
                threshold: [0; 3],
                metadata: 0
            };
            n
        ];
        let make = |lo: usize, hi: usize, t: Wide, start: Wide| {
            let len = total.sub(t);
            let cap_limit = Wide::word((2 * n) as u64);
            let cap = if cats[hi].tag & (1 << 14) != 0 && start < cap_limit {
                len.min(cap_limit.sub(start)).0[0]
            } else {
                0
            };
            let phase = start.0[0].wrapping_sub(t.0[0]) & ((2 * n - 1) as u64);
            Row {
                threshold: t.be(),
                metadata: cats[lo].tag | (cats[hi].tag << 15) | (phase << 30) | (cap << (31 + k)),
            }
        };
        while !small.is_empty() && !large.is_empty() {
            let lo = small.pop().unwrap();
            let hi = large.pop().unwrap();
            let t = work[lo];
            let start = work[hi].sub(total.sub(t));
            rows[lo] = make(lo, hi, t, start);
            work[hi] = start;
            if start < total {
                small.push(hi);
            } else {
                large.push(hi);
            }
        }
        for i in small.into_iter().chain(large) {
            assert_eq!(work[i], total);
            rows[i] = make(i, i, total, Wide::ZERO);
        }
        let blocks = Self::prepare_blocks(&rows);
        let (compact, pairs) = {
            // Regular Gaussian shape: category 0 is the centre, categories
            // 1..=P are the pairs with base 2j-1 in order, the last is the tail
            // with base N; nothing was dropped in between.
            // Pairs dropped for zero 192-bit mass (sporadic in the deep tail)
            // shift the base of the later pairs; the shift is stored per row.
            let live = cats.iter().take_while(|c| c.mass != Wide::ZERO).count();
            let pairs = live.saturating_sub(2);
            let regular = live >= 2
                && cats[live..].iter().all(|c| c.mass == Wide::ZERO)
                && cats[0].tag == 0
                && (1..=pairs).all(|j| {
                    let base = cats[j].tag & 4095;
                    cats[j].tag >> 12 & 0b101 == 0b101
                        && base % 2 == 1
                        && base >= 2 * j as u64 - 1
                        && (base - (2 * j as u64 - 1)) / 2 <= 255
                })
                && cats[live - 1].tag == bounds.len() as u64 | (1 << 14);
            (regular && k <= 10, pairs)
        };
        let dropped: Vec<u64> = (0..n)
            .map(|i| {
                if compact && (1..=pairs).contains(&i) {
                    ((cats[i].tag & 4095) - (2 * i as u64 - 1)) / 2
                } else {
                    0
                }
            })
            .collect();
        let planes = Self::planes(&rows, &dropped, k, compact);
        Some(Self {
            blocks,
            planes,
            compact,
            pairs,
            bounds: bounds.len(),
            k,
        })
    }
    /// Byte-plane copy of the rows. Full layout: row bytes = threshold limbs
    /// 0, 1, 2 and the 8-byte metadata (region A 16 planes, region B 16).
    /// Compact layout: region B carries limb 2 and 6 metadata bytes (14 planes).
    fn planes(rows: &[Row], dropped: &[u64], k: u32, compact: bool) -> Vec<u8> {
        if compact {
            return Self::sparse_planes(rows, dropped, k);
        }
        Self::dense_planes(rows, dropped, k, compact)
    }
    fn dense_planes(rows: &[Row], dropped: &[u64], k: u32, compact: bool) -> Vec<u8> {
        let nb = rows.len().div_ceil(16);
        let planes_b = if compact { 14 } else { 16 };
        let mut planes = vec![0u8; nb * 16 * (16 + planes_b)];
        for (i, r) in rows.iter().enumerate() {
            let mut bytes = [0u8; 32];
            for (j, v) in r.threshold.iter().enumerate() {
                bytes[8 * j..8 * j + 8].copy_from_slice(&v.to_le_bytes());
            }
            let meta = if compact {
                let m = r.metadata;
                let flip = (m >> 13) & 1;
                let alias_tag = (m >> 15) & 0x7fff;
                let phase = (m >> 30) & ((2u64 << k) - 1);
                let cap = (m >> (31 + k)) & ((4u64 << k) - 1);
                alias_tag
                    | (phase << 15)
                    | (cap << (16 + k))
                    | (flip << (18 + 2 * k))
                    | (dropped[i] << (19 + 2 * k))
            } else {
                r.metadata
            };
            bytes[24..32].copy_from_slice(&meta.to_le_bytes());
            let (b, l) = (i / 16, i % 16);
            for (j, byte) in bytes.iter().enumerate().take(16 + planes_b) {
                let offset = if j < 16 {
                    b * 256 + j * 16 + l
                } else {
                    nb * 256 + b * 16 * planes_b + (j - 16) * 16 + l
                };
                planes[offset] = *byte;
            }
        }
        planes
    }
    /// Only public all-zero four-plane groups are omitted. The header
    /// bits and all resulting control flow depend solely on the fixed table.
    /// Two passes allocate exactly the encoded size without a dense heap copy.
    fn sparse_planes(rows: &[Row], dropped: &[u64], k: u32) -> Vec<u8> {
        let nb = rows.len().div_ceil(16);
        let block = |region: usize, b: usize| {
            let count = if region == 0 { 16 } else { 14 };
            let mut data = [0u8; 256];
            for lane in 0..16 {
                let i = b * 16 + lane;
                if i >= rows.len() {
                    break;
                }
                let row = rows[i];
                let m = row.metadata;
                let meta = ((m >> 15) & 0x7fff)
                    | (((m >> 30) & ((2u64 << k) - 1)) << 15)
                    | (((m >> (31 + k)) & ((4u64 << k) - 1)) << (16 + k))
                    | (((m >> 13) & 1) << (18 + 2 * k))
                    | (dropped[i] << (19 + 2 * k));
                let mut bytes = [0u8; 32];
                for (j, word) in row
                    .threshold
                    .iter()
                    .chain(core::iter::once(&meta))
                    .enumerate()
                {
                    bytes[8 * j..8 * j + 8].copy_from_slice(&word.to_le_bytes());
                }
                for j in 0..count {
                    data[j * 16 + lane] = bytes[region * 16 + j];
                }
            }
            let mut mask = 0u32;
            let mut size = 16;
            for (j, group) in data[..count * 16].chunks(64).enumerate() {
                if group.iter().any(|&b| b != 0) {
                    mask |= 1 << j;
                    size += group.len();
                }
            }
            (data, count * 16, mask, size)
        };
        #[cfg(target_arch = "aarch64")]
        if nb <= 64 {
            // Every decision here inspects only the immutable public table.
            // Validate the full omission pattern before choosing generated code.
            let mut masks = [0u16; 128];
            for region in 0..2 {
                for b in 0..nb {
                    let (data, n, _, _) = block(region, b);
                    for (j, plane) in data[..n].chunks_exact(16).enumerate() {
                        masks[region * nb + b] |= u16::from(plane.iter().any(|&v| v != 0)) << j;
                    }
                }
            }
            if let Some(&(id, _, expected)) = GENERATED_ALIAS_PATTERNS
                .iter()
                .find(|(_, count, expected)| *count == nb && *expected == &masks[..2 * nb])
            {
                {
                    let orders: &[&[usize]] = &[
                        &[3, 4, 5, 6, 7, 24, 25, 26, 27, 28, 29],
                        &[8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23],
                        &[0, 1, 2],
                    ];
                    let total = 16
                        + expected
                            .iter()
                            .map(|m| m.count_ones() as usize * 16)
                            .sum::<usize>();
                    let mut out = Vec::with_capacity(total);
                    out.resize(16, 0);
                    let mut second = 16;
                    for (region, order) in orders.iter().enumerate() {
                        for b in 0..nb {
                            let (a, _, _, _) = block(0, b);
                            let (bdata, _, _, _) = block(1, b);
                            for &j in *order {
                                let (source, local) =
                                    if j < 16 { (&a, j) } else { (&bdata, j - 16) };
                                let plane = &source[local * 16..local * 16 + 16];
                                if plane.iter().any(|&v| v != 0) {
                                    out.extend_from_slice(plane);
                                }
                            }
                        }
                        if region == 0 {
                            second = out.len();
                        }
                    }
                    out[..8].copy_from_slice(&(second as u64).to_le_bytes());
                    out[8..16].copy_from_slice(&(id | 256).to_le_bytes());
                    return out;
                }
            }
        }
        let run_length = |region, b, mask| {
            let mut count = 1;
            while b + count < nb && block(region, b + count).2 == mask {
                count += 1;
            }
            count
        };
        let mut sizes = [0; 2];
        for region in 0..2 {
            let mut b = 0;
            while b < nb {
                let (_, _, mask, size) = block(region, b);
                let count = run_length(region, b, mask);
                sizes[region] += 16 + count * (size - 16);
                b += count;
            }
        }
        let mut out = Vec::with_capacity(16 + sizes[0] + sizes[1]);
        out.extend_from_slice(&((16 + sizes[0]) as u64).to_le_bytes());
        out.extend_from_slice(&[0u8; 8]);
        for region in 0..2 {
            let mut b = 0;
            while b < nb {
                let mask = block(region, b).2;
                let count = run_length(region, b, mask);
                out.extend_from_slice(&mask.to_le_bytes());
                out.extend_from_slice(&(count as u32).to_le_bytes());
                out.extend_from_slice(&[0u8; 8]);
                for i in b..b + count {
                    let (data, n, actual_mask, _) = block(region, i);
                    assert_eq!(mask, actual_mask);
                    for (j, group) in data[..n].chunks(64).enumerate() {
                        if mask & (1 << j) != 0 {
                            out.extend_from_slice(group);
                        }
                    }
                }
                b += count;
            }
        }
        assert_eq!(out.len(), 16 + sizes[0] + sizes[1]);
        #[cfg(test)]
        {
            let dense = Self::dense_planes(rows, dropped, k, true);
            let mut cursor = 16;
            for region in 0..2 {
                let mut b = 0;
                while b < nb {
                    let mask = u32::from_le_bytes(out[cursor..cursor + 4].try_into().unwrap());
                    let run = u32::from_le_bytes(out[cursor + 4..cursor + 8].try_into().unwrap())
                        as usize;
                    assert!(run > 0 && b + run <= nb);
                    cursor += 16;
                    for i in b..b + run {
                        let count = if region == 0 { 16 } else { 14 };
                        let start = if region == 0 {
                            i * 256
                        } else {
                            nb * 256 + i * 224
                        };
                        for (j, group) in dense[start..start + count * 16].chunks(64).enumerate() {
                            if mask & (1 << j) != 0 {
                                assert_eq!(&out[cursor..cursor + group.len()], group);
                                cursor += group.len();
                            } else {
                                assert!(group.iter().all(|&b| b == 0));
                            }
                        }
                    }
                    b += run;
                }
            }
            assert_eq!(cursor, out.len());
        }
        out
    }

    /// Test hook: rebuild the byte planes in the full 32-byte layout.
    #[cfg(test)]
    pub(crate) fn force_full_layout(&mut self) {
        let rows: Vec<Row> = (0..1usize << self.k)
            .map(|i| {
                let r = self.row(i);
                Row {
                    threshold: [r[0], r[1], r[2]],
                    metadata: r[3],
                }
            })
            .collect();
        self.planes = Self::planes(&rows, &vec![0; rows.len()], self.k, false);
        self.compact = false;
    }
    #[cfg(test)]
    pub(crate) fn is_compact(&self) -> bool {
        self.compact
    }
    /// Sixteen queries against the byte-plane copy: every public block is
    /// scanned twice (regions A and B), each private index selects one byte per
    /// plane inside a vector register. Same outputs as `eight` on the same draws.
    fn sixteen(&self, draws: &[[u64; 4]; 16], out: &mut [[u64; 2]; 16]) {
        let mut indices = Zeroizing::new([0u8; 32]);
        for i in 0..16 {
            let c = (draws[i][3] & self.column_mask()) as u32;
            let bits = 4;
            indices[i] = (c & ((1 << bits) - 1)) as u8;
            indices[16 + i] = (c >> bits) as u8;
        }
        #[cfg(target_arch = "aarch64")]
        // SAFETY: all arrays are initialized and disjoint, the block count is
        // positive and below 256 (bounds.len() < 4096 gives k <= 11), indices
        // are masked to the prepared range, and k, pairs, bounds are public.
        unsafe {
            if let Some(parts) = self.rare_parts() {
                crate::ct_rarequeue::full(&parts, draws, out);
                return;
            }
            if self.compact {
                pretzel44_ct_alias_sixteen_compact(
                    out.as_mut_ptr().cast(),
                    self.planes.as_ptr(),
                    self.block_count(),
                    indices.as_ptr(),
                    draws.as_ptr().cast(),
                    self.k as usize,
                    self.pairs,
                    self.bounds,
                );
            } else {
                pretzel44_ct_alias_sixteen(
                    out.as_mut_ptr().cast(),
                    self.planes.as_ptr(),
                    self.block_count(),
                    indices.as_ptr(),
                    draws.as_ptr().cast(),
                    self.k as usize,
                );
            }
        }
    }
    #[cfg(target_arch = "aarch64")]
    pub(crate) fn rare_parts(&self) -> Option<crate::ct_rarequeue::Parts<'_>> {
        if !self.compact || self.planes.len() < 16 {
            return None;
        }
        let id = u64::from_le_bytes(self.planes[8..16].try_into().unwrap());
        if !(257..=259).contains(&id) {
            return None;
        }
        let offset = u64::from_le_bytes(self.planes[..8].try_into().unwrap()) as usize;
        crate::ct_rarequeue::Parts::new(
            id,
            &self.planes[16..offset],
            &self.planes[offset..],
            self.k,
            self.pairs,
            self.bounds,
        )
    }
    pub(crate) fn column_mask(&self) -> u64 {
        (1 << self.k) - 1
    }
    #[cfg(not(all(not(test), target_arch = "aarch64")))]
    // Called by the portable sixteen-lane path only; test builds compile it and do not call it.
    #[cfg_attr(all(test, target_arch = "aarch64"), allow(dead_code))]
    fn eight(&self, draws: &[[u64; 4]; 8], out: &mut [[u64; 2]; 8]) {
        let indices = Zeroizing::new(core::array::from_fn::<_, 8, _>(|i| {
            (draws[i][3] & self.column_mask()) as u32
        }));
        #[cfg(target_arch = "aarch64")]
        // SAFETY: all arrays are initialized and disjoint, block count is
        // positive, indices are masked to the prepared range, and k is public.
        unsafe {
            pretzel44_ct_alias_eight(
                out.as_mut_ptr().cast(),
                self.blocks.as_ptr(),
                self.block_count(),
                indices.as_ptr(),
                draws.as_ptr().cast(),
                self.k as usize,
            );
        }
    }
    #[cfg(test)]
    pub(crate) fn classify(&self, draws: &[[u64; 4]]) -> AliasWords<2> {
        let mut out = new_words::<2>(draws.len());
        self.classify_into(draws, &mut out);
        out
    }
    /// `classify` into caller-owned erased storage (no allocation).
    pub(crate) fn classify_into(&self, draws: &[[u64; 4]], out: &mut [[u64; 2]]) {
        assert_eq!(draws.len(), out.len());

        for (input, output) in draws.chunks(16).zip(out.chunks_mut(16)) {
            if input.len() == 16 {
                self.sixteen(input.try_into().unwrap(), output.try_into().unwrap());
            } else {
                let mut padded = Zeroizing::new([[0; 4]; 16]);
                padded[..input.len()].copy_from_slice(input);
                let mut result = Zeroizing::new([[0; 2]; 16]);
                self.sixteen(&padded, &mut result);
                output.copy_from_slice(&result[..output.len()]);
            }
        }
    }
    #[cfg(test)]
    pub(crate) fn row(&self, i: usize) -> [u64; 4] {
        core::array::from_fn(|j| {
            self.blocks[i / 16][2 * j][i % 16] as u64
                | ((self.blocks[i / 16][2 * j + 1][i % 16] as u64) << 32)
        })
    }
}

/// Fixed-address scalar specification/fallback. This is independently checked
/// against an original-CDF coupling, including every allocated tie edge.
#[cfg_attr(target_arch = "aarch64", allow(dead_code))]
fn decode(row: [u64; 4], u: [u64; 4], k: u32) -> [u64; 2] {
    let primary = ct_lt_limbs_be(&[u[0], u[1], u[2]], &[row[0], row[1], row[2]]);
    let tag = ct_select_u64(primary, row[3], row[3] >> 15);
    let phase = ((row[3] >> 30) & ((2u64 << k) - 1)) & !primary;
    let parity = (u[2].wrapping_add(phase) >> k) & 1;
    let count = (tag & 4095) + ((parity ^ (tag >> 13)) & ((tag >> 12) & 1));
    let mut diff = Zeroizing::new([0u64; 3]);
    let mut borrow = false;
    for i in (0..3).rev() {
        let (x, a) = u[i].overflowing_sub(row[i]);
        let (x, b) = x.overflowing_sub(borrow as u64);
        diff[i] = x;
        borrow = a | b;
    }
    let cap = (row[3] >> (31 + k)) & ((4u64 << k) - 1);
    let alias_tie = ct_eq_u64(diff[0] | diff[1], 0) & ct_lt_u64(diff[2], cap);
    let primary_tie = ct_eq_u64(u[0] | u[1], 0) & ct_lt_u64(u[2], 2u64 << k);
    [
        count,
        ct_select_u64(primary, primary_tie, alias_tie) & 0u64.wrapping_sub((tag >> 14) & 1),
    ]
}

#[cfg(all(target_arch = "aarch64", target_vendor = "apple"))]
core::arch::global_asm!(
    concat!(
        ".text\n.globl _pretzel44_ct_alias_eight\n.p2align 2\n_pretzel44_ct_alias_eight:\n",
        include_str!("ct_alias_eight.S")
    ),
    options(raw)
);
// SAFETY: contract of `pretzel44_ct_alias_eight`, which the `global_asm!` items above assemble from
// `ct_alias_eight.S` and which is declared for test builds only. It reads `512 * blocks` bytes at
// `table` (one `Block` of 512 bytes per pass), 32 bytes at `indices` (eight `u32`) and 256 bytes at
// `draws` (eight rows of four `u64`), and writes 128 bytes at `out` (eight pairs of `u64`).
// `blocks` must be positive: the loop counts it down and tests it after the first pass. `k` is used
// as a number only. NEON only; d8 to d15 are saved and restored in a 64-byte frame, no other
// callee-saved register is written and no pointer is kept.
#[cfg(target_arch = "aarch64")]
#[cfg(any(test, not(target_arch = "aarch64")))]
unsafe extern "C" {
    fn pretzel44_ct_alias_eight(
        out: *mut u64,
        table: *const Block,
        blocks: usize,
        indices: *const u32,
        draws: *const u64,
        k: usize,
    );
}
#[cfg(all(target_arch = "aarch64", target_vendor = "apple"))]
core::arch::global_asm!(
    concat!(
        ".text\n.globl _pretzel44_ct_alias_sixteen\n.p2align 2\n_pretzel44_ct_alias_sixteen:\n",
        include_str!("ct_alias_sixteen.S")
    ),
    options(raw)
);

#[cfg(all(target_arch = "aarch64", target_vendor = "apple"))]
core::arch::global_asm!(concat!(".text\n.globl _pretzel44_ct_alias_sixteen_compact\n.p2align 2\n_pretzel44_ct_alias_sixteen_compact:\n",include_str!("ct_alias_sixteen_runs.S")), options(raw));

// SAFETY: contract of the two kernels that the `global_asm!` items above assemble from
// `ct_alias_sixteen.S` and from `ct_alias_sixteen_runs.S`. Both read 32 bytes at `indices` and 512
// bytes at `draws` (16 rows of four `u64`) and write 256 bytes at `out` (16 pairs of `u64`). Both
// use `k` as a number only; the compact kernel also takes `pairs` and `bounds`, as numbers only.
// Both use NEON only, save and restore d8 to d15 in a 576-byte frame, write no other callee-saved
// register and keep no pointer.
// `pretzel44_ct_alias_sixteen` reads `512 * blocks` bytes at `planes`: 256 for each block, then 256
// for each block again from `planes + 256 * blocks`. `blocks` must be positive: both loops count it
// down and test it after the first pass.
// `pretzel44_ct_alias_sixteen_compact` reads the run layout that `Alias::sparse_planes` writes when
// it finds no generated pattern. The `u64` at `planes` is the byte offset of the second region; the
// first region starts at byte 16. A region is a sequence of runs: a 16-byte header, whose first
// `u32` is a mask below 16 (it indexes a 16-entry jump table unchecked) and whose second `u32` is a
// positive block count, followed for each block of the run by one 64-byte group per set mask bit
// (bit 3 in the second region is a 32-byte group). The counts of each region must add up to exactly
// `blocks`: the scan of a region stops when the number of blocks read reaches it. `blocks` must be
// at least 1 here too: the first run header of each region is read before any test. `Alias::new`
// gives every table at least one row (the last category, the mass above the last bound, is never
// zero), so `block_count()` is at least 1.
#[cfg(target_arch = "aarch64")]
unsafe extern "C" {
    fn pretzel44_ct_alias_sixteen(
        out: *mut u64,
        planes: *const u8,
        blocks: usize,
        indices: *const u8,
        draws: *const u64,
        k: usize,
    );
    fn pretzel44_ct_alias_sixteen_compact(
        out: *mut u64,
        planes: *const u8,
        blocks: usize,
        indices: *const u8,
        draws: *const u64,
        k: usize,
        pairs: usize,
        bounds: usize,
    );
}

#[cfg(test)]
impl Alias {
    pub(crate) fn reference(&self, u: [u64; 4]) -> [u64; 2] {
        decode(self.row((u[3] & self.column_mask()) as usize), u, self.k)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    fn be(s: &str) -> [u64; 3] {
        assert_eq!(s.len(), 48);
        core::array::from_fn(|i| u64::from_str_radix(&s[16 * i..16 * i + 16], 16).unwrap())
    }
    pub(crate) fn check_original_bounds(name: &str, bounds: &[[u64; 3]], z: [u64; 3]) {
        let mut lines = include_str!("ct_alias_fixtures.txt").lines();
        while let Some(line) = lines.next() {
            let a: Vec<_> = line.split_whitespace().collect();
            if a[0] == "T" && a[1] == name {
                assert_eq!(be(a[2]), z);
                let b: Vec<_> = lines
                    .next()
                    .unwrap()
                    .split_whitespace()
                    .skip(1)
                    .map(be)
                    .collect();
                assert_eq!(b, bounds);
                return;
            }
        }
        panic!("missing original table fixture");
    }
    #[test]
    fn exact_public_rows_and_native_outputs_against_original_cdf_coupling() {
        let mut lines = include_str!("ct_alias_fixtures.txt").lines();
        let mut tables = 0;
        while let Some(line) = lines.next() {
            let a: Vec<_> = line.split_whitespace().collect();
            assert_eq!(a[0], "T");
            let name = a[1];
            let z = be(a[2]);
            let bounds: Vec<_> = lines
                .next()
                .unwrap()
                .split_whitespace()
                .skip(1)
                .map(be)
                .collect();
            let alias = Alias::new(&bounds, z).unwrap();
            let mut rows = 0;
            let mut draws = Vec::new();
            let mut expected = Vec::new();
            for line in lines.by_ref() {
                let a: Vec<_> = line.split_whitespace().collect();
                match a[0] {
                    "R" => {
                        let t = be(a[1]);
                        assert_eq!(
                            alias.row(rows),
                            [t[0], t[1], t[2], u64::from_str_radix(a[2], 16).unwrap()],
                            "{name} row {rows}"
                        );
                        rows += 1;
                    }
                    "Q" => {
                        let u = be(a[2]);
                        draws.push([u[0], u[1], u[2], a[1].parse().unwrap()]);
                        expected.push([
                            a[3].parse().unwrap(),
                            0u64.wrapping_sub(a[4].parse().unwrap()),
                        ]);
                    }
                    "E" => break,
                    _ => panic!("bad fixture"),
                }
            }
            assert_eq!(rows, 1usize << alias.k);
            // Mixed indices exercise routing across every real block and
            // both halves of each eight-lane batch, including the remainder.
            draws.reverse();
            expected.reverse();
            let got = alias.classify(&draws);
            for (i, ((u, r), want)) in draws
                .iter()
                .zip(got.iter())
                .zip(expected.iter())
                .enumerate()
            {
                assert_eq!(alias.reference(*u), *want, "{name} scalar {i}");
                assert_eq!(*r, *want, "{name} native {i}");
            }
            tables += 1;
        }
        assert_eq!(tables, 30);
    }
    /// Randomized coupling check on the three shipping tables: native batch
    /// outputs equal the fixed-address scalar reference on random draws and on
    /// every threshold edge (u = t-1, t, t+1, t+cap-1, t+cap, and the primary
    /// tie edge), for every row, including batch remainders of every length.
    #[test]
    fn native_batches_match_scalar_reference_on_shipping_tables_and_edges() {
        let theta = crate::theta::ThetaCtx::new();
        let mut seed = 0x9e3779b97f4a7c15u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for (w, even) in [
            (crate::params::PROPOSAL_W0, true),
            (crate::params::WS, false),
            (crate::params::WE, false),
        ] {
            let cdt = crate::gauss::Cdt::new(&theta, w, even);
            let (bounds, z) = cdt.ct_tables();
            let mut alias = Alias::new(bounds, z).unwrap();
            assert!(
                alias.is_compact(),
                "shipping tables take the compact layout"
            );
            let n = 1usize << alias.k;
            let mut draws = Vec::new();
            for i in 0..n {
                let row = alias.row(i);
                let t = [row[0], row[1], row[2]];
                let cap = (row[3] >> (31 + alias.k)) & ((4u64 << alias.k) - 1);
                let mut edges = vec![t];
                for delta in [
                    -1i128,
                    1,
                    cap as i128 - 1,
                    cap as i128,
                    cap as i128 + 1,
                    (2i128 << alias.k) - 1,
                    2i128 << alias.k,
                ] {
                    let mut u = t;
                    let mut carry = delta;
                    for k in (0..3).rev() {
                        let v = u[k] as i128 + carry;
                        u[k] = v as u64;
                        carry = v >> 64;
                    }
                    if carry == 0 {
                        edges.push(u);
                    }
                }
                edges.push([0, 0, (next() >> 54).min((2 << alias.k) - 1)]);
                for u in edges {
                    draws.push([u[0], u[1], u[2], i as u64 | (next() << alias.k)]);
                }
                for _ in 0..4 {
                    draws.push([next(), next(), next(), i as u64 | (next() << alias.k)]);
                }
            }
            for layout in 0..2 {
                if layout == 1 {
                    alias.force_full_layout();
                }
                for len in [1usize, 7, 8, 9, 15, 16, 17, 31, 32, 33, draws.len()] {
                    let part = &draws[..len.min(draws.len())];
                    let got = alias.classify(part);
                    for (u, r) in part.iter().zip(got.iter()) {
                        assert_eq!(*r, alias.reference(*u), "w={w} layout={layout} u={u:x?}");
                    }
                }
            }
        }
    }
    #[test]
    fn unsupported_public_shapes_fall_back() {
        assert!(Alias::new(&[], [0; 3]).is_none());
        assert!(Alias::new(&[[0; 3]; 2], [0; 3]).is_none());
        assert!(Alias::new(&[[0, 0, 3], [0, 0, 2], [0, 0, 4]], [0, 0, 5]).is_none());
        assert!(Alias::new(&[[0, 0, 1], [0, 0, 2], [0, 0, 9]], [0, 0, 10]).is_none());
        assert!(Alias::new(&[[0; 3]], [u64::MAX; 3]).is_none());
    }
}

#[cfg(test)]
mod normalizer_tests {
    use super::*;
    #[test]
    fn strict_normalizer_mask_matches_full_integer_order_at_carry_edges() {
        let words = [0, 1, 1u64 << 32, u64::MAX - 1, u64::MAX];
        let mut values = Vec::new();
        for a in words {
            for b in words {
                for c in words {
                    values.push([a, b, c]);
                }
            }
        }
        for u in &values {
            for z in &values {
                assert_eq!(above_normalizer(u, z), 0u64.wrapping_sub((u > z) as u64));
            }
        }
    }
}

include!("ct_alias_generated.rs");

// Test seam: field-by-field comparison of two aliases (test builds only).
#[cfg(test)]
impl Alias {
    pub(crate) fn same_fields(&self, o: &Alias) -> bool {
        self.blocks == o.blocks
            && self.k == o.k
            && same_plane_fields(self, o)
            && same_batch_fields(self, o)
    }
}
#[cfg(test)]
fn same_plane_fields(a: &Alias, b: &Alias) -> bool {
    a.planes == b.planes && a.compact == b.compact && a.pairs == b.pairs && a.bounds == b.bounds
}

#[cfg(test)]
fn same_batch_fields(_a: &Alias, _b: &Alias) -> bool {
    true
}
