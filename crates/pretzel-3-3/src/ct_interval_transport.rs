const _: () = {
    assert!(
        crate::params::PROPOSAL_SHELL_LO >= 80343 && crate::params::PROPOSAL_SHELL_HI <= 181545
    );
    assert!(crate::params::ENV_NUM == 65544 && crate::params::ENV_DEN == 65536);
    assert!(
        crate::params::N == 256
            && crate::params::PROPOSAL_W0 == 9216
            && crate::params::WS == 196
            && crate::params::WE == 121
    );
    let expected = [
        0x1e6a48849f6572a5u64,
        0xf7663bf7f0afda57,
        0xf9a42878e0fbcb58,
        0xffffebe71e0d482a,
    ];
    let mut i = 0;
    while i < 4 {
        assert!(crate::params::THETA_NUM_LIMBS[i] == expected[i]);
        i += 1;
    }
};

// Exact-target Shuttle-style interval transport.
use crate::{ct_slots::Positions, fixed::Fx};
use zeroize::Zeroize;
#[cfg(test)]
use zeroize::Zeroizing;

// SAFETY: these symbols are in `libinterval_transport.a`, which `build.rs` compiles and links.
// `pretzel33_interval_decision` is a C function of `interval-transport.c`. The other five are
// routines of `interval-erased-wrapper.S` (the rank-four file under this crate's symbol prefix):
// each calls the function of the same name with the suffix `_impl`, with the argument registers
// unchanged (`pretzel33_interval_coarse_step` also copies its one stack argument), then stores zero
// over a fixed range of stack below its frame, clears caller-saved registers and the flags, and
// leaves the callee's result in x0 where the function has one. `pretzel33_interval_batch_impl` is
// in `transport-tables.S` and executes SDOT; the other `_impl` functions are C, compiled from
// `interval-transport.c` and the files it includes. They are C and assembly and do not unwind.
// `Prepared::new`, `Prepared::batch` and `Prepared::finish` state the extents their callees use.
// The pointer contract of `pretzel33_interval_prepare_slots` is not stated here: it belongs with
// its one call, in `prepare`. The two functions declared for tests:
// `pretzel33_interval_coarse_step` writes three `u64` at `out`, reads `coeff[5..12]` and six `u64`
// at `raw`, reads and rewrites six rows of eight `u64` at `queue` and the `u64` at `rank`;
// `pretzel33_interval_decision` writes three `u64` at `out` and reads 35 rows of three `u64` at
// `coeff` and six `u64` at `raw`.
extern "C" {
    fn pretzel33_interval_batch(args: *const u64) -> u64;
    #[cfg(test)]
    fn pretzel33_interval_coarse_step(
        out: *mut u64,
        coeff: *const i64,
        b: u64,
        a: i64,
        x: i64,
        raw: *const u64,
        queue: *mut u64,
        rank: *mut u64,
        active: u64,
    );
    fn pretzel33_interval_finish_deferred(
        coeff: *const u64,
        b: u64,
        queue: *const u64,
        rank: u64,
    ) -> u64;

    fn pretzel33_interval_prepare_key(out: *mut u64, coarse: *mut i64, b: u64);
    fn pretzel33_interval_prepare_slots(raw: *const u64, out: *mut i64) -> u64;
    #[cfg(test)]
    fn pretzel33_interval_decision(
        out: *mut u64,
        coeff: *const u64,
        b: u64,
        a: i64,
        x: i64,
        raw: *const u64,
    );
}
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct DeferredChecks {
    queue: [[u64; 8]; 6],
    rank: u64,
}
impl DeferredChecks {
    pub(crate) fn new() -> Self {
        Self {
            queue: [[0; 8]; 6],
            rank: 0,
        }
    }
}
impl Drop for DeferredChecks {
    fn drop(&mut self) {
        self.queue.zeroize();
        self.rank.zeroize();
    }
}
pub(crate) struct Prepared {
    b: u64,
    coeff: [[u64; 3]; 35],
    coarse: [i64; 12],
}
impl Drop for Prepared {
    fn drop(&mut self) {
        self.b.zeroize();
        self.coeff.zeroize();
        self.coarse.zeroize();
    }
}
impl Prepared {
    pub(crate) fn new(b: u64) -> Self {
        let mut value = Self {
            b,
            coeff: [[0; 3]; 35],
            coarse: [0; 12],
        };
        // SAFETY: the wrapper in `interval-erased-wrapper.S` calls
        // `pretzel33_interval_prepare_key_impl` (`interval-transport.c`) with its arguments
        // unchanged and then clears 4096 bytes of stack below its frame. The C function writes 35
        // rows of three `u64` at its first pointer and 12 `i64` at its second, and reads neither
        // before writing: exactly `value.coeff` and `value.coarse`, two distinct fields of a local.
        // It keeps no pointer. Base AArch64 instructions and NEON only.
        unsafe {
            pretzel33_interval_prepare_key(
                value.coeff.as_mut_ptr().cast(),
                value.coarse.as_mut_ptr(),
                b,
            );
        }
        value
    }

    pub(crate) fn batch(
        &self,
        slots: &Positions<'_>,
        xs: &[i64; 128],
        lambda: &Fx,
        abort: u64,
        deferred: &mut crate::ct_deferred::Deferred,
        checks: &mut DeferredChecks,
        packed: &crate::ct_gram_registers::Packed,
    ) -> u64 {
        const _: () = assert!(core::mem::size_of::<usize>() == 8);
        debug_assert_eq!(deferred.recorded, 0);
        let mut args = [
            slots.native_records() as u64,
            xs.as_ptr() as u64,
            lambda.0.as_ptr() as u64,
            self.coarse.as_ptr() as u64,
            deferred.glo.as_ptr() as u64,
            deferred.ghi.as_ptr() as u64,
            packed.high.as_ptr() as u64,
            deferred.idx.as_mut_ptr() as u64,
            deferred.sgn8.as_mut_ptr() as u64,
            checks.queue.as_mut_ptr() as u64,
            (&mut checks.rank as *mut u64) as u64,
            self.b,
            abort,
        ];
        let owner = crate::ct_erase::StackByteGuard::new(&mut args);
        // All fixed extents and the mutually disjoint mutable owners remain borrowed
        // throughout this call. The native wrapper erases its full call depth.
        // SAFETY: `owner` views the 13 words of `args`, aligned for `u64`, which the callee
        // (`pretzel33_interval_batch_impl` in `transport-tables.S`, behind its wrapper) reads. It
        // runs 72 slots. Through the addresses in `args` it reads the first 72 of the 64-byte
        // records of `slots` (`Positions` holds `SECOND_ROWS = 128`), `xs[..72]`, the seven limbs
        // of `lambda`, `self.coarse[5..12]`, the 128 bytes of `glo` and of `ghi` and the 64 bytes
        // of `packed.high`; it reads at most the first 80 bytes of `idx` and of `sgn8` and writes
        // their first 72; it reads and rewrites the six rows of `checks.queue` and `checks.rank`.
        // All of these are borrowed by this function for the whole call, and the four written ones
        // are distinct fields behind exclusive borrows. SDOT needs FEAT_DotProd: `build.rs` calls
        // `require_dot_product`, which refuses a target that does not enable `dotprod`.
        let out = unsafe { pretzel33_interval_batch(owner.as_ptr().cast()) };
        deferred.recorded = 72;
        out
    }

    #[cfg(test)]
    pub(crate) fn decide_deferred(
        &self,
        a: i64,
        x: i64,
        u: &Fx,
        active: u64,
        checks: &mut DeferredChecks,
    ) -> (u64, u64, u64) {
        let mut out = Zeroizing::new([0u64; 3]);
        unsafe {
            pretzel33_interval_coarse_step(
                out.as_mut_ptr(),
                self.coarse.as_ptr(),
                self.b,
                a,
                x,
                u.0.as_ptr(),
                checks.queue.as_mut_ptr().cast(),
                &mut checks.rank,
                active,
            );
        }
        (out[0], out[1], out[2])
    }
    pub(crate) fn finish(&self, checks: &DeferredChecks) -> u64 {
        // SAFETY: the wrapper in `interval-erased-wrapper.S` calls
        // `pretzel33_interval_finish_deferred_impl` with its arguments unchanged and then clears
        // 256 bytes of stack below its frame. The C function reads 35 rows of three `u64` at
        // `coeff` and all six rows of eight `u64` at `queue`, whatever `rank` is, and writes
        // nothing through them: exactly `self.coeff` and `checks.queue`. It keeps no pointer.
        unsafe {
            pretzel33_interval_finish_deferred(
                self.coeff.as_ptr().cast(),
                self.b,
                checks.queue.as_ptr().cast(),
                checks.rank,
            )
        }
    }
    #[cfg(test)]
    pub(crate) fn decide(&self, a: i64, x: i64, u: &Fx) -> (u64, u64, u64) {
        let mut out = Zeroizing::new([0u64; 3]);
        unsafe {
            pretzel33_interval_decision(
                out.as_mut_ptr(),
                self.coeff.as_ptr().cast(),
                self.b,
                a,
                x,
                u.0.as_ptr(),
            );
        }
        (out[0], out[1], out[2])
    }
}
pub(crate) fn prepare(slots: &Positions<'_>, out: &mut [i64; 128]) -> u64 {
    // SAFETY: `Positions` borrows `SECOND_ROWS` = 128 records of `WORDS` = 8 `u64`, and
    // `interval_coin_ptr` is word 1 of their flattened view, a pointer derived from that whole
    // view (128 * 8 = 1024 words). The callee is the wrapper of `interval-erased-wrapper.S`
    // around `pretzel33_interval_prepare_slots_impl` (`interval-transport.c`); the wrapper
    // does not use `raw` or `out`. Through `raw` the C function only reads, and what
    // it reads is `raw[8 * k]` to `raw[8 * k + 5]` for `k < 80`: words 1 to 6 of each of the
    // first 80 records, the last being `raw[637]`, word 638 of the view. `raw` has the
    // alignment of the records. The callee writes `out[0]` to `out[127]`, all of the exclusive
    // borrow `out`, and keeps neither pointer after it returns.
    unsafe { pretzel33_interval_prepare_slots(slots.interval_coin_ptr(), out.as_mut_ptr()) }
}

#[cfg(test)]
mod prepared_contract_tests {
    use super::*;
    #[test]
    fn candidate_interval_coefficients_match_portable_model() {
        let actual = Prepared::new(80343);
        let expected: [[u64; 3]; 35] = [
            [1087852902857649, 0, 0],
            [52419762961362620, 0, 0],
            [910289369665812188, 0, 0],
            [
                17866143757749217882,
                18446744073709551614,
                18446744073709551615,
            ],
            [
                9340592994905748435,
                18446744073709551531,
                18446744073709551615,
            ],
            [
                727070627205822399,
                18446744073709549670,
                18446744073709551615,
            ],
            [14557099706700127267, 8816, 0],
            [7832019222408782387, 1797659, 0],
            [14976097642160592007, 44172937, 0],
            [
                1793605284122923596,
                18446744073642433589,
                18446744073709551615,
            ],
            [
                2369684560187443059,
                18446744044182779948,
                18446744073709551615,
            ],
            [
                5645121233371967667,
                18446743454012199595,
                18446744073709551615,
            ],
            [13033424588424176121, 3245305691995, 0],
            [6672258398745949461, 365234096506743, 0],
            [15072859617371959252, 4548731702344022, 0],
            [
                7454572162599653147,
                18362949022586840511,
                18446744073709551615,
            ],
            [
                5537265530958079247,
                15704897984808225865,
                18446744073709551615,
            ],
            [
                2024610580133924251,
                17435559087655138013,
                18446744073709551615,
            ],
            [4774324678203947494, 2328482000979675085, 44],
            [13908534831153085126, 3632544237413125678, 310],
            [
                10647035068858541380,
                12696856370925674977,
                18446744073709542663,
            ],
            [
                6062541233397499652,
                18325039899403860554,
                18446744073709462335,
            ],
            [6909837605106821298, 5545169140797684644, 1536609],
            [4586126377907705576, 4722671890891957272, 12114165],
            [
                11884219526526015470,
                9847729665390179263,
                18446744073470457223,
            ],
            [
                4553676560807159578,
                11893754172040908063,
                18446744073575581451,
            ],
            [5445992210030832096, 6876388618103186445, 22570300234],
            [
                12412969176309375560,
                5592828930752541053,
                18446743882184512382,
            ],
            [16779917519955220408, 16456800606551741906, 791918869298],
            [
                6897054679253164955,
                18044552957074190013,
                18446742220715188286,
            ],
            [7321395049503714645, 1029276748315941061, 2482421503582],
            [
                1238490929532127210,
                18156931878998700806,
                18446742267580519498,
            ],
            [17786210126852572729, 17811140566351474321, 629336703003],
            [
                8807199020680642144,
                8188501420626034208,
                18446743993999417611,
            ],
            [6168469281631394495, 6222633968419459729, 1547439293],
        ];
        for (a, e) in actual.coeff.iter().zip(expected.iter()) {
            let mut d = [0u64; 3];
            let mut borrow = 0i128;
            for j in 0..3 {
                let x = a[j] as i128 - e[j] as i128 - borrow;
                d[j] = x as u64;
                borrow = (x >> 127) & 1;
            }
            assert!(
                d == [0, 0, 0] || d == [1, 0, 0] || d == [u64::MAX; 3],
                "coefficient mismatch {:?} {:?}",
                a,
                e
            );
        }
        let actual = Prepared::new(80344);
        let expected: [[u64; 3]; 35] = [
            [1087940903411119, 0, 0],
            [52404710214433539, 0, 0],
            [909606505565156798, 0, 0],
            [
                17855001290748099991,
                18446744073709551614,
                18446744073709551615,
            ],
            [
                9559203565919942347,
                18446744073709551531,
                18446744073709551615,
            ],
            [
                17482704949775634480,
                18446744073709549670,
                18446744073709551615,
            ],
            [5951481930325281760, 8836, 0],
            [15890230064803186378, 1797576, 0],
            [2272940925254608184, 44157313, 0],
            [
                1973112200924431034,
                18446744073642077878,
                18446744073709551615,
            ],
            [
                13687496184743769042,
                18446744044183280672,
                18446744073709551615,
            ],
            [
                14067617842884023104,
                18446743454214499499,
                18446744073709551615,
            ],
            [7642894392318805923, 3249200834833, 0],
            [379060678412835714, 365215437797203, 0],
            [12504804165033012736, 4546821683437688, 0],
            [
                13453976957935641873,
                18362927476518892328,
                18446744073709551615,
            ],
            [
                4129086907116133234,
                15705255837115637016,
                18446744073709551615,
            ],
            [
                8830247666525911334,
                17446050394101169550,
                18446744073709551615,
            ],
            [9557802950053202460, 2331909749035937747, 44],
            [7756463486201981051, 1180245333712958035, 310],
            [
                4335791341678686732,
                16027920708543083111,
                18446744073709542662,
            ],
            [
                13412345204362618615,
                10119453703443562068,
                18446744073709462356,
            ],
            [10850488126397966591, 9653399371296981642, 1536785],
            [4096780142372501073, 1891360257790570521, 12111589],
            [
                4669384534858232430,
                884128632648201254,
                18446744073470440228,
            ],
            [
                8217226186230409751,
                7589868067998838165,
                18446744073575857390,
            ],
            [9185663457134559316, 8030677019119437881, 22570424607],
            [
                12905736375204510669,
                5796723854053150962,
                18446743882168061315,
            ],
            [10657760645102087816, 10151859375615440163, 792024736125],
            [
                6360180575935775397,
                13131970391506948148,
                18446742220397699825,
            ],
            [10727996431811323314, 9298880867215950269, 2482928025341],
            [
                11870413622438415008,
                16320715658382435964,
                18446742267158286519,
            ],
            [10981868246880854530, 5483461992204374635, 629501278466],
            [
                16345444146760969891,
                1095139862894151610,
                18446743993976479092,
            ],
            [17402903436759913938, 14748294364609885472, 1547923521],
        ];
        for (a, e) in actual.coeff.iter().zip(expected.iter()) {
            let mut d = [0u64; 3];
            let mut borrow = 0i128;
            for j in 0..3 {
                let x = a[j] as i128 - e[j] as i128 - borrow;
                d[j] = x as u64;
                borrow = (x >> 127) & 1;
            }
            assert!(
                d == [0, 0, 0] || d == [1, 0, 0] || d == [u64::MAX; 3],
                "coefficient mismatch {:?} {:?}",
                a,
                e
            );
        }
        let actual = Prepared::new(120000);
        let expected: [[u64; 3]; 35] = [
            [
                18446743974838519814,
                18446744073709551615,
                18446744073709551615,
            ],
            [
                18446739268087662513,
                18446744073709551615,
                18446744073709551615,
            ],
            [
                18446637771891076697,
                18446744073709551615,
                18446744073709551615,
            ],
            [3617468040137152, 0, 0],
            [466774425192084039, 0, 0],
            [3771966872324181096, 1, 0],
            [18247902358847684430, 24, 0],
            [
                7499363236559910796,
                18446744073709550933,
                18446744073709551615,
            ],
            [
                14244402198233525535,
                18446744073709473575,
                18446744073709551615,
            ],
            [
                15127952848640610031,
                18446744073706569636,
                18446744073709551615,
            ],
            [
                15948218877324316918,
                18446744073674596000,
                18446744073709551615,
            ],
            [3839279493872822530, 2284605788, 0],
            [6507000706510074530, 139593004743, 0],
            [1511798009638884597, 3050064283679, 0],
            [
                8079284236797487234,
                18446716407488159165,
                18446744073709551615,
            ],
            [
                16508767151127540126,
                18443012640902590038,
                18446744073709551615,
            ],
            [
                18249855329378727834,
                18353620529534479896,
                18446744073709551615,
            ],
            [8144386403574056031, 162461058375918208, 0],
            [14416670674467859488, 11101522526500733025, 3],
            [3669887626030863027, 4946112219294867445, 75],
            [
                8762962823301980335,
                17495771777829145399,
                18446744073709551180,
            ],
            [
                18129198097349806555,
                6513023458906782511,
                18446744073709509638,
            ],
            [
                12837077295654416339,
                9381191451889962293,
                18446744073709155106,
            ],
            [9750307373095127320, 5658838455914370168, 10256044],
            [3127177737974581532, 17864926353630354940, 196043046],
            [
                10499394292271746187,
                14444470039785191180,
                18446744072145364211,
            ],
            [
                17345555188983555985,
                12536928652853057625,
                18446744031088073950,
            ],
            [13268911771822602991, 12693389678335573539, 295600105226],
            [16014531756046279148, 9565012640946738757, 4286025591622],
            [
                13141742789561697570,
                5517851831868368204,
                18446686345493360931,
            ],
            [4912350409591892278, 10233614301880848699, 260315171431919],
            [
                8374918721852705731,
                17303486535655141849,
                18446216133846054148,
            ],
            [2976464936389886910, 4997807869588808857, 463248932584239],
            [
                16912032260693768739,
                8956449483020461287,
                18446605643795052481,
            ],
            [5739870004666983126, 5231665396138804858, 6054543083690],
        ];
        for (a, e) in actual.coeff.iter().zip(expected.iter()) {
            let mut d = [0u64; 3];
            let mut borrow = 0i128;
            for j in 0..3 {
                let x = a[j] as i128 - e[j] as i128 - borrow;
                d[j] = x as u64;
                borrow = (x >> 127) & 1;
            }
            assert!(
                d == [0, 0, 0] || d == [1, 0, 0] || d == [u64::MAX; 3],
                "coefficient mismatch {:?} {:?}",
                a,
                e
            );
        }
        let actual = Prepared::new(181544);
        let expected: [[u64; 3]; 35] = [
            [457556, 0, 0],
            [74307570, 0, 0],
            [6503722398, 0, 0],
            [374785561714, 0, 0],
            [10395724293393, 0, 0],
            [
                18446147489904290568,
                18446744073709551615,
                18446744073709551615,
            ],
            [
                18339955751146293233,
                18446744073709551615,
                18446744073709551615,
            ],
            [
                10210713111626040064,
                18446744073709551615,
                18446744073709551615,
            ],
            [
                3477885261865257709,
                18446744073709551595,
                18446744073709551615,
            ],
            [
                16254324395024676806,
                18446744073709551280,
                18446744073709551615,
            ],
            [12389939091428162972, 38172, 0],
            [11298716925897454317, 4126177, 0],
            [13569918102483591852, 215182393, 0],
            [9013882156520851063, 5348059608, 0],
            [
                14697688973672942821,
                18446743946118144057,
                18446744073709551615,
            ],
            [
                14738525166930111378,
                18446724672045677455,
                18446744073709551615,
            ],
            [
                9617048904595687697,
                18445824222958063912,
                18446744073709551615,
            ],
            [
                7741967104834016128,
                18428885117612846211,
                18446744073709551615,
            ],
            [16424145140012576132, 497344699097806723, 0],
            [18169728920935004957, 10673822933962060838, 2],
            [4378930870297584890, 7489813688715669714, 76],
            [16864194103459729790, 12814777155091919338, 162],
            [
                11858227179662805630,
                504429909839991062,
                18446744073709486817,
            ],
            [
                1952852126804709383,
                4828156902467647000,
                18446744073707543223,
            ],
            [
                7706727460290187022,
                17365334981253491986,
                18446744073703640163,
            ],
            [14652858268253453061, 4883583816528138272, 1008902210],
            [2307002855378914311, 7916069005975835298, 18649318904],
            [
                6621500703678102445,
                13190732114854366292,
                18446743910299605998,
            ],
            [
                1659424507533333347,
                1378569394837341616,
                18446737494701445392,
            ],
            [10718813235391833818, 13066606699473239459, 19418778324955],
            [11225834734990502584, 15438041547820631482, 1019728266378613],
            [
                7919052235881728989,
                16474175395365237792,
                18438218656182548368,
            ],
            [4945326670000767644, 14294188899947417329, 21677611838864583],
            [
                8053160043042180433,
                2762152904863583945,
                18430445779014314105,
            ],
            [2714721266197035362, 1080760900799460646, 1657027013553501],
        ];
        for (a, e) in actual.coeff.iter().zip(expected.iter()) {
            let mut d = [0u64; 3];
            let mut borrow = 0i128;
            for j in 0..3 {
                let x = a[j] as i128 - e[j] as i128 - borrow;
                d[j] = x as u64;
                borrow = (x >> 127) & 1;
            }
            assert!(
                d == [0, 0, 0] || d == [1, 0, 0] || d == [u64::MAX; 3],
                "coefficient mismatch {:?} {:?}",
                a,
                e
            );
        }
        let actual = Prepared::new(181545);
        let expected: [[u64; 3]; 35] = [
            [457597, 0, 0],
            [74301238, 0, 0],
            [6502754307, 0, 0],
            [374705928455, 0, 0],
            [10391419993426, 0, 0],
            [
                18446147378163332759,
                18446744073709551615,
                18446744073709551615,
            ],
            [
                18339961741593952952,
                18446744073709551615,
                18446744073709551615,
            ],
            [
                10211711976166679045,
                18446744073709551615,
                18446744073709551615,
            ],
            [
                3549467547164756746,
                18446744073709551595,
                18446744073709551615,
            ],
            [
                899296846612748615,
                18446744073709551281,
                18446744073709551615,
            ],
            [3035146540080860921, 38175, 0],
            [1204050034997098789, 4125916, 0],
            [8195716121935571, 215156455, 0],
            [9745885003189378668, 5346823245, 0],
            [
                9312629852033017399,
                18446743946090178500,
                18446744073709551615,
            ],
            [
                15158152083742040091,
                18446724672650235377,
                18446744073709551615,
            ],
            [
                14410687161869807841,
                18445824305802210188,
                18446744073709551615,
            ],
            [
                10429574573242932677,
                18428888637369601766,
                18446744073709551615,
            ],
            [9226580201333165013, 497405547674339151, 0],
            [4900934016373533007, 10672324491646623401, 2],
            [12283308275867702610, 7364133938126680881, 76],
            [14885045918769660836, 9578884928272358491, 162],
            [
                10554167710995352659,
                13029880876656041477,
                18446744073709486816,
            ],
            [
                10094218344684919655,
                16462481150780737175,
                18446744073707543331,
            ],
            [
                3591727796242392035,
                15232394316043253221,
                18446744073703642981,
            ],
            [16580897954005487485, 14781274511708052317, 1008909030],
            [3477729615898877672, 5729171378037574417, 18648381307],
            [
                8632218720084464105,
                6883577371803276492,
                18446743910286013240,
            ],
            [
                17932624784946065474,
                7747635507777360671,
                18446737494791771278,
            ],
            [9620714528456366693, 8619868356297072062, 19421415722924],
            [15984000555309807957, 10578896541732037257, 1019722958289555],
            [7769673090024362038, 13449377272477037, 18438218482755972080],
            [
                17014036348279562115,
                11087414465220664774,
                21678388596668825,
            ],
            [
                15030969019711526411,
                14865594013404902719,
                18430444988982176474,
            ],
            [12624488751509807842, 3176686654034955988, 1657126011681732],
        ];
        for (a, e) in actual.coeff.iter().zip(expected.iter()) {
            let mut d = [0u64; 3];
            let mut borrow = 0i128;
            for j in 0..3 {
                let x = a[j] as i128 - e[j] as i128 - borrow;
                d[j] = x as u64;
                borrow = (x >> 127) & 1;
            }
            assert!(
                d == [0, 0, 0] || d == [1, 0, 0] || d == [u64::MAX; 3],
                "coefficient mismatch {:?} {:?}",
                a,
                e
            );
        }
    }
}

#[cfg(test)]
#[path = "centered6_tests.rs"]
mod centered6_tests;

#[cfg(test)]
mod prefix80_tests {
    unsafe extern "C" {
        fn pretzel33_interval_prepare_slots_reference(raw: *const u64, out: *mut i64) -> u64;
        fn pretzel33_interval_prepare_slots(raw: *const u64, out: *mut i64) -> u64;
    }
    #[test]
    fn original_success_preserves_prefix() {
        let mut state = 2026092880u64;
        let mut successes = 0;
        for trial in 0..4096 {
            let mut raw = [0u64; 1024];
            for x in &mut raw {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *x = match trial {
                    0 => 0,
                    1 => u64::MAX,
                    2 => 1,
                    3 => 1 << 63,
                    _ => state,
                };
            }
            let mut old = [0x12345678i64; 128];
            let mut new = [0x76543210i64; 128];
            let a = unsafe {
                pretzel33_interval_prepare_slots_reference(raw.as_ptr().add(1), old.as_mut_ptr())
            };
            let b =
                unsafe { pretzel33_interval_prepare_slots(raw.as_ptr().add(1), new.as_mut_ptr()) };
            if a == 0 {
                assert_eq!(b, 0);
                assert_eq!(old[..80], new[..80]);
                successes += 1;
            }
            if b != 0 {
                assert_ne!(a, 0);
            }
            assert!(new[80..].iter().all(|&x| x == 0));
        }
        assert!(successes > 4000);
        println!(
            "prefix of 80 slots: comparisons=4096 successful={}",
            successes
        );
    }
}
