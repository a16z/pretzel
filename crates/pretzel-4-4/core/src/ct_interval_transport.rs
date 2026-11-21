const _: () = {
    assert!(
        crate::params::PROPOSAL_SHELL_LO >= 100380 && crate::params::PROPOSAL_SHELL_HI <= 230053
    );
    assert!(crate::params::ENV_NUM == 65612 && crate::params::ENV_DEN == 65536);
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

// SAFETY: these symbols are in `libinterval_transport.a`, which the build script compiles and
// links. `pretzel44_interval_decision` is a C function of `interval-transport.c`. The other five
// are routines of `interval-erased-wrapper.S`: each calls the function of the same name with the
// suffix `_impl`, with the argument registers unchanged (`pretzel44_interval_coarse_step` also
// copies its one stack argument), then stores zero over a fixed range of stack below its frame,
// clears caller-saved registers and the flags, and leaves the callee's result in x0 where the
// function has one. `pretzel44_interval_batch_impl` is in `transport-tables.S` and executes SDOT;
// the other `_impl` functions are C, compiled from `interval-transport.c` and the files it
// includes. They are C and assembly and do not unwind.
// `Prepared::new`, `Prepared::batch` and `Prepared::finish` state the extents their callees use.
// The pointer contract of `pretzel44_interval_prepare_slots` is not stated here: it belongs with
// its one call, in `prepare`. The two functions declared for tests:
// `pretzel44_interval_coarse_step` writes three `u64` at `out`, reads `coeff[5..12]` and six `u64`
// at `raw`, reads and rewrites six rows of eight `u64` at `queue` and the `u64` at `rank`;
// `pretzel44_interval_decision` writes three `u64` at `out` and reads 35 rows of three `u64` at
// `coeff` and six `u64` at `raw`.
extern "C" {
    fn pretzel44_interval_batch(args: *const u64) -> u64;
    #[cfg(test)]
    fn pretzel44_interval_coarse_step(
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
    fn pretzel44_interval_finish_deferred(
        coeff: *const u64,
        b: u64,
        queue: *const u64,
        rank: u64,
    ) -> u64;

    fn pretzel44_interval_prepare_key(out: *mut u64, coarse: *mut i64, b: u64);
    fn pretzel44_interval_prepare_slots(raw: *const u64, out: *mut i64) -> u64;
    #[cfg(test)]
    fn pretzel44_interval_decision(
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
        // `pretzel44_interval_prepare_key_impl` (`interval-transport.c`) with its arguments
        // unchanged and then clears 4096 bytes of stack below its frame. The C function writes 35
        // rows of three `u64` at its first pointer and 12 `i64` at its second, and reads neither
        // before writing: exactly `value.coeff` and `value.coarse`, two distinct fields of a local.
        // It keeps no pointer. Base AArch64 instructions and NEON only.
        unsafe {
            pretzel44_interval_prepare_key(
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
        // (`pretzel44_interval_batch_impl` in `transport-tables.S`, behind its wrapper) reads. It
        // runs 128 slots. Through the addresses in `args` it reads the 128 records of 64 bytes of
        // `slots` (`Positions` holds `SECOND_ROWS = 128`), the 128 entries of `xs`, the seven limbs
        // of `lambda`, `self.coarse[5..12]`, the 128 bytes of `glo` and of `ghi` and the 64 bytes
        // of `packed.high`; it reads and writes the 128 bytes of `idx` and of `sgn8`; it reads and
        // rewrites the six rows of `checks.queue` and `checks.rank`. All of these are borrowed by
        // this function for the whole call, and the four written ones are distinct fields behind
        // exclusive borrows. SDOT needs FEAT_DotProd: the build script calls `require_dot_product`,
        // which refuses a target that does not enable `dotprod`.
        let out = unsafe { pretzel44_interval_batch(owner.as_ptr().cast()) };
        deferred.recorded = 128;
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
            pretzel44_interval_coarse_step(
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
        // `pretzel44_interval_finish_deferred_impl` with its arguments unchanged and then clears
        // 256 bytes of stack below its frame. The C function reads 35 rows of three `u64` at
        // `coeff` and all six rows of eight `u64` at `queue`, whatever `rank` is, and writes
        // nothing through them: exactly `self.coeff` and `checks.queue`. It keeps no pointer.
        unsafe {
            pretzel44_interval_finish_deferred(
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
            pretzel44_interval_decision(
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
    // around `pretzel44_interval_prepare_slots_impl` (`interval-transport.c`); the wrapper
    // does not use `raw` or `out`. Through `raw` the C function only reads, and what
    // it reads is `raw[8 * k]` to `raw[8 * k + 5]` for `k < 128`: words 1 to 6 of every
    // record, the last being `raw[1021]`, word 1022 of the view. `raw` has the alignment of
    // the records. The callee writes `out[0]` to `out[127]`, all of the exclusive borrow
    // `out`, and keeps neither pointer after it returns.
    unsafe { pretzel44_interval_prepare_slots(slots.interval_coin_ptr(), out.as_mut_ptr()) }
}

#[cfg(test)]
mod prepared_contract_tests {
    use super::*;
    #[test]
    fn warm_public_interval_coefficients_match_independent_oracle() {
        let actual = Prepared::new(105500);
        let expected: [[u64; 3]; 35] = [
            [2698792557752, 0, 0],
            [100287282862026, 0, 0],
            [988768040413950, 0, 0],
            [
                18327070800665358729,
                18446744073709551615,
                18446744073709551615,
            ],
            [
                10218253688147641351,
                18446744073709551615,
                18446744073709551615,
            ],
            [
                11987687521933521845,
                18446744073709551602,
                18446744073709551615,
            ],
            [
                10237661263424240977,
                18446744073709551597,
                18446744073709551615,
            ],
            [7862530802020147844, 17249, 0],
            [17689770563626470694, 796542, 0],
            [17731413435061848582, 13391684, 0],
            [
                5169198583824445544,
                18446744073373755600,
                18446744073709551615,
            ],
            [
                3835758646876706944,
                18446744047766774644,
                18446744073709551615,
            ],
            [
                15272851905762574413,
                18446743487876730568,
                18446744073709551615,
            ],
            [12544812880988293066, 3299451274738, 0],
            [13845163537491715254, 552299718858770, 0],
            [4558044837447140966, 12514374289228238, 0],
            [
                11004434938852874315,
                18397294250809878919,
                18446744073709551615,
            ],
            [
                5865898632057887584,
                10145720626500840906,
                18446744073709551615,
            ],
            [
                2705497274198621956,
                13835300146712293615,
                18446744073709551608,
            ],
            [3830188228018104984, 14028506043591408405, 86],
            [14067543570931384938, 13091180928393689819, 4173],
            [11891090125057240338, 8806439998185072132, 17017],
            [
                15514047754764823634,
                6188332179444217437,
                18446744073708408079,
            ],
            [
                4360178589087754531,
                3307003460064543077,
                18446744073697716952,
            ],
            [11438918864301208804, 736250620150062393, 214068031],
            [16778478371273164744, 13007163425141786054, 2512916656],
            [
                10745849871855157877,
                11738548095855137569,
                18446744037008027197,
            ],
            [
                13344734857512833367,
                3136400490380237832,
                18446743900198378937,
            ],
            [6084700187685801311, 14619475829005228065, 4734236527784],
            [
                1103213792779378557,
                13069698460293504561,
                18446714422558863592,
            ],
            [13503006101978089299, 15133235813931486107, 86315845453079],
            [
                9428311809183276135,
                11126694495019000040,
                18446620363332615517,
            ],
            [11744236653817648632, 14300257007466739494, 80087944896362],
            [
                6320245216474421191,
                6093187348215803140,
                18446725958159499539,
            ],
            [7757700482923852519, 4982091576726178871, 610202164175],
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
        let actual = Prepared::new(160000);
        let expected: [[u64; 3]; 35] = [
            [
                18446744073671199925,
                18446744073709551615,
                18446744073709551615,
            ],
            [
                18446744070863972750,
                18446744073709551615,
                18446744073709551615,
            ],
            [
                18446743942136232036,
                18446744073709551615,
                18446744073709551615,
            ],
            [
                18446742400662031264,
                18446744073709551615,
                18446744073709551615,
            ],
            [339667205184218, 0, 0],
            [37419151336499498, 0, 0],
            [2182782537446944302, 0, 0],
            [12911446246657025371, 3, 0],
            [
                2566805877837713465,
                18446744073709551571,
                18446744073709551615,
            ],
            [
                10916227049898405876,
                18446744073709538159,
                18446744073709551615,
            ],
            [
                1746597625659789312,
                18446744073708679868,
                18446744073709551615,
            ],
            [
                5674855280455912297,
                18446744073680324048,
                18446744073709551615,
            ],
            [
                10123295408891928292,
                18446744073656732981,
                18446744073709551615,
            ],
            [8714037231715353038, 53894660612, 0],
            [761470370181286498, 3197851172443, 0],
            [11114761911772552894, 84060589570898, 0],
            [
                11722494223562070536,
                18446219435446488995,
                18446744073709551615,
            ],
            [
                11152114464654140822,
                18311025454822582556,
                18446744073709551615,
            ],
            [
                11017342456522811267,
                13366212836549008864,
                18446744073709551615,
            ],
            [
                1993770871907636517,
                5352840459150352048,
                18446744073709551613,
            ],
            [8612810789957146953, 3754531166777998270, 165],
            [7788161773515768155, 4992509979543853660, 7244],
            [12523469460365521327, 12225019426342926987, 73906],
            [
                4133145155396118343,
                16192731661579679013,
                18446744073706774438,
            ],
            [
                12781198608839880594,
                5521253205312769112,
                18446744073619058450,
            ],
            [
                16620707433208603171,
                18314117699370267406,
                18446744073579976603,
            ],
            [3777214807410592320, 17449027327943649868, 31060907520],
            [27665748358280214, 8067150352381042162, 256375716108],
            [
                8952640724473504583,
                15694316351545044011,
                18446737843437296827,
            ],
            [
                7635968797145260426,
                7001708543166549835,
                18446704529900611319,
            ],
            [5090779180580899396, 12613660078292269577, 959173738545599],
            [
                14863553525014048625,
                15328587166919304485,
                18441951365866689267,
            ],
            [17969966660841464065, 986889190478126434, 8643165850404708],
            [
                15627444708901054014,
                10163647568308416344,
                18441866778605979394,
            ],
            [11293217925413058636, 2960176022849267989, 383065629229430],
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
        let actual = Prepared::new(200000);
        let expected: [[u64; 3]; 35] = [
            [58137, 0, 0],
            [2281882, 0, 0],
            [
                18446744073630254487,
                18446744073709551615,
                18446744073709551615,
            ],
            [
                18446744048820794654,
                18446744073709551615,
                18446744073709551615,
            ],
            [
                18446741388962522545,
                18446744073709551615,
                18446744073709551615,
            ],
            [
                18446555529672823051,
                18446744073709551615,
                18446744073709551615,
            ],
            [
                18438689252844570936,
                18446744073709551615,
                18446744073709551615,
            ],
            [15712529842552355, 0, 0],
            [1405193638069314462, 2, 0],
            [5089032089595534606, 209, 0],
            [558437012431015165, 12315, 0],
            [6894004955491936423, 386348, 0],
            [
                17978613672177117899,
                18446744073702532534,
                18446744073709551615,
            ],
            [
                4370562882755856860,
                18446744071946096512,
                18446744073709551615,
            ],
            [
                8338626980346938685,
                18446743955342630388,
                18446744073709551615,
            ],
            [
                7284207980213632363,
                18446739869700683414,
                18446744073709551615,
            ],
            [
                7623858183973081608,
                18446728525179757233,
                18446744073709551615,
            ],
            [5690957219871283692, 7733044769541055, 0],
            [7727637768522482085, 483604719656631483, 0],
            [5587042322840424048, 13281238074452418457, 0],
            [
                3962442047180390912,
                17671581140580332866,
                18446744073709551612,
            ],
            [
                12199163873274860249,
                1964565990315683764,
                18446744073709550557,
            ],
            [
                10547764509710688120,
                13169697324042818307,
                18446744073709513329,
            ],
            [
                6054689638437094637,
                5169594960852794521,
                18446744073709246353,
            ],
            [12364233373439853596, 18097010637471311978, 22139160],
            [16770167548892818778, 7388931149358116905, 756830602],
            [14464217418901243179, 11760596944734202158, 2664807881],
            [
                18375293240622166907,
                8862245096607012686,
                18446743772091680264,
            ],
            [
                11609630588457208386,
                17441700458336980755,
                18446740051342181680,
            ],
            [2846342006124004297, 6233389201044577908, 59499646447104],
            [7957415327636775865, 6737577688802535058, 812606133794038],
            [
                18124099017099967913,
                16865760241903298264,
                18435289835081919896,
            ],
            [4565681695238712358, 17847018360111905755, 38567563902217634],
            [
                6255410724344771960,
                1141044580601374036,
                18410462081095390188,
            ],
            [1973886398090975808, 6986588990747708473, 4497952744108248],
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
        let actual = Prepared::new(230053);
        let expected: [[u64; 3]; 35] = [
            [
                18446744073709550511,
                18446744073709551615,
                18446744073709551615,
            ],
            [
                18446744073709456232,
                18446744073709551615,
                18446744073709551615,
            ],
            [
                18446744073704043440,
                18446744073709551615,
                18446744073709551615,
            ],
            [
                18446744073653477859,
                18446744073709551615,
                18446744073709551615,
            ],
            [34973173000, 0, 0],
            [5452170536773, 0, 0],
            [513206021033349, 0, 0],
            [32998677740757215, 0, 0],
            [1113965278721835845, 0, 0],
            [
                6503910283752509803,
                18446744073709551613,
                18446744073709551615,
            ],
            [
                16767816666290182064,
                18446744073709550995,
                18446744073709551615,
            ],
            [
                7716472660575856282,
                18446744073709495748,
                18446744073709551615,
            ],
            [
                13813133134724659055,
                18446744073706420899,
                18446744073709551615,
            ],
            [
                6111559118939846786,
                18446744073624348883,
                18446744073709551615,
            ],
            [8023252012456929470, 3577737916, 0],
            [720213194619126224, 601899143453, 0],
            [10307164930793373553, 38802761337200, 0],
            [7624087028742968540, 1334778640437999, 0],
            [
                90542489676540859,
                18446575884669299516,
                18446744073709551615,
            ],
            [
                5196781733122596840,
                15511480353635910784,
                18446744073709551615,
            ],
            [
                17458099616203580850,
                8045117866617271519,
                18446744073709551606,
            ],
            [
                17241369851094986684,
                15984949281614793075,
                18446744073709551363,
            ],
            [14786752015487351089, 14448051331296237962, 1753],
            [76889612969602706, 16324317865391946987, 396195],
            [16831241802638983739, 8747819395418714092, 13108917],
            [901318333296813159, 9768814240025004015, 65604940],
            [
                4102757058728695278,
                4898916376782970157,
                18446744065733381271,
            ],
            [
                14744174339085946091,
                16355986820178782369,
                18446743866295245896,
            ],
            [4353659466385849343, 14700320106987581985, 522719705963],
            [17536731336369279562, 594002376306715138, 78888730414192],
            [2307781630908309077, 15369181237744796782, 206216023195946],
            [
                17036800919961967641,
                11736544326824290653,
                18432619532622032159,
            ],
            [
                14389056855893393130,
                11232306285465037580,
                74302640386106710,
            ],
            [
                4518658751654838799,
                14858023812803258930,
                18349322160844624961,
            ],
            [6227368597541796620, 3842325359696630460, 16103450993170362],
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
