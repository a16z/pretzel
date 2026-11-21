#!/usr/bin/env python3
"""Fixture sets of the Pretzel-(5,5) proposal sampler, generated; no compiler is invoked.

Run from the repository root:
  python3 crates/pretzel-5-5/samplers/generators/gen_proposal_fixtures.py --check
Use --output-dir DIR to write the six generated files for inspection, and --self-test to check
the hash expansion and the hand-built cases; see README.md.

Each set is a list of records: input bytes, then the outputs of the sampler. The inputs follow the
rules in README.md. The outputs here come from an integer model of the sampler, written from the
Rust source; the tests of the proposal crate rebuild the same inputs, run the sampler, and compare
the SHA-256 of the same bytes with the same constants.
"""
import argparse
import hashlib
import re
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE.parent / "proposal" / "src"
REPOSITORY = HERE.parents[3]

# SHA-256 of each generated file. The tests of the proposal crate hold the same constants.
PINS = {
    "coretail-main": "d0b247d20b7a5af394470c75576d825bafbaa81673ef41d2d71a3961199608f4",
    "coretail-middle": "f1818ab0abbe22c2450957caf39eea8d86805437b085de05401d40d0495ecec5",
    "coretail-final": "9a1dc9cf2ca1040109f777893fe1dffb614b3f269eb8653af13d37097f04d98c",
    "coretail-major": "854abe1af9fe8f170935b81a6c0d93fc8894b0b56ba0f637b0b4a1a72bdeec92",
    "leading-alias32": "2df04288385c029cfee00112fd1bcd86aef7cce5de44b013daef46504a127a40",
    "coretail-composite": "520ad041d762fc6a24cef7af0a6fa0868f97cd9b106e00f01ace9eb24ce5887c",
}

# Bytes of one record of each set.
STRIDES = {
    "coretail-main": 8,
    "coretail-middle": 17,
    "coretail-final": 81,
    "coretail-major": 9088 + 1 + 2 * 2560,
    "leading-alias32": 1856 + 1 + 4 * 256,
    "coretail-composite": 10944 + 1 + 4 * 2816,
}

MAJOR_ROWS = 198
LEADING_ROWS = 803
COMPOSITE_ROWS = 218
LEADING_QUEUED = [0, 1, 2, 15, 16, 17, 31, 255, 256]


def expand(label, seed, length):
    """SHA-256 in counter mode: block i is SHA-256(label, one zero byte, seed and i as 32-bit
    little-endian words); the output is the first `length` bytes of block 0, block 1, ..."""
    out = bytearray()
    counter = 0
    while len(out) < length:
        block = label.encode("ascii") + b"\x00" + struct.pack("<II", seed, counter)
        out += hashlib.sha256(block).digest()
        counter += 1
    return bytes(out[:length])


def boundary(cut, top):
    """The values 0, cut - 1, cut, cut + 1 and top that lie in [0, top], increasing, once each."""
    return sorted(set(x for x in (0, cut - 1, cut, cut + 1, top) if 0 <= x <= top))


def bit(data, index):
    return (data[index // 8] >> (7 - index % 8)) & 1


def set_bit(data, index, value):
    mask = 1 << (7 - index % 8)
    data[index // 8] = (data[index // 8] & ~mask) | (mask if value else 0)


class Tables:
    """The public tables the signer path reads, parsed from the sources of the proposal crate."""

    def __init__(self, src):
        self.src = Path(src)
        m = self.rust_bytes("coretail_main_tables.rs", 2 * 3 * 256)
        self.main = [[m[(f * 3 + p) * 256:(f * 3 + p + 1) * 256] for p in range(3)] for f in range(2)]
        self.middle = (self.src / "coretail-middle-planes.bin").read_bytes()
        self.final = (self.src / "coretail-final-planes.bin").read_bytes()
        p = self.rust_bytes("leading_alias32_tables.rs", 5 * 128)
        self.planes = [p[128 * i:128 * (i + 1)] for i in range(5)]
        self.even = (self.src / "lead_even.bin").read_bytes()
        assert (len(self.middle), len(self.final), len(self.even)) == (6144, 125952, 5632)

    def rust_bytes(self, name, count):
        text = (self.src / name).read_text().split("=", 1)[1]
        values = [int(x) for x in re.findall(r"\d+", text)]
        assert len(values) == count, (name, len(values))
        return values

    def main_cut(self, family, column):
        """16-bit cut and alias of the first stage."""
        return self.main[family][0][column] | (self.main[family][1][column] << 8), self.main[family][2][column]

    def mid(self, family, plane, column):
        return self.middle[(0 if family == 0 else 3072) + 256 * plane + column]

    def final_cut(self, level, family, column):
        """40-byte cut and alias of one level of the last stage."""
        base = level * 20992 + (0 if family == 0 else 10496) + column
        return bytes(self.final[base + 256 * p] for p in range(40)), self.final[base + 256 * 40]

    def even_plane(self, column, plane):
        return self.even[(column // 16) * 704 + plane * 16 + column % 16]

    def leading_cut32(self, column):
        return bytes(self.planes[j][column] for j in range(4))

    def leading_cut(self, column):
        """40-byte cut of the leading tie stage."""
        e = self.even_plane
        return bytes([e(column, 0), e(column, 1), e(column, 2)] + [e(column, 7 + p) for p in range(11)]
                     + [e(column, 18 + p) for p in range(26)])


# ---------------------------------------------------------------------------- integer model
def signed(x, sign):
    return -x if sign & 1 else x


def model_core(T, family, column, sign, coin):
    """coretail_main::core16, one lane: (ready, value)."""
    cut, alias = T.main_cut(0 if family == 0 else 1, column)
    resolved = coin != cut or column == alias
    x = column if coin < cut else alias
    return (1, signed(x, sign)) if resolved and x != 255 else (0, 0)


def model_middle(T, meta):
    """coretail_middle::middle16, one lane: (ready, value)."""
    family, main, sign, tail = meta[0], meta[1], meta[2], meta[9]
    coin = bytes(meta[3:9])
    cut = bytes(T.mid(family, p, main) for p in range(6))
    alias = T.mid(family, 6, main)
    main_ready = coin != cut or main == alias
    a = main if (coin < cut or main == alias) else alias
    coin = bytes(meta[10:14])
    cut = bytes(T.mid(family, 7 + p, tail) for p in range(4))
    alias = T.mid(family, 11, tail)
    tail_ready = coin != cut or tail == alias
    b = tail if (coin < cut or tail == alias) else alias
    ready = main_ready and (a != 255 or (tail_ready and b != 255))
    x = b + 255 if a == 255 else a
    return (1, signed(x, sign)) if ready else (0, 0)


def model_final(T, meta, record):
    """coretail_final::final8, one live lane: (failed, value). The sign is not applied."""
    family = meta[0]
    bits = int.from_bytes(record, "big")
    cursor, value, bad, active = 0, 0, False, True
    for level in range(6):
        prefix = 6 if level == 0 else 4 if level == 1 else 0
        window = ((bits << cursor) & ((1 << 512) - 1)).to_bytes(64, "big")
        column = meta[1] if level == 0 else meta[9] if level == 1 else window[0]
        word = []
        for at in range(40):
            if at < prefix:
                word.append(meta[3 + at] if level == 0 else meta[10 + at])
            else:
                word.append(window[at - prefix + (1 if level >= 2 else 0)])
        word = int.from_bytes(bytes(word), "big")
        cut, alias = T.final_cut(level, family, column)
        cut = int.from_bytes(cut, "big")
        common = 320 - (word ^ cut).bit_length()
        full = column == alias
        need = 0 if (full or cut == 0) else max(min(common + 1, 320) - 8 * prefix, 0)
        chosen = column if (full or word < cut) else alias
        if active:
            cursor += need + (8 if level >= 2 else 0)
            if cursor > 512:
                bad = True
                cursor = 512
            if chosen != 255:
                value = 255 * level + chosen
                active = False
    failed = bad or active or value > 1149 + 313 * family
    return failed, (0 if failed else value)


def model_major(T, e):
    """coretail_major::sample: (bad, 2560 values, queued lanes, lanes sent to the last stage,
    results of the last stage as (family, level from 1 to 6, signed value))."""
    out = [0] * 2560
    queue = []
    for n in range(2560):
        family = 1 if n >= 1280 else 0
        sign = (e[2560 + n // 8] >> (n % 8)) & 1
        c0, c1 = e[2880 + 2 * n], e[2881 + 2 * n]
        ready, out[n] = model_core(T, family, e[n], sign, (c0 << 8) | c1)
        if not ready:
            queue.append((n, family, e[n], sign, c0, c1))
    bad = len(queue) > 64
    last = []
    for slot, (n, family, column, sign, c0, c1) in enumerate(queue[:64]):
        at = 8000 + 9 * slot
        meta = [family, column, sign, c0, c1] + list(e[at:at + 9])
        ready, out[n] = model_middle(T, meta)
        if not ready:
            last.append((n, meta))
    bad = bad or len(last) > 8
    deep = []
    for lane, (n, meta) in enumerate(last[:8]):
        failed, value = model_final(T, meta, e[8576 + 64 * lane:8640 + 64 * lane])
        bad = bad or failed
        out[n] = signed(value, meta[2])
        deep.append((meta[0], value // 255 + 1, out[n]))
    if bad:
        out = [0] * 2560
    return bad, out, len(queue), len(last), deep


def model_leading(T, e):
    """leading_alias32::sample: (abort, 256 values, queued lanes)."""
    out = [0] * 256
    abort = False
    queue = []
    for i in range(256):
        column, sign = e[i] >> 1, e[i] & 1
        coin = e[256 + 4 * i:260 + 4 * i]
        cut = T.leading_cut32(column)
        full = column == 0
        ready = full or coin != cut
        take = full or coin < cut
        late = column >= 85
        value = (0 if late else 2 * column) if take else T.planes[4][column]
        out[i] = signed(value, sign) if ready else 0
        abort = abort or (ready and take and late)
        if not ready:
            queue.append(i)
    for slot in range(16):
        if slot < len(queue):
            i = queue[slot]
            column, sign, head = e[i] >> 1, e[i] & 1, e[256 + 4 * i:260 + 4 * i]
        else:
            i, column, sign, head = None, 0, 0, bytes(4)
        word = head + e[1280 + 36 * slot:1316 + 36 * slot]
        info = sum(T.even_plane(column, 3 + j) << (8 * j) for j in range(4))
        take = word < T.leading_cut(column) or bool((info >> 24) & 1)
        value = (info & 2047) if take else ((info >> 11) & 2047)
        if (take and (info >> 22) & 1) or (not take and (info >> 23) & 1):
            abort = True
        if i is not None:
            out[i] = signed(value, sign)
    abort = abort or len(queue) > 16
    if abort:
        out = [0] * 256
    return abort, out, len(queue)


# ---------------------------------------------------------------------------- input rules
def main_inputs(T):
    rows = []
    for family in range(2):
        for column in range(256):
            cut, alias = T.main_cut(family, column)
            if alias == column:
                cut = 0xFFFF
            for coin in boundary(cut, 0xFFFF):
                for sign in range(2):
                    rows.append(bytes([family, column, sign, coin & 255, coin >> 8]))
    return rows


def middle_inputs(T):
    def cuts(family, column, first, count, alias_plane):
        top = (1 << (8 * count)) - 1
        cut = int.from_bytes(bytes(T.mid(family, first + p, column) for p in range(count)), "big")
        if T.mid(family, alias_plane, column) == column:
            cut = top
        return [x.to_bytes(count, "big") for x in boundary(cut, top)]

    rows = []
    for column in range(256):
        for family in range(2):
            tail = (column + 13) % 256
            for main in cuts(family, column, 0, 6, 6):
                for coin in cuts(family, tail, 7, 4, 11):
                    for sign in range(2):
                        rows.append(bytes([family, column, sign]) + main + bytes([tail]) + coin)
            for coin in cuts(family, column, 7, 4, 11):
                for sign in range(2):
                    rows.append(bytes([family, 255, sign]) + bytes(6) + bytes([column]) + coin)
    return rows


def final_tie(T, family, index):
    """Coin equal to the 48-bit prefix of the cut of column 1; the record decides."""
    cut, _ = T.final_cut(0, family, 1)
    s = expand("coretail-final", 4 * family + index, 69)
    return bytes([family, 1, 0]) + cut[:6] + s[:5] + s[5:]


def final_edge(T, family, delta):
    """The 320-bit word is the cut of column 1 plus delta (-1, 0 or 1)."""
    cut, _ = T.final_cut(0, family, 1)
    word = ((int.from_bytes(cut, "big") + delta) % (1 << 320)).to_bytes(40, "big")
    return bytes([family, 1, 0]) + word[:6] + bytes(5) + word[6:] + bytes(30)


def final_chain(T, family, columns):
    """Every word is zero; the record holds only the columns of levels two and later, each at the
    bit position the previous levels leave the cursor at."""
    record = bytearray(64)
    cursor = 0
    for level, column in enumerate(columns):
        prefix = 6 if level == 0 else 4 if level == 1 else 0
        if level >= 2:
            for k in range(8):
                set_bit(record, cursor + k, (column >> (7 - k)) & 1)
            cursor += 8
        cut, alias = T.final_cut(level, family, column)
        if alias != column and any(cut):
            zeros = next(i for i in range(320) if bit(cut, i))
            cursor += max(zeros + 1 - 8 * prefix, 0)
    return bytes([family, columns[0], 0]) + bytes(6) + bytes([columns[1]]) + bytes(4) + bytes(record)


def final_overflow(T, family):
    """Column 255 with the word one step below its cut, then column 1 with the word equal to its
    cut for as long as the record lasts: the cursor passes the end of the record."""
    cut, _ = T.final_cut(0, family, 255)
    word = bytearray(cut)
    last = max(i for i in range(320) if bit(cut, i))
    set_bit(word, last, 0)
    next_cut, _ = T.final_cut(1, family, 1)
    record = bytearray(64)
    record[:34] = word[6:]
    cursor = last + 1 - 48
    for i in range(512 - cursor):
        if 32 + i < 320:
            set_bit(record, cursor + i, bit(next_cut, 32 + i))
    return bytes([family, 255, 0]) + bytes(word[:6]) + bytes([1]) + next_cut[:4] + bytes(record)


def final_chains(family):
    chains = [[255, 254], [255, 255], [255, 255, 254], [255, 255, 255], [255, 255, 255, 254],
              [255, 255, 255, 255]]
    last = [255, 255, 255, 255, 129] if family == 0 else [255, 255, 255, 255, 255, 187]
    return chains + [last]


def final_inputs(T):
    rows = []
    for family in range(2):
        rows += [final_tie(T, family, i) for i in range(4)]
        rows += [final_edge(T, family, delta) for delta in (-1, 0, 1)]
        rows += [final_chain(T, family, columns) for columns in final_chains(family)]
        rows.append(final_overflow(T, family))
    return rows


def final_plain(T):
    """The 28 cases of the last stage that do not fail, in the order of `final_inputs`."""
    rows = final_inputs(T)
    return rows[:14] + rows[15:29]


def major_pending(T, e, count, to_last_stage, first):
    """Every lane resolves at once (column 0), except `count` lanes, 39 apart from lane `first`,
    whose coin equals the 16-bit cut of their column; with `to_last_stage` the next 32 coin bits
    equal the cut as well."""
    e[:2560] = bytes(2560)
    for j in range(count):
        n = first + 39 * j
        family = 1 if n >= 1280 else 0
        column = 1 + j
        cut, _ = T.main_cut(family, column)
        e[n] = column
        e[2880 + 2 * n] = cut >> 8
        e[2881 + 2 * n] = cut & 255
        if to_last_stage:
            for p in range(4):
                e[8000 + 9 * j + p] = T.mid(family, 2 + p, column)


def major_embed(e, case, sign):
    """The first lane of the family of `case` (lane 0 or lane 1280) carries that case of the last
    stage with the given sign: its column, its coin bits and its record. For family 1 the columns
    of lanes 0 to 1279 are set to 0, so that the lane is the first one queued."""
    n = 1280 * case[0]
    e[:n] = bytes(n)
    e[n] = case[1]
    e[2560 + n // 8] = (e[2560 + n // 8] & 0xFE) | sign
    e[2880 + 2 * n:2882 + 2 * n] = case[3:5]
    e[8000:8009] = case[5:14]
    e[8576:8640] = case[14:]


def major_input(T, row):
    e = bytearray(expand("coretail-major", row, 9088))
    if row in (35, 36, 37):
        major_pending(T, e, 28 + row, False, 0)
    elif row in (39, 40, 41):
        major_pending(T, e, row - 32, True, 0)
    elif row in (43, 44):
        major_pending(T, e, row - 36, True, 1280)
    elif row in (55, 69):
        major_embed(e, final_overflow(T, 0 if row == 55 else 1), 0)
    elif 70 <= row < 98:
        case = final_plain(T)[row - 70]
        major_embed(e, case, (row - 70 + case[0]) % 2)
    elif row == 98:
        major_embed(e, final_plain(T)[26], 0)
    return bytes(e)


def leading_edge(T, column, sign, delta):
    word = ((int.from_bytes(T.leading_cut(column), "big") + delta) % (1 << 320)).to_bytes(40, "big")
    e = bytearray(1856)
    e[0] = 2 * column | sign
    e[256:260] = word[:4]
    e[1280:1316] = word[4:]
    return bytes(e)


def leading_queue(T, count):
    """`count` lanes whose 32-bit coin equals the cut of their column; the other lanes hold
    column 0, which resolves at once."""
    e = bytearray(1856)
    if count <= 31:
        lanes = sorted(37 * (j % 7) + 3 * (j // 7) for j in range(count))
    else:
        lanes = list(range(count))
    for i, lane in enumerate(lanes):
        column = 1 + i % 127
        e[lane] = 2 * column | (i % 2)
        e[256 + 4 * lane:260 + 4 * lane] = T.leading_cut32(column)
    e[1280:] = expand("leading-alias32-queue", 0, 576)
    return bytes(e)


def leading_input(T, row):
    if row < 24:
        return expand("leading-alias32", row, 1856)
    if row == 24:
        return bytes(1856)
    if row == 25:
        return bytes([255]) * 1856
    if row < 794:
        i = row - 26
        return leading_edge(T, i // 6, (i % 6) // 3, i % 3 - 1)
    return leading_queue(T, LEADING_QUEUED[row - 794])


def composite_input(T, row):
    if row < 198:
        return expand("coretail-composite", row, 1856) + major_input(T, row)
    leading_row = row - 198 if row < 214 else row + 585
    return leading_input(T, leading_row) + major_input(T, 0)


def combinations(results):
    """The (family, level, sign) of the results; sign is -1, 0 or 1."""
    return set((f, level, (v > 0) - (v < 0)) for _, f, level, v in results)


def coverage(results):
    """Summary of the last-stage results of the rows that do not abort: `results` is a list of
    (row, family, level, value)."""
    values = sorted(set(v for _, _, _, v in results))
    return {
        "results": len(results),
        "rows": len(set(r for r, _, _, _ in results)),
        "family 0": sum(1 for _, f, _, _ in results if f == 0),
        "family 1": sum(1 for _, f, _, _ in results if f == 1),
        "levels": sorted(set(level for _, _, level, _ in results)),
        "least": values[0] if values else None,
        "greatest": values[-1] if values else None,
        "magnitudes of 255 or more": sorted(set(abs(v) for v in values if abs(v) >= 255)),
        "negative of 255 or more": sum(1 for _, _, _, v in results if v <= -255),
        "family, level and sign combinations": len(combinations(results)),
    }


# The last-stage results that the major and composite sets carry to a non-abort output.
MAJOR_COVERAGE = {
    "results": 58,
    "rows": 32,
    "family 0": 29,
    "family 1": 29,
    "levels": [1, 2, 3, 4, 5, 6],
    "least": -1149,
    "greatest": 1462,
    "magnitudes of 255 or more": [509, 510, 764, 765, 1019, 1020, 1149, 1462],
    "negative of 255 or more": 7,
    "family, level and sign combinations": 20,
}


# ---------------------------------------------------------------------------- the six sets
def generate(T):
    """name -> (file bytes, notes)."""
    out = {}
    data = bytearray()
    for row in main_inputs(T):
        ready, value = model_core(T, row[0], row[1], row[2], row[3] | (row[4] << 8))
        data += row + bytes([ready]) + struct.pack("<h", value)
    out["coretail-main"] = (bytes(data), "%d records" % (len(data) // 8))

    data = bytearray()
    for row in middle_inputs(T):
        ready, value = model_middle(T, list(row))
        data += row + bytes([ready]) + struct.pack("<h", value)
    out["coretail-middle"] = (bytes(data), "%d records" % (len(data) // 17))

    data = bytearray()
    failures = 0
    for row in final_inputs(T):
        failed, value = model_final(T, list(row[:14]), row[14:])
        failures += failed
        data += row + bytes([int(failed)]) + struct.pack("<h", value)
    out["coretail-final"] = (bytes(data), "%d records, %d failing" % (len(data) // 81, failures))

    data = bytearray()
    aborts = []
    overflow = []
    major = {}
    deep_results = []
    for row in range(MAJOR_ROWS):
        e = major_input(T, row)
        bad, values, queued, last, deep = model_major(T, e)
        major[row] = (bad, values)
        if not bad:
            deep_results += [(row,) + d for d in deep]
        if bad:
            aborts.append(row)
        if queued > 64 or last > 8:
            overflow.append(row)
        data += e + bytes([int(bad)]) + struct.pack("<2560h", *values)
    out["coretail-major"] = (bytes(data), "%d records, abort rows %s, of which queue overflow %s"
                             % (MAJOR_ROWS, aborts, overflow))
    out["coverage"] = coverage(deep_results)

    data = bytearray()
    aborts = []
    overflow = []
    for row in range(LEADING_ROWS):
        e = leading_input(T, row)
        bad, values, queued = model_leading(T, e)
        if bad:
            aborts.append(row)
        if queued > 16:
            overflow.append(row)
        data += e + bytes([int(bad)]) + struct.pack("<256i", *values)
    out["leading-alias32"] = (bytes(data), "%d records, abort rows %s, of which queue overflow %s"
                              % (LEADING_ROWS, aborts, overflow))

    data = bytearray()
    aborts = []
    for row in range(COMPOSITE_ROWS):
        e = composite_input(T, row)
        a, low, _ = model_leading(T, e[:1856])
        major_row = row if row < 198 else 0
        b, high = major[major_row]
        assert e[1856:] == major_input(T, major_row)
        if a or b:
            aborts.append(row)
            data += e + bytes([1]) + bytes(4 * 2816)
        else:
            data += e + bytes([0]) + struct.pack("<2816i", *(low + high))
    out["coretail-composite"] = (bytes(data), "%d records, abort rows %s" % (COMPOSITE_ROWS, aborts))
    return out


# ---------------------------------------------------------------------------- self-test
def self_test(T):
    # The expansion against direct hashlib calls, and the bit helpers.
    assert expand("abc", 0, 0) == b""
    first = hashlib.sha256(b"abc\x00" + bytes(8)).digest()
    second = hashlib.sha256(b"abc\x00" + bytes(4) + b"\x01\x00\x00\x00").digest()
    assert expand("abc", 0, 40) == first + second[:8]
    assert expand("abc", 0x01020304, 32) == hashlib.sha256(b"abc\x00\x04\x03\x02\x01" + bytes(4)).digest()
    assert expand("abc", 0, 4).hex() == "aa6d11d0", expand("abc", 0, 4).hex()
    data = bytearray(2)
    set_bit(data, 0, 1)
    set_bit(data, 15, 1)
    assert bytes(data) == b"\x80\x01" and bit(data, 0) == 1 and bit(data, 1) == 0
    assert boundary(0, 9) == [0, 1, 9] and boundary(9, 9) == [0, 8, 9] and boundary(5, 9) == [0, 4, 5, 6, 9]

    # The hand-built cases of the last stage do what their names say.
    for family in range(2):
        cap = 1149 + 313 * family
        values = [model_final(T, list(r[:14]), r[14:]) for r in
                  (final_chain(T, family, c) for c in final_chains(family))]
        assert values == [(False, v) for v in (509, 510, 764, 765, 1019, 1020, cap)], values
        edges = [model_final(T, list(r[:14]), r[14:]) for r in
                 (final_edge(T, family, d) for d in (-1, 0, 1))]
        _, alias = T.final_cut(0, family, 1)
        assert edges == [(False, 1), (False, alias), (False, alias)], edges
        row = final_overflow(T, family)
        assert model_final(T, list(row[:14]), row[14:]) == (True, 0)
        for i in range(4):
            row = final_tie(T, family, i)
            failed, value = model_final(T, list(row[:14]), row[14:])
            assert not failed and value in (1, alias)
    rows = final_inputs(T)
    assert len(rows) == 30 and len(set(rows)) == 30 and all(len(r) == 78 for r in rows)

    # The forced rows of the major sampler: queue sizes and outcomes.
    expected = {35: (False, 63, None), 36: (False, 64, None), 37: (True, 65, None),
                39: (False, 7, 7), 40: (False, 8, 8), 41: (True, 9, 9),
                43: (False, 7, 7), 44: (False, 8, 8),
                55: (True, 1, 1), 69: (True, 1, 1)}
    for row, (bad, queued, last) in expected.items():
        got = model_major(T, major_input(T, row))
        assert (got[0], got[2]) == (bad, queued), (row, got[0], got[2], got[3])
        assert last is None or got[3] == last, (row, got[3])

    # Every embedded case of the last stage reaches the output of the major sampler with its sign,
    # except the chain (255, 254) of family 1, which the middle stage already resolves to 509.
    plain = final_plain(T)
    for k, case in enumerate(plain):
        failed, value = model_final(T, list(case[:14]), case[14:])
        sign = (k + case[0]) % 2
        bad, values, _, last, deep = model_major(T, major_input(T, 70 + k))
        assert not failed and not bad
        assert values[1280 * case[0]] == signed(value, sign), (k, value, values[1280 * case[0]])
        first = [d for d in deep if d[2] == signed(value, sign) and d[0] == case[0]]
        assert (len(first) >= 1) == ((value, case[0]) != (509, 1)), (k, value, deep)

    # The forced rows of the leading sampler.
    for k, count in enumerate(LEADING_QUEUED):
        bad, _, queued = model_leading(T, leading_input(T, 794 + k))
        assert (bad, queued) == (count > 16, count), (count, bad, queued)
    assert model_leading(T, leading_input(T, 24))[::2] == (False, 0)
    assert model_leading(T, leading_input(T, 25))[::2] == (False, 0)

    # The model notices a changed input.
    e = bytearray(major_input(T, 0))
    reference = model_major(T, bytes(e))[1]
    e[0] ^= 0x55
    assert model_major(T, bytes(e))[1] != reference

    # The coverage stated in README.md.
    got = generate(T)["coverage"]
    assert got == MAJOR_COVERAGE, got
    print("self-test passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--check", action="store_true", help="compare every generated file with its pinned SHA-256")
    parser.add_argument("--output-dir", type=Path, help="write the generated files here (outside the repository)")
    parser.add_argument("--self-test", action="store_true", help="check the expansion and the hand-built cases")
    parser.add_argument("--record-hashes", choices=sorted(STRIDES), metavar="SET",
                        help="print the first 8 hexadecimal digits of the SHA-256 of every record of one set")
    args = parser.parse_args()
    if not (args.check or args.output_dir or args.self_test or args.record_hashes):
        parser.error("one of --check, --output-dir, --self-test or --record-hashes is required")
    T = Tables(SRC)
    if args.self_test:
        self_test(T)
    if not (args.check or args.output_dir or args.record_hashes):
        return 0
    files = generate(T)
    del files["coverage"]
    if args.record_hashes:
        name = args.record_hashes
        data, stride = files[name][0], STRIDES[name]
        for index in range(len(data) // stride):
            record = data[index * stride:(index + 1) * stride]
            print("%s record %d %s" % (name, index, hashlib.sha256(record).hexdigest()[:8]))
        if not (args.check or args.output_dir):
            return 0
    if args.output_dir:
        target = args.output_dir.resolve()
        if target == REPOSITORY or REPOSITORY in target.parents:
            parser.error("--output-dir must be outside the repository")
        target.mkdir(parents=True, exist_ok=True)
        for name, (data, _) in files.items():
            (target / (name + "-fixtures.bin")).write_bytes(data)
    status = 0
    for name, (data, notes) in files.items():
        digest = hashlib.sha256(data).hexdigest()
        same = digest == PINS[name]
        print("%-19s %8d bytes  %s  %s  %s" % (name, len(data), digest, "ok" if same else "DIFFERENT", notes))
        if args.check and not same:
            status = 1
    if args.check:
        print("check passed" if status == 0 else "check FAILED: a generated file differs from its pinned SHA-256")
    return status


if __name__ == "__main__":
    sys.exit(main())
