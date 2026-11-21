#!/usr/bin/env python3
"""Deterministic assembly emitter; no compiler is invoked.

Run: python3 crates/pretzel-4-4/core/generators/gen_assembly.py --check
Use --output-dir DIR to inspect the candidate; see README.md.
The input is a hand-written assembly template, not compiler disassembly.
"""
import argparse
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]

def alias_runs():
    s=(ROOT/'src/ct_alias_sixteen_compact.S').read_text()
    s=s.replace('mov x12, #256\nmadd x8, x2, x12, x1','ldr x8, [x1]\nadd x8, x1, x8\nadd x1, x1, #16',1)
    for ptr,label,region in [('x1','2','A'),('x8','3','B')]:
     start=re.search('^'+label+':\\n',s,re.M).start()
     end=s.index('b.ne '+label+'b',start)+len('b.ne '+label+'b\n')
     old=s[start:end]
     groups=re.findall(r'(ld1 \{[^\n]+\}, \['+ptr+r'\], #\d+\n(?:tbx[^\n]+\n)+)',old)
     assert len(groups)==4
     outer=f'Lpretzel_runs_{region}_outer';table=f'Lpretzel_runs_{region}_table';done=f'Lpretzel_runs_{region}_done'
     body=f'{outer}:\nldp w12, w10, [{ptr}]\nadd {ptr}, {ptr}, #16\nadr x11, {table}\nldrsw x12, [x11, w12, uxtw #2]\nadd x11, x11, x12\nbr x11\n'
     for mask in range(16):
      case=f'Lpretzel_runs_{region}_{mask}'
      body+=case+':\ndup v29.16b, w9\ncmeq v29.16b, v28.16b, v29.16b\norn v30.16b, v27.16b, v29.16b\n'
      body+=''.join(g for j,g in enumerate(groups) if mask&(1<<j))
      body+=f'add w9, w9, #1\nsubs w10, w10, #1\nb.ne {case}\ncmp x9, x2\nb.lo {outer}\nb {done}\n'
     body+='.p2align 2\n'+table+':\n'
     body+=''.join(f'.long Lpretzel_runs_{region}_{mask}-{table}\n' for mask in range(16))
     body+=done+':\n'
     s=s[:start]+body+s[end:]
    return s.encode()


def outputs():
    return {"ct_alias_sixteen_runs.S": alias_runs()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    data = outputs()
    if args.check:
        failures = [name for name, content in data.items() if (ROOT / "src" / name).read_bytes() != content]
        if failures:
            raise SystemExit("Generated assembly drift: " + ", ".join(failures))
        print(f"Generated assembly: {len(data)} files match byte-for-byte")
    else:
        dest = args.output_dir.resolve()
        repo = ROOT.parents[2]
        if dest == repo or repo in dest.parents:
            parser.error("output directory must be outside the source worktree")
        dest.mkdir(parents=True, exist_ok=True)
        for name, content in data.items():
            (dest / name).write_bytes(content)


if __name__ == "__main__":
    main()
