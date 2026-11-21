"""Fail-closed AArch64 stack inventory for a retained release image.

The input is emitted by stack_depth_lldb.py. The direct-call subtotal is NOT
an upper bound when any edge or stack adjustment is unresolved. No runtime
routine, panic path, indirect call, or stack probe has an implicit allowance.
"""
import argparse
import gzip
import json
from pathlib import Path
import re


def inventory(image):
    functions = {int(f['address']): f for f in image['functions']}
    problems = set()
    frames, edges, callsites, probes = {}, {}, [], {}
    for address, function in functions.items():
        # Darwin permits a 128-byte red zone below SP. Charge it at every
        # call-graph vertex, even for functions that never use it.
        frame, callees = 128, set()
        end = address + function['size']
        # LLVM's fixed-page stack probe: compute a target SP, decrement by a
        # fixed page, touch it, and repeat until equality. Authenticate the
        # entire five-instruction shape before replacing one page by its
        # total allocation. Other allocation loops remain unresolved.
        probes[address]=[]
        instructions=function['instructions']
        immediate=r'(0x[0-9a-f]+|\d+)(?:,\s*lsl\s*#(\d+))?'
        for index in range(len(instructions)-4):
            setup,step,touch,compare,latch=instructions[index:index+5]
            start=re.fullmatch(r'(x\d+),\s*sp,\s*#'+immediate,setup['operands'])
            decrement=re.fullmatch(r'sp,\s*sp,\s*#'+immediate,step['operands'])
            if not (setup['mnemonic']=='sub' and start and step['mnemonic']=='sub' and decrement):
                continue
            total=int(start[2],0)<<int(start[3] or 0)
            page=int(decrement[1],0)<<int(decrement[2] or 0)
            if (touch['mnemonic']=='str' and re.fullmatch(r'xzr,\s*\[sp\]',touch['operands'])
                    and compare['mnemonic']=='cmp' and compare['operands']=='sp, '+start[1]
                    and latch['mnemonic']=='b.ne' and latch['operands']==hex(step['address'])
                    and page>0 and total>=page and total%page==0
                    and [x['address'] for x in (setup,step,touch,compare,latch)]==list(range(setup['address'],setup['address']+20,4))):
                frame+=total-page
                probes[address].append(dict(latch=latch['address'],allocation_bytes=total,page_bytes=page,iterations=total//page))
        for instruction in function['instructions']:
            op, args = instruction['mnemonic'], instruction['operands']
            # Sum all downward adjustments. Mutually exclusive allocations
            # are over-counted; never choose only a preferred prologue.
            if op == 'sub' and re.match(r'sp,\s*sp,', args):
                m = re.fullmatch(r'sp,\s*sp,\s*#(0x[0-9a-f]+|\d+)(?:,\s*lsl\s*#(\d+))?', args)
                if m:
                    frame += int(m[1], 0) << int(m[2] or 0)
                else:
                    problems.add((address, 'unresolved SP subtraction: '+args))
            elif re.search(r'\[sp,\s*#-(0x[0-9a-f]+|\d+)\]!', args):
                frame += int(re.search(r'\[sp,\s*#-(0x[0-9a-f]+|\d+)\]!', args)[1], 0)
            elif re.search(r'\[sp\],\s*#-', args):
                problems.add((address, 'negative post-index SP update: '+args))
            elif args.startswith('sp,') and op not in ('add', 'cmp'):
                problems.add((address, 'unresolved SP write: '+op+' '+args))
            elif op == 'add' and args.startswith('sp,') and not re.fullmatch(r'sp,\s*sp,\s*#(?:0x[0-9a-f]+|\d+)(?:,\s*lsl\s*#\d+)?', args):
                problems.add((address, 'unresolved SP restoration: '+args))
            if op in ('blr', 'br', 'blraa', 'braa', 'blrab', 'brab'):
                problems.add((address, 'indirect edge: '+op+' '+args))
            if re.search(r'\[sp,\s*[xw]', args):
                problems.add((address, 'register-indexed SP access: '+args))
            offset = re.search(r'\[sp,\s*#-(0x[0-9a-f]+|\d+)\](?![!])', args)
            if offset and int(offset[1], 0)>128:
                problems.add((address, 'access below Darwin red zone: '+args))
            if op == 'bl' or op == 'b' or op.startswith('b.') or op in ('cbz','cbnz','tbz','tbnz'):
                targets = re.findall(r'0x[0-9a-f]+', args)
                if not targets:
                    problems.add((address, 'unresolved branch: '+op+' '+args))
                else:
                    target = int(targets[-1], 16)
                    if not address <= target < end:
                        callees.add(target)
                        callsites.append(dict(caller=address,instruction=instruction['address'],target=target,
                                              comment=instruction.get('comment','')))
                    elif op == 'bl':
                        problems.add((address, 'recursive/internal call: '+args))
            if op in ('.long', '.word', 'udf'):
                problems.add((address, 'uninterpreted instruction: '+op))
        frames[address], edges[address] = frame, callees
    roots = [a for a, f in functions.items() if 'keygen_with_entropy_unscrubbed' in f['name']]
    if not roots:
        raise ValueError('No private key-generation body in image')
    reached, active, cache = set(), set(), {}
    def walk(address):
        if address not in functions:
            problems.add((address, 'external/unresolved call target'))
            return 0, []
        reached.add(address)
        if address in active:
            problems.add((address, 'recursive call graph'))
            return 0, []
        if address in cache:
            return cache[address]
        active.add(address)
        children = [walk(c) for c in sorted(edges[address])]
        depth, chain = max(children, default=(0, []), key=lambda p: p[0])
        active.remove(address)
        cache[address] = frames[address]+depth, [address]+chain
        return cache[address]
    subtotal, chain = max((walk(a) for a in roots), key=lambda p:p[0])
    relevant = sorted((hex(a), reason) for a, reason in problems if a in reached or a not in functions)
    # A loop containing a downward SP adjustment may allocate repeatedly.
    # Require review rather than treating a per-function sum as its bound.
    for a in reached:
        ins = functions[a]['instructions']
        down = [i['address'] for i in ins if (i['mnemonic']=='sub' and i['operands'].startswith('sp,')) or re.search(r'\[sp,\s*#-.*\]!',i['operands'])]
        for i in ins:
            if i['mnemonic'] == 'b' or i['mnemonic'].startswith('b.') or i['mnemonic'] in ('cbz','cbnz','tbz','tbnz'):
                targets = re.findall(r'0x[0-9a-f]+', i['operands'])
                if targets and a <= int(targets[-1],16) < a+functions[a]['size'] and any(int(targets[-1],16) <= d <= i['address'] for d in down) and i['address'] not in {p['latch'] for p in probes[a]}:
                    relevant.append((hex(a), 'loop contains downward SP adjustment'))
    return dict(status='FAIL' if relevant else 'PASS',
                static_bound_bytes=None if relevant else subtotal,
                direct_call_subtotal_bytes=subtotal,
                subtotal_is_upper_bound=not relevant,
                deepest_chain=[dict(address=hex(a), name=functions[a]['name'], frame_bytes=frames[a]) for a in chain],
                unresolved=relevant, allow_list=[], reachable_functions=len(reached),
                external_edges=[dict(caller=functions[e['caller']]['name'], instruction=hex(e['instruction']),
                                     target=hex(e['target']),comment=e['comment'])
                                for e in callsites if e['caller'] in reached and e['target'] not in functions],
                bounded_stack_probes=[dict(function=functions[a]['name'],**p) for a in sorted(reached) for p in probes[a]],
                red_zone_bytes_per_vertex=128)



# Each cut names one no-return Rust entry. Hash suffixes alone are variable.
# A cut is only admitted at BL or a tail B, never a conditional transfer.
PANIC_CUTS = (
    'alloc::alloc::handle_alloc_error', 'alloc::raw_vec::handle_error',
    'core::panicking::assert_failed', 'core::panicking::panic',
    'core::panicking::panic_bounds_check', 'core::panicking::panic_fmt',
    'core::slice::index::slice_end_index_len_fail',
    'core::slice::index::slice_index_order_fail::do_panic::runtime',
)
# Termination is no-return, but is not silently assigned a passing stack bound.
NORETURN_TERMINATION = {'abort','std::process::abort','std::sys::pal::unix::abort_internal'}

SYSTEM_ALLOWANCES = {name:4096 for name in (
    'getentropy','__error','bzero','memcpy','malloc','free','posix_memalign','realloc',
    'dispatch_semaphore_signal','dispatch_semaphore_wait','dispatch_semaphore_create',
    'dispatch_release','_tlv_atexit','tlv_get_addr')}

def branch_target(ins):
    values=re.findall(r'0x[0-9a-f]+',ins['operands'])
    return int(values[-1],16) if values else None

def canonical(name):
    return re.sub(r'::h[0-9a-f]{16}$','',name)

def shell_gate(ins):
    """Candidate sites of the shell test of key generation in the private body.

    The mask is the OR of two `csetm ..., lo` results. A candidate is the instruction
    directly after an `orr xR, xA, xB` whose sources are the destinations of the two
    nearest preceding `csetm ..., lo`, with straight-line code from the first `csetm`
    to the `orr` and neither destination written again before the `orr`. It is a
    usable site (`taken` is set) only when it tests xR in a known form: `cbz`, `cbnz`,
    `cmp xR, #0` or `tst xR, xR` followed by `b.eq` or `b.ne`, or `cmn xR, #0x1`
    followed by `b.ne`. `taken` says where the branch goes: to the accepted candidate
    or to the rejected one. Every `cmn x8, #0x1` elsewhere is a candidate that is not
    usable. The caller requires exactly one candidate, and requires it to be usable.
    """
    flow=('b','bl','blr','br','ret','cbz','cbnz','tbz','tbnz','udf','brk')
    reads=('cmp','cmn','tst','ccmp','ccmn')
    def written(register,between):
        names=(register,'w'+register[1:])
        for k in between:
            operands=[o.strip() for o in k['operands'].split(',')]
            first=2 if k['mnemonic'].startswith('ldp') or k['mnemonic'] in ('ldxp','ldaxp') else 1
            if k['mnemonic'] not in reads and any(o in names for o in operands[:first]):return True
            if '!' in k['operands'] or '], ' in k['operands']:
                if any(re.search(r'\b'+n+r'\b',k['operands']) for n in names):return True
        return False
    sites=[];anchored=set()
    for j,i in enumerate(ins[:-1]):
        made=re.fullmatch(r'(x\d+), (x\d+), (x\d+)',i['operands']) if i['mnemonic']=='orr' else None
        if not made or made.group(2)==made.group(3):continue
        found=[k for k in range(max(0,j-16),j) if ins[k]['mnemonic']=='csetm'][-2:]
        masks=[re.fullmatch(r'(x\d+), lo',ins[k]['operands']) for k in found]
        if len(masks)!=2 or not all(masks) or {m.group(1) for m in masks}!={made.group(2),made.group(3)}:continue
        if any(k['mnemonic'] in flow or k['mnemonic'].startswith('b.') for k in ins[found[0]:j]):continue
        if any(written(m.group(1),ins[k+1:j]) for k,m in zip(found,masks)):continue
        register=made.group(1);test=ins[j+1];follow=ins[j+2]['mnemonic'] if j+2<len(ins) else ''
        site=dict(compare=j+1,branch=j+1,register=register,taken=None);anchored.add(j+1)
        if test['mnemonic'] in ('cbz','cbnz') and test['operands'].startswith(register+', '):
            site['taken']='accepted' if test['mnemonic']=='cbz' else 'rejected'
        elif ((test['mnemonic']=='cmp' and test['operands'] in (register+', #0x0',register+', #0')) or
              (test['mnemonic']=='tst' and test['operands']==register+', '+register)) and follow in ('b.eq','b.ne'):
            site.update(branch=j+2,taken='accepted' if follow=='b.eq' else 'rejected')
        elif test['mnemonic']=='cmn' and test['operands']==register+', #0x1' and follow=='b.ne':
            site.update(branch=j+2,taken='accepted')
        sites.append(site)
    for j,i in enumerate(ins):
        if i['mnemonic']=='cmn' and i['operands']=='x8, #0x1' and j not in anchored:
            sites.append(dict(compare=j,branch=j,register='x8',taken=None))
    return sites

def shell_retry(ins,root):
    """The retry loop of key generation. PASS means: the body has exactly one candidate shell
    test (see shell_gate) and it is usable; the block of the rejected candidate, read
    linearly up to its first `ret` or unconditional transfer (or up to the accepted target),
    holds a branch back to code before the test; and the code of the loop, from the lowest
    such target to that branch, holds no write to SP and no call of the body itself."""
    sites=shell_gate(ins)
    retry=dict(status='FAIL')
    if len(sites)==1 and sites[0]['taken'] is not None:
        site=sites[0];compare=ins[site['compare']];branch=ins[site['branch']]
        target=branch_target(branch)
        if target is None:return retry
        # The rejected-candidate block: the fall-through before the accepted target, or the
        # code from the rejected target on. A rejected target behind the test is the back edge.
        if site['taken']=='accepted':block=[i for i in ins[site['branch']+1:] if i['address']<target]
        elif target<compare['address']:block=[branch]
        else:block=[i for i in ins if i['address']>=target]
        # It ends at its first return or unconditional transfer; the latch must lie inside.
        for n,i in enumerate(block):
            if i['mnemonic'] in ('ret','b','br','udf','brk') and i is not branch:
                block=block[:n+1];break
        # Search it for the retry latch back into the seed-drawing body.
        jumps=('b','cbz','cbnz','tbz','tbnz')
        latches=[i for i in block if (i['mnemonic'] in jumps or i['mnemonic'].startswith('b.')) and branch_target(i) is not None and branch_target(i)<compare['address']]
        if latches:
            latch=min(latches,key=lambda i:branch_target(i));start=branch_target(latch)
            # The loop: from its start to the latch; when the rejected block lies after the
            # accepted code, from its start to the test and from the rejected target to the latch.
            apart=site['taken']=='rejected' and target>compare['address']
            segment=[i for i in ins if start<=i['address']<=latch['address'] and not (apart and branch['address']<i['address']<target)]
            sp=[i for i in segment if i['operands'].startswith('sp,') and i['mnemonic'] not in ('cmp',) or re.search(r'\[sp,\s*#-.*\]!',i['operands'])]
            recursive=[i for i in segment if i['mnemonic']=='bl' and branch_target(i)==root]
            retry=dict(status='PASS' if not sp and not recursive else 'FAIL',compare=compare,branch=branch,latch=latch,
                loop_start=hex(start),loop_end=hex(latch['address']),sp_adjustments=sp,recursive_calls=recursive,
                argument='The rejected-candidate back edge remains inside the private body; no SP write or recursive call in its loop. The second seed reuses the same frames.')
    return retry

def scoped_analyze(image):
    functions={f['address']:f for f in image['functions']}
    roots=[a for a,f in functions.items() if 'keygen_with_entropy_unscrubbed' in f['name']]
    if not roots:raise ValueError('No private key-generation body in image')
    pending=list(roots);live_functions={};cuts=[];external={};errors=[];udf_sites=[]
    used_cuts=set();normal_pcs={}
    while pending:
        address=pending.pop()
        if address in live_functions:continue
        function=functions[address];instructions={i['address']:i for i in function['instructions']}
        queue=[address];live=set();replace={}
        while queue:
            pc=queue.pop()
            if pc in live:continue
            if pc not in instructions:
                errors.append([hex(pc),'normal control flow leaves the instruction inventory']);continue
            live.add(pc);ins=instructions[pc];op=ins['mnemonic'];target=branch_target(ins)
            if op in ('ret','br','braa','brab','udf','brk'):continue
            branch=op in ('bl','b','cbz','cbnz','tbz','tbnz') or op.startswith('b.')
            if branch and target is not None:
                if target not in instructions:
                    name=functions[target]['name'] if target in functions else ins.get('comment','').removeprefix('symbol stub for: ')
                    cut=canonical(name)
                    if cut in PANIC_CUTS:
                        if op not in ('bl','b'):
                            errors.append([hex(pc),'conditional edge into no-return panic cut'])
                        if any(x['mnemonic'] in ('ret','br','braa','brab') for x in functions[target]['instructions']):
                            errors.append([hex(pc),'cut function has a return or unresolved tail transfer'])
                        used_cuts.add(cut)
                        cuts.append(dict(caller=function['name'],instruction=hex(pc),target=name,
                                         name_pattern=re.escape(cut)+r'::h[0-9a-f]{16}',reason='panic path, outside the guarantee',transfer=op))
                        # This call cannot return to the normal path. Replace
                        # only in the analysis graph, never in the executable.
                        replace[pc]=dict(ins,mnemonic='ret',operands='')
                        continue
                    if target in functions:pending.append(target)
                    elif name in SYSTEM_ALLOWANCES:
                        external[target]=name
                    else:errors.append([hex(pc),'unresolved external '+name])
                elif op!='bl':queue.append(target)
                if op=='b':continue
            queue.append(pc+4)
        normal_pcs[address]=live
        for ins in function['instructions']:
            if ins['mnemonic']=='udf':
                udf_sites.append(dict(function=function['name'],instruction=hex(ins['address']),
                    classification='reachable trap: FAIL' if ins['address'] in live else ('zero trap padding after return/tail transfer' if instructions.get(ins['address']-4,{}).get('mnemonic') in ('ret','b','br') else ('trap padding after no-return termination call' if canonical(instructions.get(ins['address']-4,{}).get('comment','').removeprefix('symbol stub for: ')) in NORETURN_TERMINATION else 'unreachable exceptional-only instruction; normal CFG has no path to this site')),
                    predecessor=instructions.get(ins['address']-4)))
        live_functions[address]=dict(function,instructions=[replace.get(i['address'],i) for i in function['instructions'] if i['address'] in live])
    for address,name in external.items():
        live_functions[address]=dict(address=address,name='SYSTEM::'+name,size=8,
            instructions=[dict(address=address,mnemonic='sub',operands='sp, sp, #3968'),
                          dict(address=address+4,mnemonic='ret',operands='')])
    result=inventory(dict(functions=list(live_functions.values())))
    errors.extend(result['unresolved'])
    # All configured entries must be exercised by this image's normal graph.
    # Do not silently retain stale or excessively broad allowances.
    unused_cuts=sorted(set(PANIC_CUTS)-used_cuts)
    unused_system=sorted(set(SYSTEM_ALLOWANCES)-set(external.values()))
    for name in unused_cuts+unused_system:errors.append([name,'unused allow-list entry'])
    result.update(status='FAIL' if errors else 'PASS',unresolved=errors,
        subtotal_is_upper_bound=not errors,
        static_bound_bytes=None if errors else result['static_bound_bytes'],
        bound_label='static bound with measured allowances for system routines',
        noreturn_cut_validation='Each cut function has no RET or indirect tail transfer; explicit Rust panic/alloc-failure entries cannot return. Conditional incoming transfers fail.',
        scope='Shipped OS entropy through getentropy, no installed panic hook, valid inputs. Custom entropy and panic/unwind coverage are outside the guarantee.',
        cut_edges=cuts,udf_sites=udf_sites,normal_instruction_addresses={hex(a):[hex(p) for p in sorted(ps)] for a,ps in normal_pcs.items()},
        system_allowances=[dict(name=n,stub_address=hex(a),allowance_bytes=4096,
            reason=('Darwin thread-local access thunk. ' if n=='tlv_get_addr' else '')+'System routine has no frame in this image; assumed allowance 4096 bytes. Every observed depth must be at most 2048 bytes; unobserved routines remain explicitly unmeasured') for a,n in sorted(external.items())],
        allow_list=[dict(function=n,name_pattern=re.escape(n),reason='panic path, outside the guarantee',uses=sum(c['target']==n for c in cuts)) for n in sorted({c['target'] for c in cuts})],
        cut_policy_patterns=[re.escape(n)+r'::h[0-9a-f]{16}' for n in PANIC_CUTS],
        indirect_sites=[dict(function=functions[a]['name'],instruction=hex(i['address']),mnemonic=i['mnemonic'],operands=i['operands'],resolution='unresolved: FAIL') for a,pcs in normal_pcs.items() for i in functions[a]['instructions'] if i['address'] in pcs and i['mnemonic'] in ('blr','br','blraa','braa','blrab','brab')],
        unused_allow_list=unused_cuts+unused_system,
        allocator_edges=[dict(stub_address=hex(a),name=n) for a,n in external.items() if n in ('malloc','free','realloc','posix_memalign')])
    body=functions[roots[0]];ins=body['instructions']
    retry=shell_retry(ins,roots[0])
    result['forced_retry_static']=retry
    if retry['status']!='PASS' and len(ins)>100:
        result['status']='FAIL';result['unresolved'].append(['shell retry','loop argument unresolved']);result['static_bound_bytes']=None
    return result


def analyze(image, binary=None):
    from stack_depth_image import MachO
    from stack_depth_resolve import resolve
    macho=MachO(binary,image) if binary else None
    expanded,evidence=resolve(image,macho,PANIC_CUTS)
    result=scoped_analyze(expanded)
    result.update(evidence)
    result['binary_sha256']=image.get('binary_sha256')
    if evidence['resolution_errors']:
        result['unresolved'].extend(evidence['resolution_errors'])
        result.update(status='FAIL',static_bound_bytes=None,subtotal_is_upper_bound=False)
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--binary',type=Path)
    parser.add_argument('--bound', type=int, default=131072)
    parser.add_argument('--margin', type=int, default=32768)
    args=parser.parse_args()
    with gzip.open(args.image, 'rt') as stream:
        result=analyze(json.load(stream),args.binary)
    result.update(bound_bytes=args.bound, margin_bytes=args.margin)
    result['static_margin_assertion']='unresolved' if result['static_bound_bytes'] is None else ('PASS' if result['static_bound_bytes']+args.margin<=args.bound else 'FAIL: static bound plus margin exceeds bound')
    if result['static_bound_bytes'] is not None and result['static_bound_bytes']+args.margin > args.bound:
        result['status']='FAIL'
    args.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
    raise SystemExit(result['status'] != 'PASS')


if __name__ == '__main__':
    main()
