"""Actions-only debugger observation of an UNMODIFIED release executable.

Run inside LLDB's Python interpreter. Software breakpoints and injected public
entropy are instrumentation of this check only. They do not recompile any function.
This is diagnostic evidence, never a substitute for a static upper bound.
"""
import gzip
import hashlib
import json
import os
from pathlib import Path
import struct
import re
import time

import lldb

PAINT=512*1024
CASES=int(os.environ.get('DEPTH_CASES','4096'))
OBSERVE_SYSTEM=os.environ.get('DEPTH_OBSERVE_SYSTEM','true')=='true'


# The same function as in stack_depth_static.py; the unit tests compare the two texts.
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


def run(debugger):
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_OS') != 'macOS':
        raise RuntimeError('Native observation requires macOS Actions')
    out=Path(os.environ['DEPTH_OUTPUT'])
    out.mkdir(parents=True,exist_ok=True)
    binary=Path(os.environ['DEPTH_BINARY'])
    result=dict(status='FAIL', binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                paint_bytes=PAINT, samples=[], failures=[], instrumentation='LLDB software breakpoints and public entropy injection; no source or function-body patch',
                unwind='Outside the depth guarantee; the scrub guard still runs during unwind, with unbounded coverage',
                system_routines={}, forced_shell_retry=False, system_observer_enabled=OBSERVE_SYSTEM,
                seed_retry_coverage=False)
    process=None
    began=None
    def save():
        if began is not None:result['elapsed_progress_seconds']=time.monotonic()-began
        (out/'dynamic.json').write_text(json.dumps(result,indent=2)+'\n')
    try:
        print('STAGE start-target',flush=True)
        debugger.SetAsync(False)
        target=debugger.CreateTarget(str(binary))
        if not target.IsValid():
            raise RuntimeError('Cannot create target')
        module=target.GetModuleAtIndex(0)
        functions=[]
        for symbol in module:
            if symbol.GetType() != lldb.eSymbolTypeCode:
                continue
            start=symbol.GetStartAddress().GetFileAddress()
            end=symbol.GetEndAddress().GetFileAddress()
            if end <= start or end-start > 4*1024*1024:
                continue
            instructions=[]
            for ins in symbol.GetInstructions(target):
                data=ins.GetData(target)
                err=lldb.SBError()
                raw=data.ReadRawData(err,0,data.GetByteSize())
                if not err.Success():
                    raise RuntimeError(str(err))
                instructions.append(dict(address=ins.GetAddress().GetFileAddress(),mnemonic=ins.GetMnemonic(target),operands=ins.GetOperands(target),comment=ins.GetComment(target),bytes=raw.hex()))
            functions.append(dict(name=symbol.GetName(),address=start,size=end-start,instructions=instructions,
                                  function_bytes_sha256=hashlib.sha256(bytes.fromhex(''.join(i['bytes'] for i in instructions))).hexdigest()))
        with gzip.open(out/'image.json.gz','wt') as stream:
            json.dump(dict(binary_sha256=result['binary_sha256'],functions=functions),stream)
        print('STAGE image-inventory-done',flush=True)
        bodies=[f for f in functions if 'keygen_with_entropy_unscrubbed' in f['name']]
        scrubs=[f for f in functions if 'ct_erase' in f['name'] and 'scrub_stack' in f['name']]
        erasers=[f for f in functions if f['name'].lstrip('_')=='pretzel55_ct_erase_words']
        unwraps=[f for f in functions if 'core::result::unwrap_failed' in f['name'] or 'unwrap_failed' in f['name']]
        if len(bodies)!=1 or not scrubs or len(erasers)!=1:
            raise RuntimeError('Ambiguous body/scrub/eraser symbols: '+str([len(bodies),len(scrubs),len(erasers)]))
        result['private_body_sha256']=bodies[0]['function_bytes_sha256']
        result['identity']='Observed and shipped body are the same symbol in the same retained executable; its file bytes are hashed before launch.'
        if os.environ.get('DEPTH_INVENTORY_ONLY')=='true':
            result['observation_state']='NOT RUN: image inventory for static preflight'
            return
        if CASES < (31 if OBSERVE_SYSTEM else 4096):
            raise RuntimeError('Campaign smaller than required full/subset minimum')
        def breakpoint(file_address):
            return target.BreakpointCreateBySBAddress(target.ResolveFileAddress(file_address))
        body_bp=breakpoint(bodies[0]['address'])
        scrub_bps=[breakpoint(f['address']) for f in scrubs]
        for bp in scrub_bps:bp.SetEnabled(False)
        erase_bp=breakpoint(erasers[0]['address']); erase_bp.SetEnabled(False)
        # Observe every real call, including entropy before public-output injection.
        system_names={'getentropy','__error','bzero','memcpy','malloc','free','realloc','posix_memalign',
                      'dispatch_semaphore_signal','dispatch_semaphore_wait','dispatch_semaphore_create',
                      'dispatch_release','_tlv_atexit'}
        system_stubs={}
        for f in functions:
            for ins in f['instructions']:
                comment=ins.get('comment','')
                if comment.startswith('symbol stub for: '):
                    name=comment.split(': ',1)[1]
                    if name in system_names:
                        address=int(ins['operands'],16)
                        system_stubs[address]=name
        tls_sites=set()
        if OBSERVE_SYSTEM:
            static=json.loads(Path(os.environ['DEPTH_STATIC']).read_text())
            if static['binary_sha256']!=result['binary_sha256']:
                raise RuntimeError('Static TLS evidence belongs to a different image')
            for entry in static['indirect_resolutions']:
                if entry['resolution']=='system routine tlv_get_addr':
                    address=int(entry['instruction'],16)
                    system_stubs[address]='tlv_get_addr';tls_sites.add(address)
        # System stubs are installed only after the initial private-body stop.
        # Resolving them while dyld is launching can stall LLDB.
        system_bps={}
        result['system_probed_stubs']=[dict(address=hex(a),name=n) for a,n in sorted(system_stubs.items())]
        entropy_bp=target.BreakpointCreateByName('getentropy'); entropy_bp.SetEnabled(False)
        # The unique opaque shell mask is tested once: any nonzero value rejects the
        # candidate. Force its register to all ones once, immediately before the
        # instruction that tests it. No instruction bytes change.
        sites=shell_gate(bodies[0]['instructions'])
        if len(sites)!=1 or sites[0]['taken'] is None:raise RuntimeError('Shell compare is not unique or not recognized')
        shell_compare=bodies[0]['instructions'][sites[0]['compare']];shell_register=sites[0]['register']
        retry_bp=breakpoint(shell_compare['address']);retry_bp.SetEnabled(False)
        result['forced_retry_compare_file_address']=hex(shell_compare['address'])
        error_bps=[breakpoint(f['address']) for f in unwraps]
        for bp in error_bps:bp.SetEnabled(False)
        command=lldb.SBCommandReturnObject()
        debugger.GetCommandInterpreter().HandleCommand('settings set target.disable-aslr false',command)
        print('STAGE launch',flush=True)
        process=target.LaunchSimple([str(CASES+4)],None,str(out))
        print('STAGE launch-returned',flush=True)
        active=None
        after_bp=None
        returned_bp=None
        system_active=None
        system_return_bp=None
        system_return_bps={}
        began=time.monotonic()
        def reg(frame,name):
            return frame.FindRegister(name).GetValueAsUnsigned()
        def read(address,size):
            err=lldb.SBError(); value=process.ReadMemory(address,size,err)
            if not err.Success() or len(value)!=size:
                raise RuntimeError('Stack read failed: '+str(err))
            return value
        def write(address,data):
            err=lldb.SBError(); count=process.WriteMemory(address,data,err)
            if not err.Success() or count!=len(data):
                raise RuntimeError('Memory write failed: '+str(err))
        def system_handler(frame,location,internal_dict=None):
            nonlocal system_active,system_return_bp
            ident=location.GetBreakpoint().GetID()
            result['system_breakpoint_stops']=result.get('system_breakpoint_stops',0)+1
            if result['system_breakpoint_stops']%100==0:save()
            try:
                if system_return_bp is not None and system_return_bp.GetID()==ident:
                    call=system_active
                    data=read(call['low'],call['bytes'])
                    changed=[j for j in range(0,len(data),8) if data[j:j+8]!=call['pattern']]
                    depth=call['sp']-(call['low']+min(changed)) if changed else 0
                    # Restore old paint/dead-frame bytes only where the call left
                    # our fresh paint intact. Keep actual system writes so the
                    # enclosing body's high-water observation includes them.
                    merged=bytearray(data)
                    for j in range(0,len(data),8):
                        if data[j:j+8]==call['pattern']:merged[j:j+8]=call['before'][j:j+8]
                    write(call['low'],bytes(merged))
                    item=result['system_routines'].setdefault(call['name'],dict(allowance_bytes=4096,observed_max_depth_bytes=0,calls=0,deepest_entry_sp=None,cases=[]))
                    item['calls']+=1
                    if depth>=item['observed_max_depth_bytes']:
                        item['observed_max_depth_bytes']=depth;item['deepest_entry_sp']=call['sp']
                    if active['case'] not in item['cases']:item['cases'].append(active['case'])
                    if depth>2048 and not item.get('failed'):
                        item['failed']=True;result['failures'].append('System routine '+call['name']+' exceeded half its 4096-byte allowance: '+str(depth));save()
                    system_return_bp.SetEnabled(False);system_return_bp=None;system_active=None
                    if call['name']=='getentropy':
                        count,pointer=call['count'],call['pointer']
                        request=len(active['entropy_requests'])
                        if active['case']==CASES+2 and request==2:
                            value=frame.EvaluateExpression('*(int *)__error() = 5')
                            if value.GetError().Fail():raise RuntimeError('Cannot set EIO')
                            if not frame.FindRegister('x0').SetValueFromCString(str(2**64-1)):raise RuntimeError('Cannot inject entropy failure')
                            active['entropy_failure']=True
                        elif active['case']>0:
                            seed=struct.pack('<QQ',active['case'],request)
                            write(pointer,hashlib.shake_256(b'pretzel-stack-depth-v1'+seed).digest(count))
                            if not frame.FindRegister('x0').SetValueFromCString('0'):raise RuntimeError('Cannot inject entropy success')
                        active['entropy_requests'].append(count)
                    for ident in system_bps:target.FindBreakpointByID(ident).SetEnabled(OBSERVE_SYSTEM)
                elif ident in system_bps and active is not None:
                    file_address,name=system_bps[ident]
                    sp=reg(frame,'sp');size=8192;low=sp-size
                    if low<active['paint_low']:raise RuntimeError('System probe outside enclosing paint')
                    pattern=hashlib.sha256((name+str(active['case'])+str(sp)).encode()).digest()[:8]
                    system_active=dict(name=name,sp=sp,low=low,bytes=size,pattern=pattern,before=read(low,size),count=reg(frame,'x1'),pointer=reg(frame,'x0'))
                    write(low,pattern*(size//8))
                    for bid in system_bps:target.FindBreakpointByID(bid).SetEnabled(False)
                    return_pc=frame.GetPC()+4 if file_address in tls_sites else reg(frame,'lr')
                    if return_pc not in system_return_bps:
                        raise RuntimeError('System return site absent from static caller inventory: '+hex(return_pc))
                    system_return_bp=system_return_bps[return_pc]
                    system_return_bp.SetEnabled(True)
                return False
            except Exception as error:
                result['callback_error']=str(error)
                result['failures'].append('System callback failed: '+str(error));save()
                return True
        lldb._pretzel_depth_system_handler=system_handler
        # Installing script callbacks from inside an active callback corrupts
        # LLDB's autogenerated wrapper cleanup. Prepare every possible direct
        # caller of a stub or tail forwarder, plus indirect-call returns, here.
        tail_targets=set(system_stubs)
        def branch_destination(ins):
            values=re.findall(r'0x[0-9a-f]+',ins['operands'])
            return int(values[-1],16) if values else None
        while True:
            old_size=len(tail_targets)
            for f in functions:
                if any((i['mnemonic']=='b' or i['mnemonic'].startswith('b.') or i['mnemonic'] in ('cbz','cbnz','tbz','tbnz')) and branch_destination(i) in tail_targets for i in f['instructions']):
                    tail_targets.add(f['address'])
            if len(tail_targets)==old_size:break
        for f in functions:
            for ins in f['instructions']:
                if (ins['mnemonic']=='bl' and branch_destination(ins) in tail_targets) or ins['mnemonic'] in ('blr','blraa','blrab'):
                    addr=target.ResolveFileAddress(ins['address']+4).GetLoadAddress(target)
                    bp=target.BreakpointCreateByAddress(addr)
                    bp.SetEnabled(False)
                    bp.SetScriptCallbackFunction('lldb._pretzel_depth_system_handler')
                    system_return_bps[addr]=bp
        result['system_return_sites_instrumented']=len(system_return_bps)
        if OBSERVE_SYSTEM:
            system_bps={breakpoint(a).GetID():(a,n) for a,n in system_stubs.items()}
            for ident in system_bps:target.FindBreakpointByID(ident).SetEnabled(False)
        for ident in system_bps:
            target.FindBreakpointByID(ident).SetScriptCallbackFunction('lldb._pretzel_depth_system_handler')
        print('STAGE observe',flush=True)
        while process.GetState()==lldb.eStateStopped:
            if result.get('callback_error'):raise RuntimeError(result['callback_error'])
            if time.monotonic()-began > 5400:
                raise RuntimeError('Observation timeout')
            thread=process.GetSelectedThread(); frame=thread.GetFrameAtIndex(0)
            if thread.GetStopReason()!=lldb.eStopReasonBreakpoint:
                raise RuntimeError('Unexpected process stop: '+str(thread.GetStopDescription(1024)))
            ids={thread.GetStopReasonDataAtIndex(i) for i in range(0,thread.GetStopReasonDataCount(),2)}
            if any(bp.GetID() in ids for bp in error_bps):
                result['entropy_error_return_observed']=True
                break
            elif entropy_bp.GetID() in ids and active is not None:
                count=reg(frame,'x1'); pointer=reg(frame,'x0')
                if not 0<count<=256:
                    raise RuntimeError('Unexpected getentropy ABI/length: '+str(count))
                request=len(active['entropy_requests'])
                # Final case exercises an actual OS entropy error. Calling
                # __error here is debugger instrumentation; its extra frames
                # make this an over-approximate diagnostic, separately tagged.
                if active['case']==CASES+2 and request==2:
                    value=frame.EvaluateExpression('*(int *)__error() = 5')
                    if value.GetError().Fail():
                        raise RuntimeError('Cannot set EIO for fault injection: '+str(value.GetError()))
                    if not frame.FindRegister('x0').SetValueFromCString(str(2**64-1)):
                        raise RuntimeError('Failed to inject entropy error return')
                    active['entropy_failure']=True
                else:
                    seed=struct.pack('<QQ',active['case'],request)
                    write(pointer,hashlib.shake_256(b'pretzel-stack-depth-v1'+seed).digest(count))
                    if not frame.FindRegister('x0').SetValueFromCString('0'):
                        raise RuntimeError('Failed to inject entropy success return')
                if not frame.FindRegister('pc').SetValueFromCString(str(reg(frame,'lr'))):
                    raise RuntimeError('Failed to return from entropy boundary')
                active['entropy_requests'].append(count)
            elif retry_bp.GetID() in ids and active is not None:
                if active.get('retry_forced'):raise RuntimeError('Retry forced more than once')
                if not frame.FindRegister(shell_register).SetValueFromCString(str(2**64-1)):raise RuntimeError('Cannot force shell mask')
                active['retry_forced']=True
                retry_bp.SetEnabled(False)
            elif body_bp.GetID() in ids:
                case=len(result['samples'])
                sp=reg(frame,'sp')
                wrapper=thread.GetFrameAtIndex(1)
                caller=thread.GetFrameAtIndex(2)
                if not wrapper.IsValid() or 'keygen' not in (wrapper.GetFunctionName() or '') or not caller.IsValid():
                    raise RuntimeError('Cannot identify the real keygen wrapper return')
                pattern=hashlib.sha256(b'paint'+case.to_bytes(8,'little')).digest()[:8]
                write(sp-PAINT,pattern*(PAINT//8))
                active=dict(case=case,entry_sp=sp,paint_low=sp-PAINT,pattern=pattern,entropy_requests=[],wrapper_return=caller.GetPC())
                # The first case retains the real system entropy call. The
                # later cases (`case>0`) use reproducible injected public seeds.
                entropy_bp.SetEnabled(not OBSERVE_SYSTEM and case>0)
                for ident in system_bps:target.FindBreakpointByID(ident).SetEnabled(OBSERVE_SYSTEM)
                retry_bp.SetEnabled(case==1)
                for bp in scrub_bps:bp.SetEnabled(True)
            elif any(bp.GetID() in ids for bp in scrub_bps) and active is not None:
                if reg(frame,'sp') != active['entry_sp']:
                    raise RuntimeError('Body and scrub call anchors differ')
                data=read(active['paint_low'],PAINT)
                pattern=active['pattern']
                touched=[i for i in range(0,PAINT,8) if data[i:i+8]!=pattern]
                if not touched:
                    raise RuntimeError('Body did not modify painted stack')
                active['deepest']=active['paint_low']+min(touched)
                active['touched_words']=len(touched)
                active['touched_addresses']=[active['paint_low']+i for i in touched]
                entropy_bp.SetEnabled(False); erase_bp.SetEnabled(True)
                for ident in system_bps:target.FindBreakpointByID(ident).SetEnabled(False)
                retry_bp.SetEnabled(False)
            elif erase_bp.GetID() in ids and active is not None:
                low=reg(frame,'x0'); count=reg(frame,'x1'); high=low+8*count
                if count not in (16384,49152):
                    raise RuntimeError('Unexpected keygen scrub word count: '+str(count))
                active.update(scrub_low=low,scrub_high=high,scrub_sp=reg(frame,'sp'),scrub_words=count)
                after_bp=target.BreakpointCreateByAddress(reg(frame,'lr'))
                erase_bp.SetEnabled(False)
            elif after_bp is not None and after_bp.GetID() in ids and active is not None:
                low,high,sp=active['scrub_low'],active['scrub_high'],active['scrub_sp']
                if not active['paint_low']<=sp<=low<high<=active['entry_sp']:
                    raise RuntimeError('Scrub coordinates outside paint')
                zeros=read(low,high-low)==bytes(high-low)
                deeper=read(active['paint_low'],sp-active['paint_low'])
                undisturbed=deeper==active['pattern']*(len(deeper)//8)
                depth=high-active['deepest']
                sample=dict(case=active['case'],depth_bytes=depth,touched_words=active['touched_words'],
                            entropy_mode='system' if active['case']==0 else ('forced_shell_retry' if active.get('retry_forced') else ('error' if active.get('entropy_failure') else 'deterministic')),
                            entropy_requests=active['entropy_requests'],entropy_failure=active.get('entropy_failure',False),
                            scrub_bytes=high-low,region_zero=zeros,deeper_pattern=undisturbed,
                            body_within_scrub=active['deepest']>=low,
                            excluded_below_bytes=low-sp,excluded_above_bytes=active['entry_sp']-high,
                            exclusion_reason='Below: live scrub frame prefix between scrub SP and erased local. Above: saved-register/ABI prefix between erased local end and body-entry SP. Neither exclusion is counted as verified zero.')
                active['sample']=sample
                if active.get('retry_forced') and active['entropy_requests'].count(64)==2:
                    result['forced_shell_retry']=True
                    result['seed_retry_coverage']='forced, not seed-induced'
                if not zeros or not undisturbed or active['deepest']<low:
                    result['failures'].append('Coverage failed at case '+str(active['case']))
                target.BreakpointDelete(after_bp.GetID()); after_bp=None
                for bp in scrub_bps:bp.SetEnabled(False)
                returned_bp=target.BreakpointCreateByAddress(active['wrapper_return'])
            elif returned_bp is not None and returned_bp.GetID() in ids and active is not None:
                low,high,sp=active['scrub_low'],active['scrub_high'],active['scrub_sp']
                data=read(low,high-low)
                dirty=[i for i in range(0,len(data),8) if data[i:i+8]!=bytes(8)]
                ranges=[]
                for offset in dirty:
                    if ranges and ranges[-1][1]==offset:ranges[-1][1]+=8
                    else:ranges.append([offset,offset+8])
                touched_zero=all(data[a-low:a-low+8]==bytes(8) for a in active['touched_addresses'] if low<=a<high)
                deeper=read(active['paint_low'],sp-active['paint_low'])
                deeper_pattern=deeper==active['pattern']*(len(deeper)//8)
                active['sample'].update(post_return_region_zero=not dirty,post_return_touched_zero=touched_zero,
                                        post_return_deeper_pattern=deeper_pattern,
                                        post_return_nonzero_ranges_from_anchor=[[a-len(data),b-len(data)] for a,b in ranges])
                if dirty or not touched_zero or not deeper_pattern:
                    result['failures'].append('After-return coverage failed at case '+str(active['case']))
                result['samples'].append(active['sample'])
                target.BreakpointDelete(returned_bp.GetID());returned_bp=None;active=None
                if len(result['samples'])%128==0:
                    save(); print('Depth samples:',len(result['samples']),flush=True)
                if len(result['samples'])==CASES+3:
                    if not error_bps:
                        raise RuntimeError('Cannot verify error propagation: no unwrap_failed symbol')
                    body_bp.SetEnabled(False)
                    for bp in scrub_bps:bp.SetEnabled(False)
                    for bp in error_bps:bp.SetEnabled(True)
            process.Continue()
        result['max_depth_bytes']=max((s['depth_bytes'] for s in result['samples']),default=None)
        result['seed_cases']=sum(s['entropy_mode']=='deterministic' for s in result['samples'])
        result['entropy_failure_cases']=sum(s['entropy_failure'] for s in result['samples'])
        if result['seed_cases']<CASES or result['entropy_failure_cases']<1:
            result['failures'].append('Incomplete seed/error coverage')
        if not result.get('entropy_error_return_observed'):
            result['failures'].append('Injected entropy error was not observed at driver expect boundary')
        if not result['forced_shell_retry']:
            result['failures'].append('Forced shell retry did not draw exactly two 64-byte seeds')
        if result['max_depth_bytes'] is None or result['max_depth_bytes']+32768>131072:
            result['failures'].append('Depth plus required margin exceeds 131072 bytes, or no measurement')
        result['elapsed_seconds']=time.monotonic()-began
        result['requested_seed_cases']=CASES
        result['observation_scope']='system-routine subset' if OBSERVE_SYSTEM else 'full body campaign, system observer disabled'
        result['status']='FAIL' if result['failures'] else 'PASS'
    except Exception as error:
        result['failures'].append(str(error))
    finally:
        if process is not None and process.IsValid():
            process.Kill()
        result['image_file_unchanged']=hashlib.sha256(binary.read_bytes()).hexdigest()==result['binary_sha256']
        if not result['image_file_unchanged']:
            result['failures'].append('Observed executable file changed')
            result['status']='FAIL'
        # Preserve partial observations even when a later breakpoint or error
        # injection fails. Partial coverage never becomes a passing result.
        result['max_depth_bytes']=max((s['depth_bytes'] for s in result['samples']),default=None)
        result['seed_cases']=sum(s['entropy_mode']=='deterministic' for s in result['samples'])
        result['system_entropy_cases']=sum(s['entropy_mode']=='system' for s in result['samples'])
        result['entropy_failure_cases']=sum(s['entropy_failure'] for s in result['samples'])
        save()
        print(json.dumps({k:v for k,v in result.items() if k!='samples'},indent=2),flush=True)


run(lldb.debugger)
