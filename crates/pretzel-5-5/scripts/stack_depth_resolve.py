"""Checked image-based indirect edges and termination post-dominance.

Analysis-only graph expansion preserves each frame. A Once invocation gets its
own vtable context; no context-insensitive union of closure targets is used.
"""
import re
from copy import deepcopy

INDIRECT={'blr','br','blraa','braa','blrab','brab'}
BRANCH={'b','bl','cbz','cbnz','tbz','tbnz'}
ONCE='std::sys::sync::once::queue::Once::call'
TERMINATORS={'abort','std::process::abort','std::sys::pal::unix::abort_internal'}


def canonical(s):return re.sub(r'::h[0-9a-f]{16}$','',s)
def target(i):
    v=re.findall(r'0x[0-9a-f]+',i['operands'])
    return int(v[-1],16) if v else None

def callee_name(i,functions):
    t=target(i)
    return canonical(functions[t]['name']) if t in functions else i.get('comment','').removeprefix('symbol stub for: ')


def cfg(f,functions,panic,termination):
    ins={i['address']:i for i in f['instructions']};succ={};term={}
    for pc,i in ins.items():
        op=i['mnemonic'];t=target(i);name=callee_name(i,functions)
        if op in ('bl','b') and name in termination:
            succ[pc]=[];term[pc]=name
        elif op in ('bl','b') and name in panic:succ[pc]=[]
        elif op in ('ret','br','braa','brab','udf','brk'):succ[pc]=[]
        elif op=='b':succ[pc]=[t] if t in ins else []
        elif op.startswith('b.') or op in ('cbz','cbnz','tbz','tbnz'):
            succ[pc]=[pc+4,t]
        else:succ[pc]=[pc+4]
    live=set();todo=[f['address']]
    while todo:
        pc=todo.pop()
        if pc in live or pc not in ins:continue
        live.add(pc);todo.extend(succ[pc])
    return ins,{p:succ[p] for p in live},term


def termination_postdominators(succ,term):
    # Least fixed point: a cycle with an escape to abort is NOT sufficient.
    # Every successor must already be proven to reach a common terminating
    # call. Return/trap/unknown exits carry the empty set. This is stricter
    # than post-dominance over finite exiting paths and excludes infinite loops.
    proven={p:{p} for p in term if p in succ}
    while True:
        changed=False
        for p,children in succ.items():
            if p in proven or not children or not all(c in proven for c in children):continue
            common=set.intersection(*(proven[c] for c in children))
            if common:proven[p]=common;changed=True
        if not changed:return proven


def blocks(succ,start):
    leaders={start}
    for p,cs in succ.items():
        if cs!=[p+4]:leaders.update(c for c in cs if c in succ);leaders.add(p+4)
    owner={};current=start
    for p in sorted(succ):
        if p in leaders or p-4 not in succ:current=p
        owner[p]=current
    return owner


def transfer(i,state,macho):
    state=dict(state);op=i['mnemonic'];args=i['operands'];parts=[x.strip() for x in args.split(',')]
    def put(reg,value):
        reg=re.sub(r'^w','x',reg)
        state.pop(reg,None)
        if value is not None:state[reg]=value
    value=None;dest=parts[0] if parts else ''
    if op=='adrp':
        if 'bytes' in i:
            word=int.from_bytes(bytes.fromhex(i['bytes']),'little')
            if word&0x9f000000!=0x90000000:raise ValueError('ADRP encoding mismatch')
            imm=((word>>29)&3)|(((word>>5)&0x7ffff)<<2)
            if imm&(1<<20):imm-=1<<21
            address=(i['address']&~4095)+(imm<<12)
        else:address=(i['address']&~4095)+(int(parts[1],0)<<12)
        value=('address',address,(i['address'],))
    elif op=='mov' and len(parts)==2:value=state.get(parts[1])
    elif op=='add' and len(parts)==3 and parts[2].startswith('#'):
        v=state.get(parts[1])
        if v and v[0]=='address':value=('address',v[1]+int(parts[2][1:],0),v[2]+(i['address'],))
    elif op=='ldr':
        m=re.fullmatch(r'x\d+, \[(x\d+)(?:, #(0x[0-9a-f]+|\d+))?\]',args)
        if m:
            v=state.get(m[1]);off=int(m[2] or '0',0)
            if v and v[0]=='address':
                address=v[1]+off
                pointer=macho.fixups.get(address) if macho else None
                if pointer and 'target' in pointer:value=('address',pointer['target'],v[2]+(i['address'],))
                else:value=('loaded',address,v[2]+(i['address'],))
    if op in ('bl','blr','blraa','blrab'):
        for n in range(19):state.pop('x'+str(n),None)
        state.pop('x30',None)
    elif op.startswith(('ldadd','ldclr','ldeor','ldset','ldsmax','ldsmin','ldumax','ldumin','swp')):
        # Atomic RMW instructions write the second operand, not the first.
        if len(parts)>1:put(parts[1],None)
        else:state.clear()
    elif op.startswith('casp'):
        for r in parts[:2]:put(r,None)
    elif op=='ldp':
        for r in parts[:2]:put(r,None)
    elif not (op.startswith('st') or op in BRANCH or op in INDIRECT or op.startswith('b.') or op in ('cmp','cmn','tst','ret','dmb','brk','udf','nop')):
        put(dest,value)
    # Both pre-index and post-index addressing update the base register.
    writeback=re.search(r'\[(x\d+|sp)[^]]*\](?:!|,)',args)
    if writeback:put(writeback[1],None)
    return state


def states(f,succ,macho,context=None):
    ii={i['address']:i for i in f['instructions']}
    initial={'x3':('address',context,())} if context is not None else {'x3':('argument',3,())}
    incoming={f['address']:initial};todo=[f['address']]
    while todo:
        pc=todo.pop();out=transfer(ii[pc],incoming[pc],macho)
        for child in succ.get(pc,[]):
            if child not in succ:continue
            merged=out if child not in incoming else {r:v for r,v in incoming[child].items() if out.get(r)==v}
            if child not in incoming or merged!=incoming[child]:incoming[child]=dict(merged);todo.append(child)
    return incoming


def resolve(image,macho,panic):
    fs={f['address']:f for f in image['functions']};errors=[];sites=[];cuts=[];contexts=[]
    # Validate each in-image no-return wrapper against the external abort
    # endpoint. A matching function name with a return is never sufficient.
    terminating={'abort'}- {canonical(f['name']) for f in fs.values()}
    termination_validation=[]
    while True:
        old=set(terminating)
        for f in fs.values():
            name=canonical(f['name'])
            if name not in TERMINATORS or name in terminating:continue
            _,ss,tt=cfg(f,fs,panic,terminating)
            pd=termination_postdominators(ss,tt)
            if f['address'] in pd:
                terminating.add(name)
                termination_validation.append(dict(function=f['name'],entry=hex(f['address']),terminating_calls=[hex(p) for p in sorted(pd[f['address']])]))
        if old==terminating:break
    once={a for a,f in fs.items() if canonical(f['name'])==ONCE}
    contextual=set(once)
    # Identify tail forwarding wrappers from instructions, not their names.
    while True:
        old=set(contextual)
        for a,f in fs.items():
            if a in contextual:continue
            _,succ,_=cfg(f,fs,panic,terminating)
            ss=states(f,succ,macho)
            if any(i['address'] in succ and i['mnemonic']=='b' and target(i) in contextual and ss[i['address']].get('x3')==('argument',3,()) for i in f['instructions']):contextual.add(a)
        if old==contextual:break
    transformed={};aliases={};serial=0
    def visit(a,context=None):
        nonlocal serial
        key=(a,context if a in contextual else None)
        if key in aliases:return aliases[key]
        if a in contextual:
            serial+=1;new=0x3000000000+serial*0x100000
        else:new=a
        aliases[key]=new
        f=fs[a];ii,succ,term=cfg(f,fs,panic,terminating)
        post=termination_postdominators(succ,term);bb=blocks(succ,a)
        ss=states(f,succ,macho,context)
        replacements={}
        for pc in sorted(succ):
            i=ii[pc];op=i['mnemonic'];t=target(i);name=callee_name(i,fs)
            if op in ('bl','b') and pc in post:
                terminal=min(post[pc])
                cuts.append(dict(caller=f['name'],instruction=hex(pc),caller_block=hex(bb[pc]),target=name,
                    postdominating_call=hex(terminal),terminating_function=term[terminal],
                    reason='abort path, the process terminates, outside the guarantee'))
                replacements[pc]=dict(i,mnemonic='ret' if pc in term else 'nop',operands='')
                continue
            if op in INDIRECT:
                v=ss.get(pc,{}).get(i['operands']);row=dict(function=f['name'],instruction=hex(pc),mnemonic=op,operands=i['operands'])
                try:
                    if op!='blr' or not v or macho is None:raise ValueError('unresolved target register')
                    # TLS access must originate and load in this basic block.
                    if v[0]=='loaded':
                        descriptor=v[1];section=macho.section(descriptor,24);fix=macho.pointer(descriptor)
                        if not section or section['name']!='__DATA,__thread_vars' or (descriptor-section['address'])%24 or fix.get('import')!='__tlv_bootstrap':raise ValueError('not an authenticated TLS descriptor')
                        if not v[2] or any(bb.get(p)!=bb[pc] for p in v[2]):raise ValueError('TLS materialization crosses basic blocks')
                        # The ABI receives the same descriptor in x0.
                        arg=ss[pc].get('x0')
                        if not arg or arg[:2]!=('address',descriptor):raise ValueError('TLS descriptor argument mismatch')
                        fake=0x2000000000
                        replacements[pc]=dict(i,mnemonic='bl',operands=hex(fake),comment='symbol stub for: tlv_get_addr')
                        row.update(resolution='system routine tlv_get_addr',descriptor=hex(descriptor),section=section['name'],fixup=fix,
                                   evidence_instructions=[ii[p] for p in v[2]],reason='Darwin thread-local access thunk',allowance_bytes=4096)
                    elif a in once and context is not None and v[0]=='address':
                        # Only the call entry at +32 of this caller's FnMut
                        # vtable is admitted. Authenticate the loading site.
                        loads=[ii[p] for p in v[2] if p in ii and ii[p]['mnemonic']=='ldr']
                        if len(loads)!=1:raise ValueError('ambiguous closure load')
                        load=loads[0];m=re.fullmatch(r'x\d+, \[(x\d+), #0x20\]',load['operands'])
                        base=ss[load['address']].get(m[1]) if m else None
                        if not base or base[:2]!=('address',context):raise ValueError('closure does not load caller vtable call entry')
                        ptr=macho.pointer(context+32)
                        if ptr.get('target')!=v[1] or v[1] not in fs:raise ValueError('closure target is not an emitted function entry')
                        child=visit(v[1]);replacements[pc]=dict(i,mnemonic='bl',operands=hex(child))
                        row.update(resolution='caller-specific Once closure',vtable=hex(context),call_entry=hex(context+32),fixup=ptr,
                                   target=hex(v[1]),target_function=fs[v[1]]['name'],load=load)
                    else:raise ValueError('no checked rule for target')
                except ValueError as exc:
                    row.update(resolution='unresolved: FAIL',reason=str(exc));errors.append([hex(pc),str(exc)])
                sites.append(row)
            elif op in BRANCH or op.startswith('b.'):
                if t in fs and t not in ii and name not in panic:
                    ctx=None
                    if t in contextual:
                        v=ss.get(pc,{}).get('x3')
                        if not v or v[0]!='address':
                            errors.append([hex(pc),'Once caller vtable is not uniquely recovered']);continue
                        ctx=v[1]
                        contexts.append(dict(caller=f['name'],instruction=hex(pc),callee=fs[t]['name'],vtable=hex(ctx),materialization=[ii[p] for p in v[2] if p in ii]))
                    child=visit(t,ctx)
                    replacements[pc]=dict(i,operands=re.sub(r'0x[0-9a-f]+$',hex(child),i['operands']))
        out=deepcopy(f);out['address']=new
        if new!=a:out['name']+=' [vtable '+hex(context or 0)+']'
        out['instructions']=[]
        for i in f['instructions']:
            r=dict(replacements.get(i['address'],i))
            t=target(r)
            if new!=a:
                if (r['mnemonic'] in BRANCH or r['mnemonic'].startswith('b.')) and t in ii:
                    r['operands']=re.sub(r'0x[0-9a-f]+$',hex(new+t-a),r['operands'])
                r['address']=new+i['address']-a
            out['instructions'].append(r)
        transformed[new]=out
        return new
    for a,f in fs.items():
        if 'keygen_with_entropy_unscrubbed' in f['name']:visit(a)
    # Keep panic entries for validation by the scoped inventory.
    for a,f in fs.items():
        if canonical(f['name']) in panic:transformed[a]=f
    excluded_sites=[]
    for cut in cuts:
        caller=next(f for f in fs.values() if f['name']==cut['caller'])
        call=next(i for i in caller['instructions'] if hex(i['address'])==cut['instruction'])
        todo=[(target(call),[])];seen=set()
        while todo:
            a,path=todo.pop()
            if a in seen or a not in fs:continue
            seen.add(a);f=fs[a];path=path+[f['name']]
            ii,succ,_=cfg(f,fs,panic,terminating)
            for pc in sorted(succ):
                i=ii[pc]
                if i['mnemonic'] in INDIRECT:
                    excluded_sites.append(dict(function=f['name'],instruction=hex(pc),resolution='abort-only reachability' if a not in transformed else 'also normally reachable; retained for resolution',
                        caller_block=cut['caller_block'],cut_instruction=cut['instruction'],postdominating_call=cut['postdominating_call'],terminating_function=cut['terminating_function'],call_chain=path))
                if i['mnemonic'] in BRANCH or i['mnemonic'].startswith('b.'):
                    t=target(i)
                    if t in fs and t not in ii and callee_name(i,fs) not in panic:todo.append((t,path))
    return dict(image,functions=list(transformed.values())),dict(abort_excluded_indirect_sites=excluded_sites,indirect_resolutions=sites,abort_cut_edges=cuts,once_contexts=contexts,resolution_errors=errors,termination_validation=termination_validation)
