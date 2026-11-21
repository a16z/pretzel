"""Build and inspect the release image on macos-15; fail closed on any gap."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import time
from stack_depth_margin import check as check_margin

HERE=Path(__file__).resolve().parent
# System routines are observed on 31 deterministic seeds plus three special cases, a subset
# chosen to keep the job within its time limit. It is not full seed coverage.
SYSTEM_SEEDS=31


def toolchain_channel():
    """The channel of rust-toolchain.toml at the repository root, as the workflow reads it."""
    found=re.findall(r'^channel = "(.*)"$',(HERE.parents[2]/'rust-toolchain.toml').read_text(),re.M)
    if len(found)!=1:raise SystemExit('rust-toolchain.toml must name exactly one channel')
    return found[0]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--binary',type=Path)
    parser.add_argument('--bound',type=int,default=131072)
    args=parser.parse_args()
    if os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_OS')!='macOS' or platform.machine()!='arm64':
        raise SystemExit('Native work requires arm64 macOS Actions')
    out=args.output.resolve();out.mkdir(parents=True,exist_ok=True)
    campaign_deadline=time.monotonic()+1860  # leave time to retain failure evidence before the job limit
    env=dict(os.environ)
    for name in ('RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','CARGO_BUILD_TARGET','CARGO_TARGET_DIR'):
        env.pop(name,None)
    env.update(RUSTUP_TOOLCHAIN=toolchain_channel(),MACOSX_DEPLOYMENT_TARGET='15.2')
    if args.binary:
        binary=args.binary.resolve()
    else:
        project=Path(os.environ['RUNNER_TEMP'])/'stack-depth-release'
        project.mkdir(exist_ok=True)
        shutil.copyfile(HERE/'stack_depth_driver.rs',project/'main.rs')
        shutil.copyfile(HERE/'stack_depth_Cargo.lock',project/'Cargo.lock')
        (project/'Cargo.toml').write_text('''[package]
name = "pretzel-keygen-depth"
version = "0.1.0"
edition = "2021"
publish = false
[workspace]
[dependencies]
scheme = { package = "pretzel-5-5", path = '''+json.dumps(str(HERE.parent))+''', features = ["stack-wipe"] }
[[bin]]
name = "pretzel-keygen-depth"
path = "main.rs"
[profile.release]
opt-level = 3
lto = true
codegen-units = 1
''')
        with (out/'build.txt').open('w') as log:
            subprocess.run(['cargo','build','--locked','--release','--manifest-path',str(project/'Cargo.toml')],env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
        binary=project/'target/release/pretzel-keygen-depth'
    shutil.copyfile(binary,out/'release-image')
    for command,name in ((['otool','-tvV'],'disassembly.txt.gz'),(['nm','-nm'],'symbols.txt.gz'),(['otool','-l'],'load-commands.txt.gz')):
        with gzip.open(out/name,'wb') as stream:
            stream.write(subprocess.check_output(command+[str(binary)]))
    digest=hashlib.sha256(binary.read_bytes()).hexdigest()
    command=out/'debugger.txt'
    command.write_text('script exec(compile(open('+repr(str(HERE/'stack_depth_lldb.py'))+').read(), '+repr(str(HERE/'stack_depth_lldb.py'))+', "exec"))\nquit\n')
    import types
    def observe(directory, inventory_only, system=False, cases=4096):
        directory.mkdir(exist_ok=True)
        probe_env=dict(env,DEPTH_OUTPUT=str(directory),DEPTH_BINARY=str(binary),
                       DEPTH_STATIC=str(out/'static.json'),DEPTH_CASES=str(cases),
                       DEPTH_OBSERVE_SYSTEM='true' if system else 'false',
                       DEPTH_INVENTORY_ONLY='true' if inventory_only else 'false')
        with (directory/'debugger.log').open('w') as log:
            try:
                process=subprocess.run(['xcrun','lldb','--batch','-s',str(command)],env=probe_env,
                                       stdout=log,stderr=subprocess.STDOUT,timeout=min(300 if inventory_only else 1500,max(1,int(campaign_deadline-time.monotonic()))))
            except subprocess.TimeoutExpired:
                log.write('\nDebugger exceeded the observation timeout.\n')
                process=types.SimpleNamespace(returncode=124)
        report=json.loads((directory/'dynamic.json').read_text()) if (directory/'dynamic.json').exists() else dict(status='FAIL',failures=['Debugger produced no report'])
        report['debugger_returncode']=process.returncode
        report['callback_errors']='Traceback (most recent call last)' in (directory/'debugger.log').read_text()
        return report
    inventory=observe(out,True)
    static=subprocess.run([sys.executable,'-B',str(HERE/'stack_depth_static.py'),str(out/'image.json.gz'),str(out/'static.json'),'--binary',str(binary),'--bound',str(args.bound)],capture_output=True,text=True)
    (out/'static.log').write_text(static.stdout+static.stderr)
    bound=json.loads((out/'static.json').read_text()) if (out/'static.json').exists() else dict(status='FAIL',static_bound_bytes=None)
    dynamic=dict(inventory);subset=dict(inventory)
    if inventory['debugger_returncode']==0 and static.returncode==0:
        dynamic=observe(out/'full',False,False,4096)
        subset=observe(out/'system-subset',False,True,SYSTEM_SEEDS)
    # All three observations and the final disk image must authenticate to the
    # same release executable. A passing subset never replaces full coverage.
    identity_ok=all(r.get('binary_sha256')==digest for r in [inventory,dynamic,subset,bound]) and hashlib.sha256(binary.read_bytes()).hexdigest()==digest
    allowance_checks=[]
    for entry in bound.get('system_allowances',[]):
        observed=subset.get('system_routines',{}).get(entry['name'])
        allowance_checks.append(dict(name=entry['name'],allowance_bytes=entry['allowance_bytes'],
            measured_depth_bytes=observed.get('observed_max_depth_bytes') if observed else None,
            status=('PASS' if observed['observed_max_depth_bytes']<=entry['allowance_bytes']//2 else 'FAIL') if observed else 'NOT OBSERVED'))
    probed={e['name'] for e in subset.get('system_probed_stubs',[])}
    required={e['name'] for e in bound.get('system_allowances',[])}
    observer_errors=dynamic.get('callback_errors',False) or subset.get('callback_errors',False)
    allowance_ok=(bool(allowance_checks) and subset.get('system_observer_enabled',False)
                  and required<=probed and bool(subset.get('system_routines'))
                  and all(c['status']!='FAIL' for c in allowance_checks) and not observer_errors)
    (out/'system-allowances.json').write_text(json.dumps(allowance_checks,indent=2)+'\n')
    margin_result=check_margin(dynamic,args.bound,32768)
    (out/'margin.json').write_text(json.dumps(margin_result,indent=2)+'\n')
    margin_ok=margin_result['status']=='PASS' and check_margin(subset,args.bound,32768)['status']=='PASS'
    def coverage(r,n):
        return (r.get('status')=='PASS' and r.get('debugger_returncode')==0 and r.get('seed_cases',0)>=n
                and r.get('system_entropy_cases',0)>=1 and r.get('entropy_failure_cases',0)>=1
                and r.get('forced_shell_retry') and r.get('entropy_error_return_observed'))
    full_ok=coverage(dynamic,4096) and not dynamic.get('system_observer_enabled',True)
    subset_ok=coverage(subset,SYSTEM_SEEDS)
    static_ok=static.returncode==0 and bound.get('status')=='PASS' and type(bound.get('static_bound_bytes')) is int and bound['static_bound_bytes']+32768<=args.bound
    status='PASS' if static_ok and full_ok and subset_ok and margin_ok and allowance_ok and identity_ok else 'FAIL'
    summary=dict(status=status,dynamic_high_water_bytes=dynamic.get('max_depth_bytes'),static_bound_bytes=bound.get('static_bound_bytes'),
                 direct_call_subtotal_bytes=bound.get('direct_call_subtotal_bytes'),bound_bytes=args.bound,margin_bytes=32768,
                 dynamic_margin_pass=margin_ok,static_status=bound['status'],dynamic_status=dynamic['status'],
                 system_subset_status=subset['status'],system_subset_required_seeds=SYSTEM_SEEDS,system_subset_seed_cases=subset.get('seed_cases'),
                 runtime_fallback='system routines are observed on 31 deterministic seeds plus 3 special cases, a subset chosen to keep the job within its time limit',
                 system_subset_elapsed_seconds=subset.get('elapsed_seconds'),full_elapsed_seconds=dynamic.get('elapsed_seconds'),
                 system_allowances_pass=allowance_ok,observer_callback_errors=observer_errors,same_binary_sha256_pass=identity_ok,
                 unobserved_system_routines=[c['name'] for c in allowance_checks if c['status']=='NOT OBSERVED'],
                 observation_state=dynamic.get('observation_state','full body campaign and system subset attempted'),binary_sha256=digest)
    (out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    text=f"""# Key-generation stack depth: {status}

Measured full-campaign high-water observation: {dynamic.get('max_depth_bytes')} bytes (lower bound on worst-case use).
Computed static bound with measured allowances for system routines: {bound.get('static_bound_bytes')} bytes.
Required scrub bound: {args.bound} bytes. Required margin: 32768 bytes.
Static preflight: {bound['status']}. Full campaign: {dynamic['status']}, {dynamic.get('seed_cases')} deterministic seeds plus OS entropy, forced retry and entropy error.
System-routine observation is on a subset: {subset['status']}, {subset.get('seed_cases')} deterministic seeds plus the same three special cases.\nRuntime fallback: {summary['runtime_fallback']}
Same binary SHA-256 across static, full and subset passes: {identity_ok} ({digest}).
System allowance cross-check: {allowance_ok}. Unobserved routines retain their allowances: {', '.join(summary['unobserved_system_routines'])}.
Full observation seconds: {dynamic.get('elapsed_seconds')}; subset seconds: {subset.get('elapsed_seconds')}.

| Site | Function | Checked resolution / evidence |
|---|---|---|
"""
    for r in bound.get('indirect_resolutions',[])+bound.get('abort_excluded_indirect_sites',[]):
        evidence=r.get('descriptor') or r.get('vtable') or ('caller block '+r.get('caller_block','')+'; terminating call '+r.get('postdominating_call',''))
        text+=f"| {r['instruction']} | {r['function']} | {r['resolution']}; {evidence} |\n"
    text+='\nDeepest computed chain: '+ ' -> '.join(f"{x['name']} ({x['frame_bytes']} bytes)" for x in bound.get('deepest_chain',[]))+'\n'
    (out/'SUMMARY.md').write_text(text)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'],'a') as stream:stream.write(text)
    for path in out.rglob('*'):
        if path.is_file() and path.stat().st_size>50*1024*1024:
            with path.open('rb') as src,gzip.open(str(path)+'.gz','wb') as dst:shutil.copyfileobj(src,dst)
            path.unlink()
    (out/'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+str(p.relative_to(out))+'\n' for p in sorted(out.rglob('*')) if p.is_file() and p.name!='SHA256SUMS'))
    print(text)
    raise SystemExit(status!='PASS')


if __name__=='__main__':main()
