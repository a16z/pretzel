"""Pure-Python gate tests. All native subprocesses are mocked and forbidden."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch
import stack_depth_ci as ci


class GateTests(unittest.TestCase):
    def exercise(self, static_ok=True, depth=472, trace=False, enabled=True, observed=True, mismatch=False, seeds=31, timeout=False):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);binary=root/'binary';binary.write_bytes(b'fixture, never executed')
            out=root/'report';calls=[]
            def run(command, **kw):
                if command[:2]==['xcrun','lldb']:
                    inventory=kw['env']['DEPTH_INVENTORY_ONLY']=='true'
                    system=kw['env']['DEPTH_OBSERVE_SYSTEM']=='true'
                    directory=Path(kw['env']['DEPTH_OUTPUT'])
                    calls.append((inventory,system))
                    dynamic=dict(status='FAIL' if inventory else 'PASS',max_depth_bytes=None if inventory else 64656,
                        binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest() if not mismatch or not system else 'wrong',
                        seed_cases=seeds if system else 4096,system_entropy_cases=1,entropy_failure_cases=1,forced_shell_retry=True,entropy_error_return_observed=True,
                        system_observer_enabled=enabled if system else False,system_probed_stubs=[dict(name='malloc'),dict(name='free')],
                        system_routines={'malloc':dict(observed_max_depth_bytes=depth)} if observed and not inventory else {})
                    if inventory:dynamic['observation_state']='NOT RUN: image inventory for static preflight'
                    (directory/'dynamic.json').write_text(json.dumps(dynamic))
                    if timeout and system:raise ci.subprocess.TimeoutExpired(command,60)
                    if trace and not inventory:kw['stdout'].write('Traceback (most recent call last)\n')
                    return types.SimpleNamespace(returncode=0)
                if 'stack_depth_static.py' in command[2]:
                    bound=dict(binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),status='PASS' if static_ok else 'FAIL',static_bound_bytes=68944 if static_ok else None,
                        direct_call_subtotal_bytes=68944,system_allowances=[dict(name=n,allowance_bytes=4096) for n in ['malloc','free']])
                    (out/'static.json').write_text(json.dumps(bound))
                    return types.SimpleNamespace(returncode=0 if static_ok else 1,stdout='',stderr='')
                raise AssertionError('Unexpected subprocess '+repr(command))
            def output(command, **kw):
                self.assertIn(command[0],['otool','nm']);return b'fixture inventory'
            with patch.dict(os.environ,dict(GITHUB_ACTIONS='true',RUNNER_OS='macOS'),clear=True), \
                 patch.object(ci.platform,'machine',return_value='arm64'), \
                 patch.object(ci.subprocess,'run',side_effect=run), \
                 patch.object(ci.subprocess,'check_output',side_effect=output), \
                 patch.object(ci.sys,'argv',['check','--output',str(out),'--binary',str(binary)]), \
                 patch('builtins.print'):
                with self.assertRaises(SystemExit) as raised:ci.main()
            return raised.exception.code,calls,json.loads((out/'summary.json').read_text()),json.loads((out/'system-allowances.json').read_text())

    def test_static_failure_never_launches_dynamic_probe(self):
        code,calls,result,_=self.exercise(static_ok=False)
        self.assertEqual(calls,[(True,False)]);self.assertTrue(code)
        self.assertIsNone(result['static_bound_bytes'])
        self.assertTrue(result['observation_state'].startswith('NOT RUN'))

    def test_passing_preflight_runs_full_probe_and_labels_unobserved(self):
        code,calls,result,allowances=self.exercise()
        self.assertEqual(calls,[(True,False),(False,False),(False,True)]);self.assertFalse(code)
        self.assertEqual(result['unobserved_system_routines'],['free'])
        self.assertEqual(allowances[1]['status'],'NOT OBSERVED')

    def test_system_half_allowance_exceeded_fails(self):
        self.assertTrue(self.exercise(depth=2049)[0])

    def test_callback_traceback_fails(self):
        self.assertTrue(self.exercise(trace=True)[0])

    def test_disabled_observer_fails(self):
        self.assertTrue(self.exercise(enabled=False)[0])

    def test_different_binary_in_subset_fails(self):
        self.assertTrue(self.exercise(mismatch=True)[0])

    def test_insufficient_subset_fails(self):
        self.assertTrue(self.exercise(seeds=30)[0])

    def test_observer_timeout_saves_failing_summary(self):
        code,_,report,_=self.exercise(timeout=True)
        self.assertTrue(code)
        self.assertEqual(report['status'],'FAIL')

    def test_no_system_observations_fails(self):
        self.assertTrue(self.exercise(observed=False)[0])


if __name__=='__main__':unittest.main()
