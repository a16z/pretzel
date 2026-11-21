"""Pure-Python fail-closed regression cases; no native execution."""
import unittest
from stack_depth_static import inventory as analyze
from stack_depth_static import analyze as scoped_analyze
from unittest.mock import patch
from stack_depth_margin import check as check_margin


def function(address, name, pairs):
    return dict(address=address,size=4*len(pairs),name=name,
                instructions=[dict(address=address+4*i,mnemonic=op,operands=args) for i,(op,args) in enumerate(pairs)])


class StaticDepth(unittest.TestCase):
    def root(self,*pairs):
        return function(0x100,'keygen_with_entropy_unscrubbed',list(pairs))

    def check(self,*functions):
        return analyze(dict(functions=list(functions)))

    def test_nested_frames_and_tail_edge(self):
        result=self.check(self.root(('stp','x29, x30, [sp, #-16]!'),('sub','sp, sp, #2, lsl #12'),('bl','0x200'),('ret','')),
                          function(0x200,'callee',[('sub','sp, sp, #32'),('b','0x300')]),
                          function(0x300,'tail',[('sub','sp, sp, #64'),('ret','')]))
        self.assertEqual(result['static_bound_bytes'],16+8192+32+64+3*128)

    def test_system_memcpy_is_not_free(self):
        result=self.check(self.root(('bl','0x500'),('ret','')))
        self.assertIsNone(result['static_bound_bytes'])
        self.assertEqual(result['status'],'FAIL')

    def test_indirect_call_is_not_free(self):
        self.assertIsNone(self.check(self.root(('blr','x8'),('ret','')))['static_bound_bytes'])

    def test_recursive_graph_is_not_bounded_by_one_visit(self):
        result=self.check(self.root(('bl','0x200'),('ret','')),function(0x200,'recursive',[('bl','0x100'),('ret','')]))
        self.assertIsNone(result['static_bound_bytes'])

    def test_variable_stack_adjustment_fails(self):
        self.assertEqual(self.check(self.root(('sub','sp, sp, x8'),('ret','')))['status'],'FAIL')

    def test_probe_loop_fails_without_bound(self):
        self.assertEqual(self.check(self.root(('sub','sp, sp, #4096'),('cbnz','x9, 0x100'),('ret','')))['status'],'FAIL')

    def test_fixed_page_probe_accounts_for_every_iteration(self):
        result=self.check(self.root(('sub','x9, sp, #0xb, lsl #12'),('sub','sp, sp, #0x1, lsl #12'),
                                   ('str','xzr, [sp]'),('cmp','sp, x9'),('b.ne','0x104'),('ret','')))
        self.assertEqual(result['static_bound_bytes'],11*4096+128)
        self.assertEqual(result['bounded_stack_probes'][0]['iterations'],11)

    def test_probe_with_wrong_target_is_rejected(self):
        result=self.check(self.root(('sub','x9, sp, #4097'),('sub','sp, sp, #4096'),
                                   ('str','xzr, [sp]'),('cmp','sp, x9'),('b.ne','0x104'),('ret','')))
        self.assertIsNone(result['static_bound_bytes'])

    def test_unreachable_indirect_does_not_hide_root(self):
        result=self.check(self.root(('sub','sp, sp, #16'),('ret','')),function(0x200,'unreachable',[('blr','x8')]))
        self.assertEqual(result['static_bound_bytes'],16+128)

    def test_looped_preindex_allocation_is_rejected(self):
        result=self.check(self.root(('stp','x0, x1, [sp, #-16]!'),('cbnz','x9, 0x100'),('ret','')))
        self.assertEqual(result['status'],'FAIL')

    def test_below_red_zone_is_rejected(self):
        result=self.check(self.root(('str','x0, [sp, #-256]'),('ret','')))
        self.assertEqual(result['status'],'FAIL')

    def test_tail_to_lower_address_is_not_a_stack_loop(self):
        result=self.check(self.root(('sub','sp, sp, #16'),('b','0x80')),
                          function(0x80,'tail',[('ret','')]))
        self.assertEqual(result['status'],'PASS')

    def test_unreachable_padding_and_landing_pad_are_excluded(self):
        with patch('stack_depth_static.PANIC_CUTS',()), patch('stack_depth_static.SYSTEM_ALLOWANCES',{}):
            result=scoped_analyze(dict(functions=[self.root(('ret',''),('udf','#0'),('blr','x8'))]))
        self.assertEqual(result['status'],'PASS')
        self.assertEqual(result['udf_sites'][0]['classification'],'zero trap padding after return/tail transfer')

    def test_reachable_udf_remains_failure(self):
        with patch('stack_depth_static.PANIC_CUTS',()), patch('stack_depth_static.SYSTEM_ALLOWANCES',{}):
            result=scoped_analyze(dict(functions=[self.root(('udf','#0'))]))
        self.assertEqual(result['status'],'FAIL')

    def test_returning_panic_cut_is_rejected(self):
        with patch('stack_depth_static.PANIC_CUTS',('panic',)), patch('stack_depth_static.SYSTEM_ALLOWANCES',{}):
            result=scoped_analyze(dict(functions=[self.root(('bl','0x200'),('ret','')),function(0x200,'panic',[('ret','')])]))
        self.assertEqual(result['status'],'FAIL')
        self.assertTrue(any('cut function has a return' in reason for _,reason in result['unresolved']))

    def test_unused_allowance_is_rejected(self):
        with patch('stack_depth_static.PANIC_CUTS',()), patch('stack_depth_static.SYSTEM_ALLOWANCES',{'memcpy':4096}):
            result=scoped_analyze(dict(functions=[self.root(('ret',''))]))
        self.assertEqual(result['status'],'FAIL')
        self.assertEqual(result['unused_allow_list'],['memcpy'])

    def retry(self,*pairs):
        from stack_depth_static import shell_retry
        return shell_retry(self.root(*pairs)['instructions'],0x100)

    MASK=(('nop',''),('csetm','x9, lo'),('csetm','x8, lo'),('orr','x8, x8, x9'))

    def test_shell_test_against_all_ones_is_recognized(self):
        result=self.retry(*self.MASK,('cmn','x8, #0x1'),('b.ne','0x120'),('b.lo','0x100'),('ret',''),('ret',''))
        self.assertEqual((result['status'],result['loop_start'],result['loop_end']),('PASS','0x100','0x118'))

    def test_shell_test_for_zero_is_recognized_in_every_form(self):
        for test in ((('cbz','x8, 0x11c'),),(('cmp','x8, #0x0'),('b.eq','0x120')),(('tst','x8, x8'),('b.eq','0x120'))):
            result=self.retry(*self.MASK,*test,('b.lo','0x100'),('ret',''),('ret',''))
            self.assertEqual((result['status'],result['loop_start'],result['compare']['address']),('PASS','0x100',0x110))
        for test in ((('cbnz','x8, 0x100'),),(('cmp','x8, #0'),('b.ne','0x100'))):
            result=self.retry(*self.MASK,*test,('ret',''))
            self.assertEqual((result['status'],result['loop_start'],result['latch']),('PASS','0x100',result['branch']))

    def test_rejected_block_after_the_accepted_code(self):
        result=self.retry(*self.MASK,('cbnz','x8, 0x11c'),('add','sp, sp, #0x10'),('ret',''),('b.lo','0x100'),('ret',''))
        self.assertEqual((result['status'],result['loop_end'],result['sp_adjustments']),('PASS','0x11c',[]))
        result=self.retry(*self.MASK,('cbnz','x8, 0x11c'),('ret',''),('ret',''),('sub','sp, sp, #0x10'),('b.lo','0x100'),('ret',''))
        self.assertEqual(result['status'],'FAIL')

    def test_shell_test_must_be_unique_and_tied_to_the_mask(self):
        one=(*self.MASK,('cbz','x8, 0x11c'),('b.lo','0x100'),('ret',''),('ret',''))
        self.assertEqual(self.retry(*one,*self.MASK[1:],('cbz','x8, 0x11c'))['status'],'FAIL')
        self.assertEqual(self.retry(*one,('cmn','x8, #0x1'),('b.ne','0x100'))['status'],'FAIL')
        for body in ((('nop',''),('cbz','x8, 0x10c'),('b.lo','0x100'),('ret','')),
                     (('nop',''),('csetm','x9, lo'),('csetm','x8, lo'),('orr','x8, x8, x10'),('cbz','x8, 0x11c'),('b.lo','0x100'),('ret',''),('ret','')),
                     (('nop',''),('csetm','x9, lo'),('csetm','x8, hi'),('orr','x8, x8, x9'),('cbz','x8, 0x11c'),('b.lo','0x100'),('ret',''),('ret','')),
                     (*self.MASK,('cbz','x9, 0x11c'),('b.lo','0x100'),('ret',''),('ret','')),
                     (*self.MASK,('cmn','x8, #0x1'),('b.eq','0x120'),('b.lo','0x100'),('ret',''),('ret','')),
                     (*self.MASK,('cbz','x8, 0x11c'),('ret',''),('ret',''),('ret',''))):
            self.assertEqual(self.retry(*body),dict(status='FAIL'))

    def test_stack_write_in_the_retry_loop_is_rejected(self):
        result=self.retry(*self.MASK,('cbz','x8, 0x120'),('sub','sp, sp, #0x10'),('b.lo','0x100'),('ret',''),('ret',''))
        self.assertEqual(result['status'],'FAIL')
        result=self.retry(*self.MASK,('cbz','x8, 0x120'),('bl','0x100'),('b.lo','0x100'),('ret',''),('ret',''))
        self.assertEqual(result['status'],'FAIL')

    def test_all_ones_form_needs_the_mask_anchor(self):
        self.assertEqual(self.retry(('nop',''),('cmn','x8, #0x1'),('b.ne','0x114'),('b.lo','0x100'),('ret',''),('ret','')),dict(status='FAIL'))
        # The real test in a form that is not recognized, with a stack write in its loop, and an
        # unrelated comparison with all ones elsewhere: the unrelated one must not be analyzed.
        result=self.retry(*self.MASK,('mov','x10, x8'),('cbz','x10, 0x128'),('sub','sp, sp, #0x10'),('b.lo','0x100'),('ret',''),
                          ('ret',''),('cmn','x8, #0x1'),('b.ne','0x138'),('b.lo','0x128'),('ret',''),('ret',''))
        self.assertEqual(result,dict(status='FAIL'))

    def test_every_candidate_compare_counts(self):
        one=(*self.MASK,('cmn','x8, #0x1'),('b.ne','0x120'),('b.lo','0x100'),('ret',''),('ret',''))
        self.assertEqual(self.retry(*one)['status'],'PASS')
        self.assertEqual(self.retry(*one,('cmn','x8, #0x1'),('ret','')),dict(status='FAIL'))
        self.assertEqual(self.retry(('cmn','x8, #0x1'),('nop',''),*one),dict(status='FAIL'))
        # A second anchored `orr` counts whatever follows it.
        self.assertEqual(self.retry(*one,*self.MASK[1:],('ret','')),dict(status='FAIL'))
        self.assertEqual(self.retry(*self.MASK,('cmn','x8, #0x1'),('b.eq','0x120'),('b.lo','0x100'),('ret',''),('ret','')),dict(status='FAIL'))

    def test_rejected_block_ends_at_its_first_return_or_jump(self):
        self.assertEqual(self.retry(*self.MASK,('cbnz','x8, 0x118'),('ret',''),('ret',''),('nop',''),('b.lo','0x100'),('ret','')),dict(status='FAIL'))
        self.assertEqual(self.retry(*self.MASK,('cbnz','x8, 0x118'),('ret',''),('b','0x120'),('ret',''),('b.lo','0x100'),('ret','')),dict(status='FAIL'))
        self.assertEqual(self.retry(*self.MASK,('cbz','x8, 0x124'),('ret',''),('b.lo','0x100'),('ret',''),('ret',''),('ret','')),dict(status='FAIL'))
        result=self.retry(*self.MASK,('cbnz','x8, 0x118'),('ret',''),('nop',''),('b','0x100'),('ret',''))
        self.assertEqual((result['status'],result['loop_end']),('PASS','0x11c'))
        result=self.retry(*self.MASK,('cbz','x8, 0x11c'),('cbnz','x3, 0x100'),('ret',''),('ret',''))
        self.assertEqual((result['status'],result['loop_end']),('PASS','0x114'))

    def test_mask_registers_must_reach_the_test_unchanged(self):
        head=(('nop',''),('csetm','x9, lo'))
        tail=(('orr','x8, x8, x9'),('cbz','x8, 0x120'),('b.lo','0x100'),('ret',''),('ret',''))
        self.assertEqual(self.retry(*head,('csetm','x8, lo'),('nop',''),*tail)['status'],'PASS')
        self.assertEqual(self.retry(*head,('cmp','x9, x8'),('csetm','x8, lo'),*tail)['status'],'PASS')
        for between in (('mov','x9, x3'),('mov','w9, w3'),('ldp','x3, x9, [x0]'),('ldr','x3, [x9], #8'),
                        ('b.eq','0x110'),('bl','0x200'),('cbz','x3, 0x110')):
            self.assertEqual(self.retry(*head,between,('csetm','x8, lo'),*tail),dict(status='FAIL'))
        self.assertEqual(self.retry(*head,('csetm','x8, lo'),('mov','x8, x3'),*tail),dict(status='FAIL'))
        # The test must follow the `orr` directly, on the whole register.
        self.assertEqual(self.retry(*self.MASK,('mov','x8, x3'),('cbz','x8, 0x120'),('b.lo','0x100'),('ret',''),('ret','')),dict(status='FAIL'))
        self.assertEqual(self.retry(*self.MASK,('cbz','w8, 0x11c'),('b.lo','0x100'),('ret',''),('ret','')),dict(status='FAIL'))
        self.assertEqual(self.retry(('nop',''),('csetm','w9, lo'),('csetm','w8, lo'),('orr','w8, w8, w9'),('cbz','w8, 0x11c'),('b.lo','0x100'),('ret',''),('ret','')),dict(status='FAIL'))

    def test_debugger_script_recognizes_the_same_shell_test(self):
        from pathlib import Path
        here=Path(__file__).resolve().parent
        texts=[]
        for name in ('stack_depth_static.py','stack_depth_lldb.py'):
            text=(here/name).read_text();start=text.index('def shell_gate(ins):')
            texts.append(text[start:text.index('\ndef ',start+1)].rstrip())
        self.assertEqual(texts[0],texts[1])

    def test_missing_root_is_rejected(self):
        with self.assertRaises(ValueError):self.check(function(0x200,'other',[('ret','')]))

    def test_margin_boundary_and_missing_observation(self):
        self.assertEqual(check_margin({'max_depth_bytes':98304})['status'],'PASS')
        self.assertEqual(check_margin({'max_depth_bytes':98305})['status'],'FAIL')
        self.assertEqual(check_margin({'max_depth_bytes':None})['reason'],'no valid measured depth')
        self.assertEqual(check_margin({'max_depth_bytes':65536},bound=1)['reason'],'measured depth plus margin exceeds bound')


if __name__=='__main__':unittest.main()
