"""Positive and adversarial cases for the three checked indirect-edge rules."""
import unittest
from unittest.mock import patch
from test_stack_depth_static import function
from stack_depth_static import analyze
from stack_depth_resolve import resolve,termination_postdominators,ONCE


class Data:
    def __init__(self,fixups=None,section='__DATA,__thread_vars'):
        self.fixups=fixups or {};self.name=section
    def pointer(self,a):
        if a not in self.fixups:raise ValueError('missing fixup')
        return self.fixups[a]
    def section(self,a,size=8):return dict(name=self.name,address=0x1000,size=48)


class ResolveTests(unittest.TestCase):
    def run_image(self,fs,data):
        with patch('stack_depth_image.MachO',return_value=data),patch('stack_depth_static.PANIC_CUTS',()),patch('stack_depth_static.SYSTEM_ALLOWANCES',{'tlv_get_addr':4096} if any('import' in x for x in data.fixups.values()) else {}):
            return analyze(dict(functions=fs),'fixture')
    def root(self,pairs):return function(0x100,'keygen_with_entropy_unscrubbed',pairs)
    def tls(self,**kw):
        f=self.root([('adrp','x0, 1'),('add','x0, x0, #0'),('ldr','x8, [x0]'),('blr','x8'),('ret','')])
        return f,Data({0x1000:dict(import_name='unused',**{'import':kw.get('symbol','__tlv_bootstrap')})},kw.get('section','__DATA,__thread_vars'))
    def test_tls_authenticated_descriptor(self):
        f,d=self.tls();r=self.run_image([f],d)
        self.assertEqual(r['static_bound_bytes'],4224)
        self.assertEqual(r['indirect_resolutions'][0]['descriptor'],'0x1000')
    def test_tls_wrong_import_fails(self):
        f,d=self.tls(symbol='malloc');self.assertIsNone(self.run_image([f],d)['static_bound_bytes'])
    def test_tls_wrong_section_fails(self):
        f,d=self.tls(section='__DATA,__data');self.assertIsNone(self.run_image([f],d)['static_bound_bytes'])
    def test_tls_cross_block_fails(self):
        f,d=self.tls();f['instructions'][1].update(mnemonic='cbz',operands='x1, 0x108')
        self.assertIsNone(self.run_image([f],d)['static_bound_bytes'])
    def test_tls_register_clobber_fails(self):
        f,d=self.tls();f['instructions'][2].update(mnemonic='mov',operands='x8, x9')
        self.assertIsNone(self.run_image([f],d)['static_bound_bytes'])
    def test_tls_got_descriptor(self):
        f,d=self.tls();f['instructions'][1].update(mnemonic='ldr',operands='x0, [x0, #0x100]');d.fixups[0x1100]={'target':0x1000}
        self.assertEqual(self.run_image([f],d)['status'],'PASS')
    def once(self,recursive=False,unknown=False):
        root=self.root([('adrp','x3, 2'),('add','x3, x3, #0'),('bl','0x200'),('ret','')])
        once=function(0x200,ONCE,[('sub','sp, sp, #32'),('mov','x21, x3'),('ldr','x8, [x21, #0x20]'),('blr','x8'),('ret','')])
        closure=function(0x300,'closure',[('bl','0x100') if recursive else ('sub','sp, sp, #64'),('ret','')])
        if unknown:root['instructions'][1].update(mnemonic='mov',operands='x3, x9')
        return [root,once,closure],Data({0x2020:{'target':0x300}})
    def test_once_charges_frame_and_closure(self):
        fs,d=self.once();r=self.run_image(fs,d)
        self.assertEqual(r['static_bound_bytes'],128*3+32+64)
        self.assertEqual(len(r['once_contexts']),1)
    def test_nested_once_contexts_remain_distinct(self):
        fs,d=self.once()
        fs[2]=function(0x300,'closure',[('adrp','x3, 3'),('add','x3, x3, #0'),('bl','0x200'),('ret','')])
        fs.append(function(0x400,'nested_closure',[('sub','sp, sp, #64'),('ret','')]))
        d.fixups[0x3020]={'target':0x400}
        r=self.run_image(fs,d)
        self.assertEqual(r['status'],'PASS')
        self.assertEqual(r['static_bound_bytes'],128*5+32*2+64)
        self.assertEqual({x['vtable'] for x in r['once_contexts']},{'0x2000','0x3000'})
    def test_once_other_callee_is_charged(self):
        fs,d=self.once()
        fs[1]=function(0x200,ONCE,[('sub','sp, sp, #32'),('mov','x21, x3'),('ldr','x8, [x21, #0x20]'),('blr','x8'),('bl','0x500'),('ret','')])
        fs.append(function(0x500,'wait',[('sub','sp, sp, #8192'),('ret','')]))
        r=self.run_image(fs,d)
        self.assertEqual(r['static_bound_bytes'],128*3+32+8192)
    def test_atomic_target_clobber_is_rejected(self):
        f,d=self.tls()
        f=self.root([('adrp','x0, 1'),('ldr','x8, [x0]'),('ldadd','x9, x8, [x10]'),('blr','x8'),('ret','')])
        self.assertIsNone(self.run_image([f],d)['static_bound_bytes'])
    def test_writeback_descriptor_clobber_is_rejected(self):
        f,d=self.tls()
        f=self.root([('adrp','x0, 1'),('ldr','x8, [x0]'),('str','x9, [x0], #8'),('blr','x8'),('ret','')])
        self.assertIsNone(self.run_image([f],d)['static_bound_bytes'])
    def test_once_unknown_vtable_fails(self):
        fs,d=self.once(unknown=True);self.assertIsNone(self.run_image(fs,d)['static_bound_bytes'])
    def test_once_cycle_fails(self):
        fs,d=self.once(recursive=True);r=self.run_image(fs,d)
        self.assertIsNone(r['static_bound_bytes']);self.assertTrue(any('recursive' in e[1] for e in r['unresolved']))
    def test_once_bad_call_entry_fails(self):
        fs,d=self.once();d.fixups.clear();self.assertIsNone(self.run_image(fs,d)['static_bound_bytes'])
    def test_postdominance_cycle_is_not_termination(self):
        self.assertNotIn(1,termination_postdominators({1:[1,2],2:[]},{2:'abort'}))
    def abort_case(self,return_path=False,returning_abort=False):
        root=self.root([('bl','0x200'),('cbz','x0, 0x10c') if return_path else ('nop',''),('bl','0x400'),('ret','')])
        root['instructions'][2]['comment']='symbol stub for: abort'
        fmt=function(0x200,'formatting',[('blr','x8'),('ret','')])
        fs=[root,fmt]
        if returning_abort:fs.append(function(0x400,'abort',[('ret','')]))
        return self.run_image(fs,Data())
    def test_abort_postdominates_formatting(self):
        r=self.abort_case();self.assertEqual(r['status'],'PASS');self.assertEqual(len(r['abort_excluded_indirect_sites']),1)
    def test_normal_return_keeps_indirect_unresolved(self):self.assertIsNone(self.abort_case(return_path=True)['static_bound_bytes'])
    def test_abort_name_with_return_is_not_a_cut(self):self.assertIsNone(self.abort_case(returning_abort=True)['static_bound_bytes'])
    def test_injected_unresolved_indirect_fails(self):
        f=self.root([('blr','x17'),('ret','')]);r=self.run_image([f],Data())
        self.assertEqual(r['status'],'FAIL');self.assertIsNone(r['static_bound_bytes'])


if __name__=='__main__':unittest.main()
