/* Hint context and hint cost routines (`pretzel44_hint_context_impl`, `pretzel44_hint_cost_impl`,
 * `pretzel44_hint_cost_bulk_impl`), called through the wrappers of `reservoir-wrapper.S`. */
#include <stdint.h>
#include <stddef.h>
#include <arm_neon.h>
static const uint8_t hk_flags[64] __attribute__((aligned(16)))={0,0,1,1,1,1,1,1,1,3,3,5,0,0,1,1,1,1,1,1,3,3,5,0,0,1,1,1,1,1,1,3,3,5,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
static const uint8_t hk_delta[64] __attribute__((aligned(16)))={74,0,0,0,0,0,0,68,0,0,0,0,64,0,0,62,0,0,60,0,0,58,0,57,0,56,0,55,0,54,0,53,53,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
typedef struct{uint8x16_t rank,flip,valid;} HkState;
static inline uint8x16_t hk_table64(const uint8_t*t,uint8x16_t ix){
 uint8x16x4_t data;for(unsigned i=0;i<4;i++)data.val[i]=vld1q_u8(t+16*i);return vqtbl4q_u8(data,ix);
}
static inline uint8x16_t hk_pack32(uint32x4_t a,uint32x4_t b,uint32x4_t c,uint32x4_t d){
 uint16x8_t lo=vcombine_u16(vmovn_u32(a),vmovn_u32(b)),hi=vcombine_u16(vmovn_u32(c),vmovn_u32(d));
 return vcombine_u8(vmovn_u16(lo),vmovn_u16(hi));
}
__attribute__((always_inline)) static inline HkState hk_context(const int32_t xs[16]){
 uint32x4_t safe[4],lab[4],ok[4];uint32x2_t mul=vdup_n_u32(34*559168);
 #pragma clang loop unroll(full)
 for(unsigned i=0;i<4;i++){
  uint32x4_t x=vreinterpretq_u32_s32(vld1q_s32(xs+4*i));ok[i]=vcltq_u32(x,vdupq_n_u32(7681));safe[i]=vandq_u32(x,ok[i]);
  uint64x2_t lo=vmull_u32(vget_low_u32(safe[i]),mul),hi=vmull_high_u32(safe[i],vcombine_u32(mul,mul));
  lab[i]=vcombine_u32(vshrn_n_u64(lo,32),vshrn_n_u64(hi,32));
 }
 uint8x16_t labels=hk_pack32(lab[0],lab[1],lab[2],lab[3]),flags=hk_table64(hk_flags,labels),narrow=vtstq_u8(flags,vdupq_n_u8(4));
 uint16x8_t ss[2],oo[2];
 #pragma clang loop unroll(full)
 for(unsigned i=0;i<2;i++){
  uint16x8_t l=vcombine_u16(vmovn_u32(lab[2*i]),vmovn_u32(lab[2*i+1]));
  uint16x8_t x=vcombine_u16(vmovn_u32(safe[2*i]),vmovn_u32(safe[2*i+1]));
  uint16x8_t left=vmulq_n_u16(l,226);left=vaddq_u16(left,vcgeq_u16(l,vdupq_n_u16(12)));left=vaddq_u16(left,vcgeq_u16(l,vdupq_n_u16(23)));
  oo[i]=vsubq_u16(x,left);
  uint16x8_t n= i?vmovl_high_u8(narrow):vmovl_u8(vget_low_u8(narrow));
  uint16x8_t pivot=vsubq_u16(vdupq_n_u16(225),vandq_u16(n,vdupq_n_u16(1)));
  ss[i]=vminq_u16(oo[i],vsubq_u16(pivot,oo[i]));
 }
 uint8x16_t coord=vcombine_u8(vmovn_u16(ss[0]),vmovn_u16(ss[1])),offset=vcombine_u8(vmovn_u16(oo[0]),vmovn_u16(oo[1]));
 uint8x16_t right=vcgtq_u8(offset,vdupq_n_u8(112)),delta=hk_table64(hk_delta,vsubq_u8(coord,vdupq_n_u8(40)));
 delta=vbslq_u8(vcgeq_u8(coord,vdupq_n_u8(74)),vdupq_n_u8(52),delta);
 uint8x16_t rank=vaddq_u8(coord,vandq_u8(delta,narrow)),f23=vtstq_u8(flags,vdupq_n_u8(1)),f202=vtstq_u8(flags,vdupq_n_u8(2));
 uint8x16_t exceptional=vandq_u8(vceqq_u8(coord,vdupq_n_u8(23)),vorrq_u8(narrow,vorrq_u8(vbicq_u8(f23,right),vbicq_u8(right,f202))));
 rank=vbslq_u8(exceptional,vdupq_n_u8(113),rank);
 return(HkState){rank,veorq_u8(right,exceptional),hk_pack32(ok[0],ok[1],ok[2],ok[3])};
}
__attribute__((noinline)) void pretzel44_hint_context_impl(uint16_t out[16],uint32_t valid[16],const int32_t xs[16]){
 HkState h=hk_context(xs);
 #pragma clang loop unroll(full)
 for(unsigned i=0;i<2;i++){
  uint16x8_t rank=i?vmovl_high_u8(h.rank):vmovl_u8(vget_low_u8(h.rank));
  uint16x8_t flip=i?vmovl_high_u8(h.flip):vmovl_u8(vget_low_u8(h.flip));
  uint16x8_t ok=i?vmovl_high_u8(h.valid):vmovl_u8(vget_low_u8(h.valid));ok=vceqq_u16(ok,vdupq_n_u16(255));
  uint16x8_t folded=vorrq_u16(rank,vshlq_n_u16(vandq_u16(flip,vdupq_n_u16(1)),8));
  vst1q_u16(out+8*i,vbslq_u16(ok,folded,vdupq_n_u16(65535)));
  vst1q_u32(valid+8*i,vceqq_u32(vmovl_u16(vget_low_u16(ok)),vdupq_n_u32(65535)));
  vst1q_u32(valid+8*i+4,vceqq_u32(vmovl_high_u16(ok),vdupq_n_u32(65535)));
 }
}
static inline uint64_t hk_sum_bytes(uint8x16_t x){
 uint64_t out;asm volatile("uaddlv h31,%1.16b\numov %w0,v31.h[0]":"=r"(out):"w"(x):"v31");return out;
}
__attribute__((noinline)) uint64_t pretzel44_hint_cost_impl(const uint8_t*table,size_t chunks,const int32_t xs[16],const int32_t hints[16],size_t count){
 HkState context=hk_context(xs);uint32x4_t hh[4],h_ok[4];
 #pragma clang loop unroll(full)
 for(unsigned i=0;i<4;i++){hh[i]=vreinterpretq_u32_s32(vld1q_s32(hints+4*i));h_ok[i]=vcltq_u32(vaddq_u32(hh[i],vdupq_n_u32(3)),vdupq_n_u32(7));}
 uint8x16_t h=hk_pack32(hh[0],hh[1],hh[2],hh[3]),valid=vandq_u8(context.valid,hk_pack32(h_ok[0],h_ok[1],h_ok[2],h_ok[3]));
 h=vbslq_u8(context.flip,vreinterpretq_u8_s8(vnegq_s8(vreinterpretq_s8_u8(h))),h);
 uint8x16_t sym=vaddq_u8(h,vdupq_n_u8(1)),middle=vcltq_u8(sym,vdupq_n_u8(3));sym=vandq_u8(sym,middle);
 uint16x8_t index[2];
 index[0]=vaddq_u16(vmulq_n_u16(vmovl_u8(vget_low_u8(context.rank)),3),vmovl_u8(vget_low_u8(sym)));
 index[1]=vaddq_u16(vmulq_n_u16(vmovl_high_u8(context.rank),3),vmovl_high_u8(sym));
 uint8x16_t lo=vcombine_u8(vmovn_u16(vandq_u16(index[0],vdupq_n_u16(63))),vmovn_u16(vandq_u16(index[1],vdupq_n_u16(63))));
 uint8x16_t hi=vcombine_u8(vmovn_u16(vshrq_n_u16(index[0],6)),vmovn_u16(vshrq_n_u16(index[1],6)));
 uint8x16_t p0=vdupq_n_u8(0),p1=p0,p2=p0;
 for(size_t c=0;c<chunks;c++){
  uint8x16_t sel=vornq_u8(lo,vceqq_u8(hi,vdupq_n_u8(c)));
  uint8x16x4_t data;
  for(unsigned j=0;j<4;j++)data.val[j]=vld1q_u8(table+c*192+16*j);p0=vqtbx4q_u8(p0,data,sel);
  for(unsigned j=0;j<4;j++)data.val[j]=vld1q_u8(table+c*192+64+16*j);p1=vqtbx4q_u8(p1,data,sel);
  for(unsigned j=0;j<4;j++)data.val[j]=vld1q_u8(table+c*192+128+16*j);p2=vqtbx4q_u8(p2,data,sel);
 }
 static const uint8_t iota[16]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
 uint8x16_t live=vcltq_u8(vld1q_u8(iota),vdupq_n_u8(count));
 uint8x16_t rare_bad=vorrq_u8(vbicq_u8(vceqq_u8(h,vdupq_n_u8(253)),vtstq_u8(p2,vdupq_n_u8(64))),vbicq_u8(vceqq_u8(h,vdupq_n_u8(3)),vtstq_u8(p2,vdupq_n_u8(128))));
 uint8x16_t good=vbicq_u8(valid,rare_bad),G=vandq_u8(good,live),M=vandq_u8(G,middle);
 uint8x16_t a0=vandq_u8(p0,M),a1=vandq_u8(p1,M),a2=vandq_u8(vbslq_u8(middle,vandq_u8(p2,vdupq_n_u8(15)),vdupq_n_u8(12)),G);
 uint8x16_t bad=vandq_u8(vbicq_u8(live,good),vdupq_n_u8(1));
 return hk_sum_bytes(a0)+(hk_sum_bytes(a1)<<8)+(hk_sum_bytes(a2)<<16)+(hk_sum_bytes(bad)<<31);
}


// Exact whole-field private pass. Input count is a public multiple of 32,
// at most 1024, and both borrowed input slices contain that many i32 values.
typedef struct {uint8x16_t lo,hi,h;} HkDescriptor;
__attribute__((always_inline)) static inline HkDescriptor hk_prepare_pair_half(const int32_t xs[16],const int32_t hints[16]) {
 HkState context=hk_context(xs);uint32x4_t hh[4],h_ok[4];
 #pragma clang loop unroll(full)
 for(unsigned i=0;i<4;i++){hh[i]=vreinterpretq_u32_s32(vld1q_s32(hints+4*i));h_ok[i]=vcltq_u32(vaddq_u32(hh[i],vdupq_n_u32(3)),vdupq_n_u32(7));}
 uint8x16_t h=hk_pack32(hh[0],hh[1],hh[2],hh[3]),valid=vandq_u8(context.valid,hk_pack32(h_ok[0],h_ok[1],h_ok[2],h_ok[3]));
 h=vbslq_u8(context.flip,vreinterpretq_u8_s8(vnegq_s8(vreinterpretq_s8_u8(h))),h);
 uint8x16_t sym=vaddq_u8(h,vdupq_n_u8(1)),middle=vcltq_u8(sym,vdupq_n_u8(3));sym=vandq_u8(sym,middle);
 uint16x8_t index[2];
 index[0]=vaddq_u16(vmulq_n_u16(vmovl_u8(vget_low_u8(context.rank)),3),vmovl_u8(vget_low_u8(sym)));
 index[1]=vaddq_u16(vmulq_n_u16(vmovl_high_u8(context.rank),3),vmovl_high_u8(sym));
 uint8x16_t lo=vcombine_u8(vmovn_u16(vandq_u16(index[0],vdupq_n_u16(63))),vmovn_u16(vandq_u16(index[1],vdupq_n_u16(63))));
 uint8x16_t hi=vcombine_u8(vmovn_u16(vshrq_n_u16(index[0],6)),vmovn_u16(vshrq_n_u16(index[1],6)));

 return (HkDescriptor){lo,vorrq_u8(hi,vmvnq_u8(valid)),h};
}
__attribute__((always_inline)) static inline uint64_t hk_reduce_full(HkDescriptor d,uint8x16_t p0,uint8x16_t p1,uint8x16_t p2) {
 uint8x16_t middle=vcltq_u8(vaddq_u8(d.h,vdupq_n_u8(1)),vdupq_n_u8(3));
 uint8x16_t valid=vcltq_u8(d.hi,vdupq_n_u8(8));
 uint8x16_t rare_bad=vorrq_u8(vbicq_u8(vceqq_u8(d.h,vdupq_n_u8(253)),vtstq_u8(p2,vdupq_n_u8(64))),vbicq_u8(vceqq_u8(d.h,vdupq_n_u8(3)),vtstq_u8(p2,vdupq_n_u8(128))));
 uint8x16_t G=vbicq_u8(valid,rare_bad),M=vandq_u8(G,middle);
 uint8x16_t a0=vandq_u8(p0,M),a1=vandq_u8(p1,M),a2=vandq_u8(vbslq_u8(middle,vandq_u8(p2,vdupq_n_u8(15)),vdupq_n_u8(12)),G);
 uint8x16_t bad=vandq_u8(vmvnq_u8(G),vdupq_n_u8(1));
 return hk_sum_bytes(a0)+(hk_sum_bytes(a1)<<8)+(hk_sum_bytes(a2)<<16)+(hk_sum_bytes(bad)<<31);
}
__attribute__((noinline)) uint64_t pretzel44_hint_cost_bulk_impl(const uint8_t*table,size_t chunks,const int32_t*xs,const int32_t*hints,size_t count) {
 uint64_t total=0;
 for(size_t off=0;off<count;off+=32) {
  HkDescriptor a=hk_prepare_pair_half(xs+off,hints+off),b=hk_prepare_pair_half(xs+off+16,hints+off+16);
  uint8x16_t a0=vdupq_n_u8(0),a1=a0,a2=a0,b0=a0,b1=a0,b2=a0;
  for(size_t c=0;c<chunks;c++) {
   uint8x16_t sa=vornq_u8(a.lo,vceqq_u8(a.hi,vdupq_n_u8(c))),sb=vornq_u8(b.lo,vceqq_u8(b.hi,vdupq_n_u8(c)));
   uint8x16x4_t data;
   for(unsigned j=0;j<4;j++)data.val[j]=vld1q_u8(table+c*192+16*j);
   a0=vqtbx4q_u8(a0,data,sa);b0=vqtbx4q_u8(b0,data,sb);
   for(unsigned j=0;j<4;j++)data.val[j]=vld1q_u8(table+c*192+64+16*j);
   a1=vqtbx4q_u8(a1,data,sa);b1=vqtbx4q_u8(b1,data,sb);
   for(unsigned j=0;j<4;j++)data.val[j]=vld1q_u8(table+c*192+128+16*j);
   a2=vqtbx4q_u8(a2,data,sa);b2=vqtbx4q_u8(b2,data,sb);
  }
  total+=hk_reduce_full(a,a0,a1,a2)+hk_reduce_full(b,b0,b1,b2);
 }
 return total;
}
