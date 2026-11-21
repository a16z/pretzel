/* An earlier C form of the routines of ../src/ct_rq_helpers_mac.S. It is compiled by nothing and
 * does not reproduce that file, which is the source; README.md lists the known differences.
 * Invocation recorded for it (Apple clang 17.0.0, clang-1700.0.13.5):
 * clang -O3 -ffreestanding -fno-asynchronous-unwind-tables -fno-unwind-tables
 *       -fno-stack-protector -S helpers.c -o helpers-mac-raw.S
 * No compiler comparison runs in CI.
 */
#include <stdint.h>
#include <stddef.h>
#include <arm_neon.h>
#define RQ_CAP 3
static inline uint64_t choose(uint64_t m,uint64_t a,uint64_t b){return(a&m)|(b&~m);}
static __attribute__((always_inline)) inline void finish(uint64_t out[16][2],const uint64_t row[16][2],const uint64_t draw[16][4],unsigned k,uint64_t pairs,uint64_t bounds,uint64_t H){
 for(int i=0;i<16;i++){
  uint64_t top=row[i][0],m=row[i][1],v=draw[i][0],col=draw[i][3];
  uint64_t primary=-(uint64_t)(v<top),dropped=(m>>(19+2*k))&255,flip=(m>>(18+2*k))&1;
  uint64_t tag0=(2*col-1+2*dropped)|0x5000|(flip<<13);
  tag0=choose(-(uint64_t)(col>pairs),bounds|0x4000,tag0);tag0&=-(uint64_t)(col!=0);
  uint64_t tag=choose(primary,tag0,m&32767),phase=((m>>15)&((2ULL<<k)-1))&~primary;
  out[i][0]=(tag&4095)+((((draw[i][2]+phase)>>k)^(tag>>13))&(tag>>12)&1);
  out[i][1]=-(uint64_t)((v==0)|(v==top)|((top!=UINT64_MAX)&(v==top+1))|(v==H));
 }
}
static inline uint64_t less192(const uint64_t*a,const uint64_t*b){return (a[0]<b[0])|((a[0]==b[0])&((a[1]<b[1])|((a[1]==b[1])&(a[2]<b[2]))));}
static void finish_full(uint64_t out[16][2],const uint64_t hi[16][2],const uint64_t lo[16][2],const uint64_t draw[16][4],unsigned k,uint64_t pairs,uint64_t bounds){
 for(int i=0;i<16;i++){
  uint64_t t[3]={hi[i][0],lo[i][0],lo[i][1]},m=hi[i][1],col=draw[i][3],primary=-less192(draw[i],t);
  uint64_t tag0=(2*col-1+2*((m>>(19+2*k))&255))|0x5000|(((m>>(18+2*k))&1)<<13);tag0=choose(-(uint64_t)(col>pairs),bounds|0x4000,tag0);tag0&=-(uint64_t)(col!=0);
  uint64_t tag=choose(primary,tag0,m&32767),phase=((m>>15)&((2ULL<<k)-1))&~primary;
  uint64_t low=draw[i][2]-t[2],borrow=(draw[i][2]<t[2]),mid=draw[i][1]-t[1]-borrow,borrow2=(draw[i][1]<t[1])|((draw[i][1]==t[1])&borrow),high=draw[i][0]-t[0]-borrow2;
  uint64_t cap=(m>>(16+k))&((4ULL<<k)-1),at=-(uint64_t)((high==0)&(mid==0)&(low<cap)),pt=-(uint64_t)((draw[i][0]==0)&(draw[i][1]==0)&(draw[i][2]<(2ULL<<k)));
  out[i][0]=(tag&4095)+((((draw[i][2]+phase)>>k)^(tag>>13))&(tag>>12)&1);
  out[i][1]=choose(primary,pt,at)&-(uint64_t)((tag>>14)&1);
 }
}

#include <arm_neon.h>
static __attribute__((always_inline)) inline void extract_queue(uint64_t queue[16][4],const uint64_t draw[16][4],const uint32_t ranks[16]){
 uint8x16x4_t hi0,hi1,meta;uint32x4_t rank[4];
 for(int block=0;block<4;block++){
  uint64x2x4_t a=vld4q_u64(&draw[4*block][0]),b=vld4q_u64(&draw[4*block+2][0]);
  if(block<2){hi0.val[2*block]=vreinterpretq_u8_u64(a.val[0]);hi0.val[2*block+1]=vreinterpretq_u8_u64(b.val[0]);}else{hi1.val[2*(block-2)]=vreinterpretq_u8_u64(a.val[0]);hi1.val[2*(block-2)+1]=vreinterpretq_u8_u64(b.val[0]);}
  uint32x2_t ma=vmovn_u64(vorrq_u64(vandq_u64(a.val[2],vdupq_n_u64(65535)),vshlq_n_u64(a.val[3],16)));
  uint32x2_t mb=vmovn_u64(vorrq_u64(vandq_u64(b.val[2],vdupq_n_u64(65535)),vshlq_n_u64(b.val[3],16)));
  meta.val[block]=vreinterpretq_u8_u32(vcombine_u32(ma,mb));rank[block]=vld1q_u32(ranks+4*block);
 }
 const uint32_t pos_data[16]={1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
 const uint8_t byte_data[16]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};uint8x16_t bytes=vld1q_u8(byte_data);
 for(unsigned q=0;q<RQ_CAP;q++){
  uint32x4_t a=vandq_u32(vceqq_u32(rank[0],vdupq_n_u32(q+1)),vld1q_u32(pos_data)),b=vandq_u32(vceqq_u32(rank[1],vdupq_n_u32(q+1)),vld1q_u32(pos_data+4));
  uint32x4_t c=vandq_u32(vceqq_u32(rank[2],vdupq_n_u32(q+1)),vld1q_u32(pos_data+8)),d=vandq_u32(vceqq_u32(rank[3],vdupq_n_u32(q+1)),vld1q_u32(pos_data+12));
  unsigned idx=vmaxvq_u32(vorrq_u32(vorrq_u32(a,b),vorrq_u32(c,d)))-1;
  uint8x16_t hi_index=vaddq_u8(vdupq_n_u8((uint8_t)(8*idx)),bytes),meta_index=vaddq_u8(vdupq_n_u8((uint8_t)(4*idx)),bytes);
  uint64_t high=vgetq_lane_u64(vreinterpretq_u64_u8(vorrq_u8(vqtbl4q_u8(hi0,hi_index),vqtbl4q_u8(hi1,vsubq_u8(hi_index,vdupq_n_u8(64))))),0);
  uint32_t packed=vgetq_lane_u32(vreinterpretq_u32_u8(vqtbl4q_u8(meta,meta_index)),0);
  queue[q][0]|=high;queue[q][2]|=packed&65535;queue[q][3]|=packed>>16;
 }
}
static __attribute__((always_inline)) inline uint64_t repair_compact(uint32_t*out,uint32_t*records,const uint64_t resolved[16][2],const uint64_t reject[8],size_t n,uint32_t rank){
 uint32_t resolved32[8]={0};for(unsigned q=0;q<RQ_CAP;q++)resolved32[q]=(uint32_t)resolved[q][0]|((resolved[q][1]&1)<<12)|((uint32_t)reject[q]<<13);
 uint8x16x2_t table={{vreinterpretq_u8_u32(vld1q_u32(resolved32)),vreinterpretq_u8_u32(vld1q_u32(resolved32+4))}};
 uint32x4_t zero=vdupq_n_u32(0),ones=vdupq_n_u32(1);uint32_t removed=0;const uint32_t pos[4]={0,1,2,3};uint32x4_t positions=vld1q_u32(pos);
 for(size_t i=0;i<((n+RQ_CAP+3)&~3u);i+=4){
  uint32x4_t word=vld1q_u32(records+i),r=vshrq_n_u32(word,12),idx=vsubq_u32(r,ones),valid=vcleq_u32(idx,vdupq_n_u32(RQ_CAP-1));
  uint32x4_t byteidx=vaddq_u32(vmulq_n_u32(idx,0x04040404),vdupq_n_u32(0x03020100));byteidx=vbslq_u32(valid,byteidx,vdupq_n_u32(0xffffffff));
  uint32x4_t tag=vreinterpretq_u32_u8(vqtbl2q_u8(table,vreinterpretq_u8_u32(byteidx)));tag=vbslq_u32(vceqq_u32(r,zero),vandq_u32(word,vdupq_n_u32(4095)),tag);
  uint32x4_t rejected=vandq_u32(vshrq_n_u32(tag,13),ones),prefix=vaddq_u32(rejected,vextq_u32(zero,rejected,3));prefix=vaddq_u32(prefix,vextq_u32(zero,prefix,2));
  uint32x4_t dest=vsubq_u32(vaddq_u32(vdupq_n_u32((uint32_t)i-removed),positions),vsubq_u32(prefix,rejected));removed+=vgetq_lane_u32(prefix,3);
  uint32x4_t packed=vorrq_u32(vorrq_u32(vandq_u32(tag,vdupq_n_u32(8191)),vshlq_n_u32(dest,16)),vdupq_n_u32(0x80000000));vst1q_u32(records+i,vandq_u32(packed,vceqq_u32(rejected,zero)));
 }
 uint32x4_t ties=zero,keep=vdupq_n_u32(-(uint32_t)(rank<=RQ_CAP));
 for(size_t j=0;j<n;j+=4){
  uint32x4_t tag=zero,expected=vaddq_u32(vdupq_n_u32(0x8000u+(uint32_t)j),positions);
  for(unsigned d=0;d<=RQ_CAP;d++){uint32x4_t word=vld1q_u32(records+j+d);tag=vorrq_u32(tag,vandq_u32(word,vceqq_u32(vshrq_n_u32(word,16),expected)));}
  ties=vorrq_u32(ties,vandq_u32(vshrq_n_u32(tag,12),ones));vst1q_u32(out+j,vandq_u32(vandq_u32(tag,vdupq_n_u32(4095)),keep));
 }
 return -(uint64_t)((rank>RQ_CAP)|(vmaxvq_u32(ties)!=0));
}

void pretzel44_rq_common(uint64_t queue[16][4],uint32_t*records,uint32_t*rank,const uint64_t draw[16][4],const uint64_t hi[16][2],unsigned k,uint64_t pairs,uint64_t bounds,uint64_t H,size_t len){
 uint64_t partial[16][2];uint32_t ranks[16]={0};finish(partial,hi,draw,k,pairs,bounds,H);
 for(size_t j=0;j<len;j++){uint32_t rare=partial[j][1]&1;*rank+=rare;uint32_t r=*rank&-(uint32_t)rare;records[j]=(uint32_t)partial[j][0]|(r<<12);ranks[j]=r;}
 extract_queue(queue,draw,ranks);
}
void pretzel44_rq_resolve(uint64_t resolved[16][2],uint64_t reject[8],const uint64_t draw[16][4],const uint64_t hi[16][2],const uint64_t lo[16][2],unsigned k,uint64_t pairs,uint64_t bounds,const uint64_t Z[3]){
 finish_full(resolved,hi,lo,draw,k,pairs,bounds);for(unsigned q=0;q<3;q++)reject[q]=less192(Z,draw[q]);
}
uint64_t pretzel44_rq_repair(uint32_t*out,uint32_t*records,const uint64_t resolved[16][2],const uint64_t reject[8],size_t n,uint32_t rank){return repair_compact(out,records,resolved,reject,n,rank);}
