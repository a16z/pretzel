#include <stdint.h>
#include <stddef.h>
#include <arm_neon.h>
/* Interleave four independent four-lane reservoir groups. Same per-block
 * step order and same exact debit, without an intervening gather call. */
__attribute__((noinline)) void pretzel44_reservoir_main_rows(uint32_t out[16][8],uint32_t rare[16],const uint16_t columns[8][16],const uint32_t input[2][16],const uint32_t rows[8][2][16]){
 uint32x4_t a[4],b[4],used[4];
 #pragma clang loop unroll(full)
 for(unsigned j=0;j<4;j++){a[j]=vld1q_u32(input[0]+4*j);b[j]=vld1q_u32(input[1]+4*j);used[j]=vdupq_n_u32(0);}
 /* Adjacent steps keep four full-width
  * vectors; all four reservoir recurrence chains preserve their step order.
  * The actual caller supplies disjoint output, input, columns and row spans. */
 for(unsigned pair=0;pair<4;pair++){
  uint32x4_t first[4];
  #pragma clang loop unroll(full)
  for(unsigned half=0;half<2;half++){
   unsigned step=2*pair+half;
  #pragma clang loop unroll(full)
  for(unsigned j=0;j<4;j++){
   uint32x4_t p=vld1q_u32(rows[step][0]+4*j),m=vld1q_u32(rows[step][1]+4*j),idx=vmovl_u16(vld1_u16(columns[step]+4*j)),diff=veorq_u32(a[j],p);
   uint32x4_t endpoint=vceqq_u32(vandq_u32(idx,vdupq_n_u32(511)),vdupq_n_u32(0));
   uint32x4_t count=vminq_u32(vaddq_u32(vclzq_u32(diff),vdupq_n_u32(1)),vdupq_n_u32(32));count=vbslq_u32(endpoint,vdupq_n_u32(1),count);
   uint32x4_t unresolved=vbicq_u32(vceqq_u32(diff,vdupq_n_u32(0)),endpoint);
   used[j]=vaddq_u32(used[j],vorrq_u32(count,vandq_u32(unresolved,vdupq_n_u32(256))));
   uint32x4_t primary=vorrq_u32(endpoint,vcltq_u32(a[j],p));
   uint32x4_t mag=vandq_u32(vbslq_u32(primary,idx,m),vdupq_n_u32(511));
   uint32x4_t value=vaddq_u32(vsubq_u32(vshlq_n_u32(mag,1),vdupq_n_u32(1)),vshrq_n_u32(idx,9));value=vandq_u32(value,vcgtq_u32(mag,vdupq_n_u32(0)));
   int32x4_t left=vreinterpretq_s32_u32(count),right=vsubq_s32(left,vdupq_n_s32(32));
   a[j]=vorrq_u32(vshlq_u32(a[j],left),vshlq_u32(b[j],right));b[j]=vshlq_u32(b[j],left);
   if(half==0){first[j]=value;}else{
    uint32x4_t lo=vzip1q_u32(first[j],value),hi=vzip2q_u32(first[j],value);
    vst1_u32(out[4*j+0]+2*pair,vget_low_u32(lo));
    vst1q_lane_u64((uint64_t*)(out[4*j+1]+2*pair),vreinterpretq_u64_u32(lo),1);
    vst1_u32(out[4*j+2]+2*pair,vget_low_u32(hi));
    vst1q_lane_u64((uint64_t*)(out[4*j+3]+2*pair),vreinterpretq_u64_u32(hi),1);
   }

  }
  }
 }
 #pragma clang loop unroll(full)
 for(unsigned j=0;j<4;j++)vst1q_u32(rare+4*j,vcgtq_u32(used[j],vdupq_n_u32(64)));
}
