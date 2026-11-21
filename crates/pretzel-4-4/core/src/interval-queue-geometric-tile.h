#ifndef INTERVAL_QUEUE_GEOMETRIC_TILE_H
#define INTERVAL_QUEUE_GEOMETRIC_TILE_H
#include <stdint.h>
#include <arm_neon.h>
static const uint8_t geometric_queue_nibble[64] __attribute__((aligned(16)))={255,255,255,255,0,255,255,255,1,255,255,255,0,1,255,255,2,255,255,255,0,2,255,255,1,2,255,255,0,1,2,255,3,255,255,255,0,3,255,255,1,3,255,255,0,1,3,255,2,3,255,255,0,2,3,255,1,2,3,255,0,1,2,3};
/* For j in [0,7], uint64(j-t)<4 is equivalent to
 * uint64(t+3)<11 && uint8(j-t)<4. The full-width guard restricts
 * t modulo 2^64 to [-3,7], so narrowing cannot create a false match. */
static __attribute__((always_inline)) inline uint8x8_t geometric_queue_select16(
 const uint8_t marks[16],uint64_t incoming,uint64_t *outgoing){
 uint8x16x4_t table;
 for(unsigned i=0;i<4;i++)table.val[i]=vld1q_u8(geometric_queue_nibble+16*i);
 const uint8x16_t destinations={0,1,2,3,4,5,6,7,0,1,2,3,4,5,6,7};
 uint8x16_t selected=vdupq_n_u8(255);uint64_t prefix=0;
 for(unsigned group=0;group<4;group++){
  unsigned nibble=marks[4*group]|((unsigned)marks[4*group+1]<<1)|((unsigned)marks[4*group+2]<<2)|((unsigned)marks[4*group+3]<<3);
  uint64_t base=incoming+prefix;
  uint64_t valid=-(uint64_t)((uint64_t)(base+3)<11);asm volatile("":"+r"(valid));
  uint8x16_t k=vsubq_u8(destinations,vdupq_n_u8((uint8_t)base));
  uint8x16_t ix=vaddq_u8(vandq_u8(k,vdupq_n_u8(3)),vdupq_n_u8((uint8_t)(4*nibble)));
  uint8x16_t local=vqtbl4q_u8(table,ix);
  uint8x16_t take=vandq_u8(vandq_u8(vcltq_u8(k,vdupq_n_u8(4)),vcltq_u8(local,vdupq_n_u8(4))),vdupq_n_u8((uint8_t)valid));
  selected=vbslq_u8(take,vaddq_u8(local,vdupq_n_u8((uint8_t)(4*group))),selected);
  prefix+=(uint64_t)marks[4*group]+marks[4*group+1]+marks[4*group+2]+marks[4*group+3];
 }
 *outgoing=incoming+prefix;return vget_low_u8(selected);
}

static __attribute__((always_inline)) inline uint8x16_t geometric_queue_gather128(
 uint8x16x4_t low,uint8x16x4_t high,uint8x16_t ix){
 uint8x16_t value=vqtbl4q_u8(low,ix);
 return vqtbx4q_u8(value,high,vsubq_u8(ix,vdupq_n_u8(64)));
}
/* All source/destination loads and stores use public loop indices. */
static __attribute__((noinline)) uint64_t geometric_queue_materialize16(
 uint64_t queue[8][6],int64_t nearest[8],uint64_t incoming,
 const uint8_t marks[16],const int64_t values[16],const uint64_t *raw){
 uint64_t outgoing;
 uint8x8_t selected=geometric_queue_select16(marks,incoming,&outgoing);
 uint8x16_t selectors=vcombine_u8(selected,selected);
 const uint8x16_t byte_offsets={0,1,2,3,4,5,6,7,0,1,2,3,4,5,6,7};
 uint8x16x4_t indices;
 for(unsigned pair=0;pair<4;pair++){
  uint8x16_t lanes=vcombine_u8(vdup_n_u8((uint8_t)(2*pair)),vdup_n_u8((uint8_t)(2*pair+1)));
  uint8x16_t expanded=vqtbl1q_u8(selectors,lanes);
  indices.val[pair]=vaddq_u8(vshlq_n_u8(expanded,3),byte_offsets);
 }
 for(unsigned field=0;field<6;field+=2){
  uint8x16x4_t low0,high0,low1,high1;
  for(unsigned part=0;part<4;part++){
   uint64x2_t a=vld1q_u64(raw+8*(2*part)+field),b=vld1q_u64(raw+8*(2*part+1)+field);
   low0.val[part]=vreinterpretq_u8_u64(vtrn1q_u64(a,b));low1.val[part]=vreinterpretq_u8_u64(vtrn2q_u64(a,b));
   a=vld1q_u64(raw+8*(8+2*part)+field);b=vld1q_u64(raw+8*(9+2*part)+field);
   high0.val[part]=vreinterpretq_u8_u64(vtrn1q_u64(a,b));high1.val[part]=vreinterpretq_u8_u64(vtrn2q_u64(a,b));
  }
  for(unsigned pair=0;pair<4;pair++){
   uint8x16_t ix=indices.val[pair];uint64x2_t mask=vreinterpretq_u64_u8(vcltq_u8(ix,vdupq_n_u8(128)));
   uint64x2_t a=vreinterpretq_u64_u8(geometric_queue_gather128(low0,high0,ix));
   uint64x2_t b=vreinterpretq_u64_u8(geometric_queue_gather128(low1,high1,ix));
   uint64x2_t first=vtrn1q_u64(a,b),second=vtrn2q_u64(a,b);
   uint64x2_t m0=vzip1q_u64(mask,mask),m1=vzip2q_u64(mask,mask);
   vst1q_u64(queue[2*pair]+field,vbslq_u64(m0,first,vld1q_u64(queue[2*pair]+field)));
   vst1q_u64(queue[2*pair+1]+field,vbslq_u64(m1,second,vld1q_u64(queue[2*pair+1]+field)));
  }
 }
 uint8x16x4_t low,high;
 for(unsigned part=0;part<4;part++){
  low.val[part]=vreinterpretq_u8_s64(vld1q_s64(values+2*part));
  high.val[part]=vreinterpretq_u8_s64(vld1q_s64(values+8+2*part));
 }
 for(unsigned pair=0;pair<4;pair++){
  uint8x16_t ix=indices.val[pair];uint64x2_t mask=vreinterpretq_u64_u8(vcltq_u8(ix,vdupq_n_u8(128)));
  uint64x2_t value=vreinterpretq_u64_u8(geometric_queue_gather128(low,high,ix));
  vst1q_s64(nearest+2*pair,vreinterpretq_s64_u64(vbslq_u64(mask,value,vreinterpretq_u64_s64(vld1q_s64(nearest+2*pair)))));
 }
 return outgoing;
}
/* Scalar prefix ranks retain full-width comparisons; only the value lookup
 * index is reduced modulo eight, under the unchanged replacement mask. */
static __attribute__((noinline)) uint64_t geometric_queue_scatter(
 int64_t out[128],const uint8_t rare[128],const int64_t resolved[8],uint64_t rank){
 uint8x16x4_t table;
 for(unsigned j=0;j<4;j++)table.val[j]=vreinterpretq_u8_s64(vld1q_s64(resolved+2*j));
 for(unsigned i=0;i<128;i+=2){
  uint64_t rank0=rank;rank+=rare[i];uint64_t rank1=rank;rank+=rare[i+1];
  uint64_t mask0=-((uint64_t)rare[i]&(rank0<8)),mask1=-((uint64_t)rare[i+1]&(rank1<8));
  asm volatile("":"+r"(mask0),"+r"(mask1));
  uint64x2_t packed={UINT64_C(0x0706050403020100)+(rank0&7)*UINT64_C(0x0808080808080808),UINT64_C(0x0706050403020100)+(rank1&7)*UINT64_C(0x0808080808080808)};
  uint64x2_t masks={mask0,mask1};
  uint64x2_t value=vreinterpretq_u64_u8(vqtbl4q_u8(table,vreinterpretq_u8_u64(packed)));
  vst1q_s64(out+i,vreinterpretq_s64_u64(vbslq_u64(masks,value,vreinterpretq_u64_s64(vld1q_s64(out+i)))));
 }
 return rank;
}
#endif
