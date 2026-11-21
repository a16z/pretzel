#include <stdint.h>
#include <stddef.h>
#define memcpy __builtin_memcpy
#define memset __builtin_memset
#include <arm_neon.h>
typedef __uint128_t W;
typedef void(*Gather)(uint64_t*,const uint8_t*,size_t,const uint8_t*);
typedef struct {Gather main,mid,suffix;const uint8_t *main_data,*mid_data,*suffix_data;const void*tree;uint64_t mass[3];} Tables;
extern void pretzel33_reservoir_main_rows(uint32_t[16][8],uint32_t[16],const uint16_t[8][16],const uint32_t[2][16],const uint32_t[8][2][16]);
extern void pretzel33_warm_tail192(uint64_t[16][2],const uint64_t[6],const uint64_t[6][3],const void*);
static inline uint32_t opaque32(uint32_t x){asm volatile("":"+r"(x));return x;}
static inline uint64_t opaque64(uint64_t x){asm volatile("":"+r"(x));return x;}
static inline uint32_t sel32(uint32_t mask,uint32_t x,uint32_t y){return (mask&x)|(~mask&y);}
static inline uint32_t load32(const void*p){uint32_t x;memcpy(&x,p,4);return x;}
static inline uint64_t load64(const void*p){uint64_t x;memcpy(&x,p,8);return x;}
static inline uint16_t column(const uint8_t*p,unsigned i){unsigned off=(10*i)/8,shift=(10*i)%8;uint32_t v=p[off]|((uint32_t)p[off+1]<<8);return(v>>shift)&1023;}
static void shift_stream(uint8_t state[48],uint32_t n){
 static const uint8_t bytes[16]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};uint8x16x3_t all;for(unsigned i=0;i<3;i++)all.val[i]=vld1q_u8(state+16*i);
 uint8x16_t ix=vaddq_u8(vld1q_u8(bytes),vdupq_n_u8(n>>3));int8x16_t sh=vdupq_n_s8(n&7),rsh=vsubq_s8(sh,vdupq_n_s8(8));
 for(unsigned i=0;i<3;i++){uint8x16_t idx=vaddq_u8(ix,vdupq_n_u8(16*i));uint8x16_t a=vqtbl3q_u8(all,idx),b=vqtbl3q_u8(all,vaddq_u8(idx,vdupq_n_u8(1)));vst1q_u8(state+16*i,vorrq_u8(vshlq_u8(a,sh),vshlq_u8(b,rsh)));}
}
/* Fixed q is104 or192; all positions in the bitstream stay in registers. */
static uint32_t decode(uint32_t out[8],const uint8_t seed[48],const uint16_t columns[16],const uint64_t prefixes[16][2],const uint64_t suffix[16][2],unsigned q,unsigned bits){
 uint8_t state[48];memcpy(state,seed,48);uint32_t bad=0,remaining=bits;
 for(unsigned i=0;i<8;i++){
  W packed=(W)prefixes[i][0]|((W)prefixes[i][1]<<64),p=packed&(((W)1<<104)-1);uint32_t meta=packed>>104;W low=(W)suffix[i][0]|((W)suffix[i][1]<<64);
  uint32_t words[6]={(uint32_t)(p>>72),(uint32_t)(p>>40),(uint32_t)(p>>8),(uint32_t)(p<<24)|((uint32_t)(low>>64)&0xffffff),(uint32_t)(low>>32),(uint32_t)low};
  uint32_t n=q,seen=0,primary=0;
  for(unsigned j=0;j<(q+31)/32;j++){
   uint32_t a=__builtin_bswap32(load32(state+4*j)),b=words[j];if(q==104&&j==3){a&=0xff000000;b&=0xff000000;}
   uint32_t diff=a^b,mask=opaque32(-((seen==0)&(diff!=0)));uint32_t step=32*j+__builtin_clz(diff|1)+1;
   n=sel32(mask,step,n);primary=sel32(mask,a<b,primary);seen|=diff;
  }
  uint32_t endpoint=(meta>>9)!=0,epmask=opaque32(-endpoint);n=sel32(epmask,1,n);primary=sel32(epmask,(meta>>9)&1,primary);
  bad|=(n>remaining)|((q!=192)&(seen==0)&!endpoint);uint32_t mag=sel32(opaque32(-primary),columns[i]&511,meta&511);out[i]=(2*mag-1+(columns[i]>>9))&opaque32(-(mag!=0));
  shift_stream(state,n);remaining-=remaining<n?remaining:n;
 }
 return bad;
}
__attribute__((noinline)) static void select_fifo(uint8_t slots[7][24],const uint8_t*tape,const uint32_t*ranks,uint32_t rank){
 /* Stable first-seven FIFO, all128publicrecords visited. Only slot bytes [0,18) are consumed; [18,24) is dead padding. */
 uint8x16_t heads[7],tails=vdupq_n_u8(0);
 for(unsigned q=0;q<7;q++)heads[q]=vdupq_n_u8(0);
 for(unsigned block=0;block<128;block++){
  uint32_t rr=ranks[block];uint8x16_t mask=vdupq_n_u8(opaque32(-((rr!=0)&(rr<=7))));
  uint8x16_t raw=vld1q_u8(tape+18*block);uint16_t tail;memcpy(&tail,tape+18*block+16,2);
  uint8x16_t pair=vreinterpretq_u8_u16(vdupq_n_u16(tail));
  #pragma clang loop unroll(full)
  for(unsigned q=0;q<6;q++)heads[q]=vbslq_u8(mask,heads[q+1],heads[q]);
  heads[6]=vbslq_u8(mask,raw,heads[6]);tails=vbslq_u8(mask,vextq_u8(tails,pair,2),tails);
 }
 uint32_t occupied=rank<7?rank:7;
 static const uint8_t bytes_fifo[16]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
 uint8x16_t iota_fifo=vld1q_u8(bytes_fifo);
 tails=vqtbl1q_u8(tails,vaddq_u8(iota_fifo,vdupq_n_u8(2*(8-occupied))));
 uint8x16x4_t lo_fifo;uint8x16x3_t hi_fifo;
 for(unsigned q=0;q<4;q++)lo_fifo.val[q]=heads[q];
 for(unsigned q=0;q<3;q++)hi_fifo.val[q]=heads[q+4];
 uint8x16_t ix_fifo=vaddq_u8(iota_fifo,vdupq_n_u8(16*(7-occupied)));
 {
 uint8x16_t selected=vorrq_u8(vqtbl4q_u8(lo_fifo,ix_fifo),vqtbl3q_u8(hi_fifo,vsubq_u8(ix_fifo,vdupq_n_u8(64))));
 vst1q_u8(slots[0],selected);uint16_t last=vgetq_lane_u16(vreinterpretq_u16_u8(tails),0);memcpy(slots[0]+16,&last,2);ix_fifo=vaddq_u8(ix_fifo,vdupq_n_u8(16));
 }
 {
 uint8x16_t selected=vorrq_u8(vqtbl4q_u8(lo_fifo,ix_fifo),vqtbl3q_u8(hi_fifo,vsubq_u8(ix_fifo,vdupq_n_u8(64))));
 vst1q_u8(slots[1],selected);uint16_t last=vgetq_lane_u16(vreinterpretq_u16_u8(tails),1);memcpy(slots[1]+16,&last,2);ix_fifo=vaddq_u8(ix_fifo,vdupq_n_u8(16));
 }
 {
 uint8x16_t selected=vorrq_u8(vqtbl4q_u8(lo_fifo,ix_fifo),vqtbl3q_u8(hi_fifo,vsubq_u8(ix_fifo,vdupq_n_u8(64))));
 vst1q_u8(slots[2],selected);uint16_t last=vgetq_lane_u16(vreinterpretq_u16_u8(tails),2);memcpy(slots[2]+16,&last,2);ix_fifo=vaddq_u8(ix_fifo,vdupq_n_u8(16));
 }
 {
 uint8x16_t selected=vorrq_u8(vqtbl4q_u8(lo_fifo,ix_fifo),vqtbl3q_u8(hi_fifo,vsubq_u8(ix_fifo,vdupq_n_u8(64))));
 vst1q_u8(slots[3],selected);uint16_t last=vgetq_lane_u16(vreinterpretq_u16_u8(tails),3);memcpy(slots[3]+16,&last,2);ix_fifo=vaddq_u8(ix_fifo,vdupq_n_u8(16));
 }
 {
 uint8x16_t selected=vorrq_u8(vqtbl4q_u8(lo_fifo,ix_fifo),vqtbl3q_u8(hi_fifo,vsubq_u8(ix_fifo,vdupq_n_u8(64))));
 vst1q_u8(slots[4],selected);uint16_t last=vgetq_lane_u16(vreinterpretq_u16_u8(tails),4);memcpy(slots[4]+16,&last,2);ix_fifo=vaddq_u8(ix_fifo,vdupq_n_u8(16));
 }
 {
 uint8x16_t selected=vorrq_u8(vqtbl4q_u8(lo_fifo,ix_fifo),vqtbl3q_u8(hi_fifo,vsubq_u8(ix_fifo,vdupq_n_u8(64))));
 vst1q_u8(slots[5],selected);uint16_t last=vgetq_lane_u16(vreinterpretq_u16_u8(tails),5);memcpy(slots[5]+16,&last,2);ix_fifo=vaddq_u8(ix_fifo,vdupq_n_u8(16));
 }
 {
 uint8x16_t selected=vorrq_u8(vqtbl4q_u8(lo_fifo,ix_fifo),vqtbl3q_u8(hi_fifo,vsubq_u8(ix_fifo,vdupq_n_u8(64))));
 vst1q_u8(slots[6],selected);uint16_t last=vgetq_lane_u16(vreinterpretq_u16_u8(tails),6);memcpy(slots[6]+16,&last,2);ix_fifo=vaddq_u8(ix_fifo,vdupq_n_u8(16));
 }
}
#include "reservoir-mid-four.c"
typedef struct {
 uint32_t samples[1024];
 union {
  struct {uint16_t columns[8][16];uint32_t input[2][16],mainrows[8][2][16],bad[16];};
  struct {uint32_t midplanes[4][4][16];uint16_t midcols[8][8];uint32_t midbad[8],midseed[5][8];};
 };
 uint32_t rank[128];
 uint8_t slots[7][24],finalseed[48];uint32_t ids[7],midout[7][8],finalid,finalout[8];
 uint16_t finalcolumns[16];uint64_t finalprefix[16][2],tailout[16][2],tailranks[6][3],aggregate[6];
 uint64_t alignment_padding;
} Workspace;
_Static_assert(sizeof(Workspace)<=8000 && sizeof(Workspace)%16==0,"workspace fits aligned existing erased lease");
_Static_assert(sizeof(Workspace)==7328,"warm exact192 tail workspace size");
/* Fixed public field extents. All workspace backing bytes are initialized
 * by the Rust word owner; old tail output is read but annihilated by the
 * all-one aggregate masks established immediately before the closed tail call.
 * No sampler work, table query, failure output or terminal erase is shortened. */
static __attribute__((always_inline)) inline void init_zero16(void *p,size_t bytes){
 for(size_t i=0;i<bytes;i+=16){vst1q_u8((uint8_t*)p+i,vdupq_n_u8(0));asm volatile("":::"memory");}
}
_Static_assert(offsetof(Workspace,finalseed)==6248 && sizeof(((Workspace*)0)->finalseed)==48,"final seed accumulator extent");
_Static_assert(offsetof(Workspace,finalcolumns)==6584 && sizeof(((Workspace*)0)->finalcolumns)==32,"all suffix columns including dummy queries");
_Static_assert(offsetof(Workspace,finalprefix)==6616 && sizeof(((Workspace*)0)->finalprefix[0])*8==128,"eight consumed final prefix rows");
_Static_assert(offsetof(Workspace,tailout)==6872 && offsetof(Workspace,tailranks)==7128 && offsetof(Workspace,aggregate)==7272,"disjoint tail output ranks and masks");
uint64_t reservoir_sample_reference(uint32_t*destination,const uint8_t*tape,const Tables*t,void*workspace,size_t n){
 Workspace*w=workspace;uint32_t*out=w->samples;uint32_t rank=0;
 init_zero16(w->finalseed,sizeof w->finalseed);
 init_zero16(w->finalcolumns,sizeof w->finalcolumns);
 init_zero16(w->finalprefix,8*sizeof w->finalprefix[0]);
 for(unsigned group=0;group<8;group++){
  for(unsigned i=0;i<16;i++){const uint8_t*b=tape+18*(16*group+i);for(unsigned j=0;j<2;j++)w->input[j][i]=__builtin_bswap32(load32(b+4*j));for(unsigned step=0;step<8;step++)w->columns[step][i]=column(b+8,step);}
  for(unsigned pair=0;pair<4;pair++){
   uint8_t ix[2][32];for(unsigned lane=0;lane<2;lane++)for(unsigned i=0;i<16;i++){uint16_t c=w->columns[2*pair+lane][i];ix[lane][i]=c&15;ix[lane][16+i]=(c&511)>>4;}
   t->main((uint64_t*)w->mainrows[2*pair],t->main_data,64,(const uint8_t*)ix);
  }
  pretzel33_reservoir_main_rows((uint32_t(*)[8])(out+128*group),w->bad,w->columns,w->input,w->mainrows);
  for(unsigned i=0;i<16;i++){unsigned block=16*group+i;uint32_t rare=w->bad[i]!=0;rank+=rare;w->rank[block]=rank&opaque32(-rare);}
 }
 uint32_t bad=(rank>7);
 select_fifo(w->slots,tape,w->rank,rank);
 /* The main-pass union member is dead here. Initialize every middle field
  * before reading it; public dummy completion seven is fully evaluated. */
 for(unsigned q=0;q<8;q++){
  for(unsigned i=0;i<8;i++)w->midcols[q][i]=q<7?column(w->slots[q]+8,i):0;
  for(unsigned j=0;j<5;j++)w->midseed[j][q]=0;
  if(q<7){
   const uint8_t*extra=tape+2304+11*q;
   w->midseed[0][q]=__builtin_bswap32(load32(w->slots[q]));w->midseed[1][q]=__builtin_bswap32(load32(w->slots[q]+4));
   w->midseed[2][q]=__builtin_bswap32(load32(extra));w->midseed[3][q]=__builtin_bswap32(load32(extra+4));
   w->midseed[4][q]=((uint32_t)extra[8]<<24)|((uint32_t)extra[9]<<16)|((uint32_t)extra[10]<<8);
  }
 }
 for(unsigned pair=0;pair<4;pair++){
  uint8_t ix[32];uint64_t packed[16][2];
  for(unsigned i=0;i<16;i++){uint16_t col=w->midcols[i&7][2*pair+(i>>3)];ix[i]=col&15;ix[i+16]=(col&511)>>4;}
  t->mid((uint64_t*)packed,t->mid_data,32,ix);
  for(unsigned i=0;i<16;i++){
   W all=(W)packed[i][0]|((W)packed[i][1]<<64),threshold=all&(((W)1<<104)-1);
   w->midplanes[pair][0][i]=(uint32_t)(threshold>>72);w->midplanes[pair][1][i]=(uint32_t)(threshold>>40);
   w->midplanes[pair][2][i]=(uint32_t)(threshold>>8);w->midplanes[pair][3][i]=(uint32_t)(threshold<<24)|(uint32_t)(all>>104);
  }
 }
 decode_mid_four(w->midout,w->midbad,w->midseed,w->midcols,w->midplanes);
 uint32_t rank1=0;w->finalid=0;
 for(unsigned q=0;q<7;q++){
  uint8_t seed[48]={0};memcpy(seed,w->slots[q],8);memcpy(seed+8,tape+2304+11*q,11);
  uint32_t failed=(w->midbad[q]!=0)&(q<rank);rank1+=failed;
  uint64_t mask=opaque64(-(uint64_t)(failed&(rank1==1)));w->finalid|=q&(uint32_t)mask;
  for(unsigned j=0;j<6;j++){uint64_t x=load64(w->finalseed+8*j)|(load64(seed+8*j)&mask);memcpy(w->finalseed+8*j,&x,8);}
  for(unsigned i=0;i<8;i++){
   unsigned at=8*(i&1)+q;const uint32_t(*pl)[16]=w->midplanes[i>>1];
   W threshold=((W)pl[0][at]<<72)|((W)pl[1][at]<<40)|((W)pl[2][at]<<8)|(pl[3][at]>>24);
   W packed=threshold|((W)(pl[3][at]&0xffffff)<<104);
   w->finalcolumns[i]|=w->midcols[q][i]&(uint16_t)mask;
   w->finalprefix[i][0]|=(uint64_t)packed&mask;w->finalprefix[i][1]|=(uint64_t)(packed>>64)&mask;
  }
 }
 bad|=rank1>1;memcpy(w->finalseed+19,tape+2381,11);
 {uint8_t ix[32];uint64_t suffix[16][2];for(unsigned i=0;i<16;i++){ix[i]=w->finalcolumns[i]&15;ix[i+16]=(w->finalcolumns[i]&511)>>4;}t->suffix((uint64_t*)suffix,t->suffix_data,32,ix);bad|=decode(w->finalout,w->finalseed,w->finalcolumns,w->finalprefix,suffix,192,240)&(rank1!=0);}
 for(unsigned q=0;q<7;q++){uint32_t mask=opaque32(-((rank1!=0)&(q==w->finalid)));for(unsigned i=0;i<8;i++)w->midout[q][i]=sel32(mask,w->finalout[i],w->midout[q][i]);}
 for(unsigned q=0;q<6;q++){
  uint64_t product[8]={0};const uint8_t*u=tape+2392+40*q;
  for(unsigned i=0;i<3;i++){uint64_t carry=0;for(unsigned j=0;j<5;j++){W v=(W)load64(u+8*j)*t->mass[i]+product[i+j]+carry;product[i+j]=v;carry=v>>64;}product[i+5]=carry;}
  w->tailranks[q][0]=product[5];w->tailranks[q][1]=product[6];w->tailranks[q][2]=product[7];w->aggregate[q]=UINT64_MAX;
  volatile uint64_t *retire_product=product;for(unsigned k=0;k<8;k++)retire_product[k]=0;
 }
 pretzel33_warm_tail192(w->tailout,w->aggregate,w->tailranks,t->tree);
 uint32_t counts[8]={0},flags[8]={0};for(unsigned q=0;q<6;q++){counts[q]=w->tailout[q][0];flags[q]=w->tailout[q][1];}
 uint8x16x2_t count_table,flag_table;for(unsigned j=0;j<2;j++){count_table.val[j]=vreinterpretq_u8_u32(vld1q_u32(counts+4*j));flag_table.val[j]=vreinterpretq_u8_u32(vld1q_u32(flags+4*j));}
/* count_table and flag_table have already been constructed. */
uint8x16x4_t repair_lo0, repair_lo1;
uint8x16x3_t repair_hi0, repair_hi1;

#pragma clang loop unroll(full)
for (unsigned q = 0; q < 4; q++) {
    repair_lo0.val[q] =
        vreinterpretq_u8_u32(vld1q_u32(w->midout[q]));
    repair_lo1.val[q] =
        vreinterpretq_u8_u32(vld1q_u32(w->midout[q] + 4));
}
#pragma clang loop unroll(full)
for (unsigned q = 0; q < 3; q++) {
    repair_hi0.val[q] =
        vreinterpretq_u8_u32(vld1q_u32(w->midout[q + 4]));
    repair_hi1.val[q] =
        vreinterpretq_u8_u32(vld1q_u32(w->midout[q + 4] + 4));
}

static const uint8_t repair_bytes[16] = {
    0, 1, 2, 3, 4, 5, 6, 7,
    8, 9, 10, 11, 12, 13, 14, 15
};
const uint8x16_t repair_iota = vld1q_u8(repair_bytes);

uint32_t tailrank = 0;
uint32x4_t ties = vdupq_n_u32(0);
const uint32x4_t zero = vdupq_n_u32(0);

/*
 * Explicit expansion keeps segment selection public and avoids indexing
 * an array of vector-table objects in the hot loop.
 */
#define REPAIR_THEN_TAIL(AT, LOW, HIGH) do {                           \
    uint8x16_t repaired = vorrq_u8(                                   \
        vqtbl4q_u8((LOW), repair_ix),                                 \
        vqtbl3q_u8((HIGH),                                            \
            vsubq_u8(repair_ix, vdupq_n_u8(64))));                     \
    uint32x4_t values = vbslq_u32(                                    \
        repair_mask, vreinterpretq_u32_u8(repaired),                  \
        vld1q_u32(out + (AT)));                                       \
                                                                     \
    uint32x4_t agg = vcgeq_u32(values, vdupq_n_u32(1021));             \
    uint32x4_t partial = vandq_u32(agg, vdupq_n_u32(1));               \
    partial = vaddq_u32(partial, vextq_u32(zero, partial, 3));          \
    partial = vaddq_u32(partial, vextq_u32(zero, partial, 2));          \
    uint32x4_t ranks = vaddq_u32(partial, vdupq_n_u32(tailrank));       \
    tailrank = vgetq_lane_u32(ranks, 3);                               \
                                                                     \
    uint32x4_t packed = vaddq_u32(                                    \
        vmulq_n_u32(vsubq_u32(ranks, vdupq_n_u32(1)), 0x04040404),     \
        vdupq_n_u32(0x03020100));                                     \
    uint8x16_t ix = vreinterpretq_u8_u32(packed);                      \
    uint32x4_t replacement =                                         \
        vreinterpretq_u32_u8(vqtbl2q_u8(count_table, ix));             \
    uint32x4_t tf =                                                  \
        vreinterpretq_u32_u8(vqtbl2q_u8(flag_table, ix));              \
    vst1q_u32(out + (AT), vbslq_u32(agg, replacement, values));         \
    ties = vorrq_u32(ties, vandq_u32(agg, tf));                        \
} while (0)

for (unsigned i = 0; i < n; i += 8) {
    uint32_t rr = w->rank[i >> 3];
    uint8x16_t repair_ix = vaddq_u8(
        repair_iota, vdupq_n_u8(16 * (rr - 1)));
    uint32x4_t repair_mask =
        vdupq_n_u32(opaque32(-((rr != 0) & (rr <= 7))));

    REPAIR_THEN_TAIL(i, repair_lo0, repair_hi0);

    /* Public length condition; keeps the multiple-of-four domain. */
    if (i + 4 < n) {
        REPAIR_THEN_TAIL(i + 4, repair_lo1, repair_hi1);
    }
}
#undef REPAIR_THEN_TAIL

/* Bad update, final masked copy, and return. */

 bad|=tailrank>6;uint32x4_t mask=vdupq_n_u32(opaque32(-(bad==0)));for(unsigned i=0;i<n;i+=4)vst1q_u32(destination+i,vandq_u32(vld1q_u32(out+i),mask));return -(uint64_t)((vmaxvq_u32(ties)!=0)|(bad!=0));
}
