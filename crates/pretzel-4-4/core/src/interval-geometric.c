#include <stdint.h>
#include <stddef.h>
#include <arm_neon.h>
typedef __int128 I;typedef unsigned __int128 W;
typedef struct {int64_t ceil_guess,nearest;uint64_t ambiguous;} result;
typedef struct {uint64_t mant,bitlen;} Norm;
static const int64_t ln2_q62=3196577161300663915,lnm_q62=5344925986425810;
static const int64_t log_coeff[7]={14,4611686018428343675,-2305843009215605579,1537228640505346197,-1152921464225525002,922610149116483488,-768887289912153586};
static const int32_t tail5=1718495319,tail6=-1432164181;
static const uint64_t inv_table[32] __attribute__((aligned(16)))={4540737002759274244,4405192614617206356,4277505872164533708,4157012749004969378,4043121988758257888,3935305402391371011,3833089677653932803,3736049432650035770,3643801298510528714,3555998857582564167,3472328296227680304,3392504657233940527,3316268597520818268,3243383573399481603,3173633389025299203,3106820054519503430,3042761909065493050,2981291971508614403,2922256486924285405,2865513642517988601,2810932430279550722,2758391637190213326,2707778946599567210,2658990136750926359,2611928364419051556,2566503523298720225,2522631668199596802,2480234497305485932,2439238885779775420,2399576464872787202,2361183241434822607,2323999253380730912};
static const int64_t log_table[32] __attribute__((aligned(16)))={71500440275001132,211259196826165143,346906799979656243,478678222179227879,606788849569836225,731436600117858114,852803762927731868,971058601665755514,1086356757488956163,1198842480830767981,1308649716501276080,1415903062576720341,1520718620294393112,1623204749490040530,1723462741901951859,1821587422829804232,1917667690106341787,2011786998059858950,2104023793070232944,2194451906414741489,2283140909332897512,2370156434588336299,2455560468251094538,2539411614949629351,2621765339435664660,2702674186955724673,2782187984622167612,2860354025716315478,2937217238630761736,3012820341962006855,3087203987093926544,3160406889463606000};
static inline Norm normalize(const uint64_t r[6]){
 uint64_t mant=UINT64_C(1)<<62, bitlen=0;
 for(unsigned i=0;i<6;i++) {
   uint64_t w=r[i], next=i?r[i-1]:0;
   unsigned lz=(unsigned)__builtin_clzll(w|1);
   W pair=((W)w<<64)|next;
   uint64_t mm=(uint64_t)((pair<<lz)>>65);
   uint64_t bb=i*64+64-lz,mask=-(uint64_t)((w|-w)>>63);
   mant=(mant&~mask)|(mm&mask);bitlen=(bitlen&~mask)|(bb&mask);
 }
 return(Norm){mant,bitlen};
}
static inline result finish_log(Norm v,int64_t x,int64_t logc,int32_t p){
 int64_t h=log_coeff[4]+(int64_t)p*(INT64_C(1)<<29);
 #pragma clang loop unroll(full)
 for(int k=3;k>=1;k--)h=log_coeff[k]+(int64_t)(((I)h*x+((I)1<<61))>>62);
 h=logc+(int64_t)(((I)h*x+((I)1<<61))>>62);
 uint64_t bitlen=v.bitlen;
 /* Warm exact-rational target: Q62 reciprocal uses a split product.
  * Signed division is exact here because base-low is divisible by2^62;
  * it therefore yields the Euclidean quotient even for negative base.
  * No potentially153-bit product is formed. */
 I base=((I)(385-bitlen)*ln2_q62)-h-lnm_q62;
 W low=((W)base)&(((W)1<<62)-1);
 I quotient=(base-(I)low)/((I)1<<62);
 I l=base*834803+quotient*(I)UINT64_C(1152921601281761902)
       +(I)((low*(W)UINT64_C(1152921601281761902))>>62);
 int64_t nearest=(int64_t)((l+((I)1<<61))>>62);
 I dist=l-(I)nearest*((I)1<<62);I neg=dist>>127;dist=(dist^neg)-neg;
 uint64_t nz=-(uint64_t)(bitlen!=0);
 return(result){(int64_t)(((uint64_t)((int64_t)(l>>62)+1))&nz),(int64_t)((uint64_t)nearest&nz),(uint64_t)(dist<=((I)1<<32))&nz};
}
static inline void lookup_four(uint64_t out[4],const uint64_t table[32],const uint64_t segments[4]){
 uint64_t packed[4];for(unsigned i=0;i<4;i++)packed[i]=UINT64_C(0x0706050403020100)+segments[i]*UINT64_C(0x0808080808080808);
 uint8x16_t ix0=vreinterpretq_u8_u64(vld1q_u64(packed)),ix1=vreinterpretq_u8_u64(vld1q_u64(packed+2)),a=vdupq_n_u8(0),b=vdupq_n_u8(0);
 #pragma clang loop unroll(full)
 for(unsigned bank=0;bank<4;bank++){
  const uint8_t*src=(const uint8_t*)table+64*bank;uint8x16x4_t data;
  for(unsigned j=0;j<4;j++)data.val[j]=vld1q_u8(src+16*j);
  a=vqtbx4q_u8(a,data,vsubq_u8(ix0,vdupq_n_u8(64*bank)));b=vqtbx4q_u8(b,data,vsubq_u8(ix1,vdupq_n_u8(64*bank)));
 }
 vst1q_u64(out,vreinterpretq_u64_u8(a));vst1q_u64(out+2,vreinterpretq_u64_u8(b));
}
__attribute__((noinline)) void pretzel44_geometric_four(const uint64_t*raw,result out[4]){
 Norm v[4];uint64_t segments[4],rinv[4],logc[4];int64_t x[4];int32_t z[4],p[4];
 for(unsigned i=0;i<4;i++){v[i]=normalize(raw+8*i);segments[i]=(v[i].mant>>57)&31;}
 lookup_four(rinv,inv_table,segments);lookup_four(logc,(const uint64_t*)log_table,segments);
 for(unsigned i=0;i<4;i++){x[i]=(int64_t)(((W)v[i].mant*rinv[i]+((W)1<<61))>>62)-(INT64_C(1)<<62);z[i]=(int32_t)((x[i]+(INT64_C(1)<<30))>>31);}
 int32x4_t zz=vld1q_s32(z),h5=vaddq_s32(vdupq_n_s32(tail5),vqrdmulhq_s32(vdupq_n_s32(tail6),zz));vst1q_s32(p,vqrdmulhq_s32(h5,zz));
 for(unsigned i=0;i<4;i++)out[i]=finish_log(v[i],x[i],(int64_t)logc[i],p[i]);
}
/* Exact infinite-union membership for nonzero 384-bit coins: X<2^28,
 * E_64>=105500*64^2>2^28. The search counts E_j<X; odd count means g. */
__attribute__((noinline)) uint64_t union64(int64_t X,uint64_t b,uint64_t t) {
 uint64_t index=0;
 for(unsigned step=32;step;step>>=1){
   uint64_t j=index+step,energy=j*(b*j+2*t);
   uint64_t mask=-(uint64_t)((int64_t)energy<X); asm volatile("" : "+r"(mask));
   index+=step&mask;
 }
 return(index&1)&(uint64_t)(X>0);
}
