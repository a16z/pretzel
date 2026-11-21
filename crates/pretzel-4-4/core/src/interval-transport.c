#include <arm_neon.h>
#define pretzel44_interval_prepare_slots pretzel44_interval_prepare_slots_impl
#define pretzel44_interval_coarse_step pretzel44_interval_coarse_step_impl
#define pretzel44_interval_finish_deferred pretzel44_interval_finish_deferred_impl
/* Complete transition. */
#define refine pretzel44_interval_refine
#define union64 pretzel44_interval_union64
#include "interval-geometric-prepare.c"
typedef struct {uint64_t a,b,c;} Q192;
#include "interval-centered7-prepare.h"
static inline Q192 add192(Q192 a,Q192 b){
 W z=(W)a.a+b.a;uint64_t x=z;z=(z>>64)+(W)a.b+b.b;uint64_t y=z;z=(z>>64)+(W)a.c+b.c;return(Q192){x,y,(uint64_t)z};
}
static inline Q192 mul192_u64(Q192 a,uint64_t y){
 W z=(W)a.b*y+(((W)a.a*y)>>64);
 W w=(W)a.c*y+(z>>64);
 return(Q192){(uint64_t)z,(uint64_t)w,(uint64_t)(w>>64)-(y&-(uint64_t)(a.c>>63))};
}
__attribute__((noinline)) Q192 pretzel44_interval_correction(const Q192 *coeff,uint64_t t){
 uint64_t y=(t*t)<<28;Q192 h=coeff[0];
 for(unsigned k=1;k<35;k++)h=add192(mul192_u64(h,y),coeff[k]);
 return h;
}
__attribute__((noinline)) void pretzel44_interval_decision(uint64_t out[3],const Q192 *coeff,uint64_t b,int64_t a,int64_t X,const uint64_t raw[6]){
 uint64_t neg=(uint64_t)(a>>63),t=(((uint64_t)a)^neg)-neg;
 uint64_t inside=(t<b)|(a==-(int64_t)b),im=-inside;
 uint64_t clipped=t^((t^b)&-(uint64_t)(t>b));
 Q192 s=pretzel44_interval_correction(coeff,clipped);s.a&=im;s.b&=im;s.c&=im;
 uint64_t z[7];W carry=0;
 for(unsigned i=0;i<6;i++){carry+=(W)raw[i]*65612;z[i]=(uint64_t)carry;carry>>=64;}z[6]=(uint64_t)carry;
 uint64_t u[4]={(z[3]>>16)|(z[4]<<48),(z[4]>>16)|(z[5]<<48),(z[5]>>16)|(z[6]<<48),z[6]>>16};
 /* Upper endpoint U_floor+1 + S_hat+64. Ambiguity becomes rejection. */
 carry=(W)u[0]+s.a+65;carry=(carry>>64)+(W)u[1]+s.b;carry=(carry>>64)+(W)u[2]+s.c;
 int64_t top=(int64_t)u[3]-(int64_t)(s.c>>63)+(int64_t)(carry>>64);
 uint64_t accept=top<1,g=pretzel44_interval_union64(X,b,t),f=accept&(1-g);
 uint64_t minus=-f,plus=-g,diff=(minus^plus)&neg;
 out[0]=minus^diff;out[1]=plus^diff;out[2]=~(minus|plus);
}
/* Stride-eight view borrows the erased slot records, avoiding a
 * second 6144-byte raw-coin owner. All slot and queue addresses are fixed. */
#include "interval-queue-geometric-tile.h"
__attribute__((noinline)) uint64_t pretzel44_interval_prepare_slots(const uint64_t *raw,int64_t out[128]){
 uint64_t q[8][6]={{0}},rank=0;uint8_t rare[128];int64_t nearest[8]={0};
 for(unsigned tile=0;tile<128;tile+=16){
  int64_t tile_nearest[16];
  for(unsigned block=0;block<16;block+=4){
   result four[4];pretzel44_geometric_four(raw+8*(tile+block),four);
   for(unsigned lane=0;lane<4;lane++){
    unsigned i=tile+block+lane;result g=four[lane];
    out[i]=g.ceil_guess;rare[i]=(uint8_t)g.ambiguous;tile_nearest[block+lane]=g.nearest;
   }
  }
  rank=geometric_queue_materialize16(q,nearest,rank,rare+tile,tile_nearest,raw+8*tile);
  for(unsigned j=0;j<16;j++)((volatile int64_t*)tile_nearest)[j]=0;
 }
 int64_t resolved[8];uint64_t bad=rank>8;
 for(unsigned j=0;j<8;j++){result value=pretzel44_interval_refine(q[j],nearest[j]);resolved[j]=value.ceil_guess;bad|=value.ambiguous&(rank>j);}
 (void)geometric_queue_scatter(out,rare,resolved,0);
 return bad;
}

/* Every queue operation is fixed-work. */
__attribute__((noinline)) void pretzel44_interval_coarse_step(uint64_t out[3],const int64_t coeff[12],uint64_t b,int64_t a,int64_t X,const uint64_t raw[6],uint64_t queue[6][8],uint64_t *rank,uint64_t active){
 uint64_t neg=(uint64_t)(a>>63),t=(((uint64_t)a)^neg)-neg;
 uint64_t inside=(t<b)|(a==-(int64_t)b);
 uint64_t clipped=t^((t^b)&-(uint64_t)(t>b)),y=(clipped*clipped)<<26;
 /* Recenter before scaling. u in[-7/8,7/8] Q62; no current coin dependency. */
 int64_t u_center=2*((int64_t)y-(INT64_C(7)<<58));
 int64_t h=coeff[5];for(unsigned j=6;j<12;j++)h=coeff[j]+(int64_t)(((I)h*u_center)>>62);
 h=(int64_t)((uint64_t)h&-inside);
 uint64_t u=(uint64_t)(((W)raw[5]*65612)>>18);
 int64_t delta=(int64_t)u+h-(INT64_C(1)<<62),radius=(INT64_C(1)<<28)+32;
 uint64_t mark=(uint64_t)((delta>=-radius)&(delta<=radius))&(active&1);
 /* Rust owns disjoint raw slot and queue arrays. Fixed vector accesses
  * preserve all six slot updates and every original word, including ranks
  * outside the queue and inactive/ambiguous combinations. */
 uint64x2_t payload0={(uint64_t)a,(uint64_t)X};
 uint64x2_t payload1=vld1q_u64(raw),payload2=vld1q_u64(raw+2),payload3=vld1q_u64(raw+4);
 for(unsigned j=0;j<6;j++){
  uint64_t m=-(mark&(*rank==j));asm volatile("":"+r"(m));
  uint64x2_t mask=vdupq_n_u64(m);
  vst1q_u64(queue[j],vbslq_u64(mask,payload0,vld1q_u64(queue[j])));
  vst1q_u64(queue[j]+2,vbslq_u64(mask,payload1,vld1q_u64(queue[j]+2)));
  vst1q_u64(queue[j]+4,vbslq_u64(mask,payload2,vld1q_u64(queue[j]+4)));
  vst1q_u64(queue[j]+6,vbslq_u64(mask,payload3,vld1q_u64(queue[j]+6)));
 }
 *rank+=mark;
 uint64_t g=pretzel44_interval_union64(X,b,t),f=(uint64_t)(delta<=radius)&(1-g);
 uint64_t minus=-f,plus=-g,diff=(minus^plus)&neg;
 out[0]=minus^diff;out[1]=plus^diff;out[2]=~(minus|plus);
}
/* Same ABI and existing256-byte erased wrapper; standalone decision stays. */
#define interval_finish_pair_impl pretzel44_interval_finish_deferred_impl
#include "interval-finish-pair.h"
#undef interval_finish_pair_impl


/* Exact public coefficient lower endpoints; no secret-indexed access. */
#include "interval-key256-table.h"
static inline Q256 key_power256(uint64_t n){
 Q256 a={{UINT64_MAX,UINT64_MAX,UINT64_MAX,UINT64_MAX}};
 for(unsigned bit=0;bit<29;bit++){
  Q256 prod=mul256(a,powers256[bit]);uint64_t m=-((n>>bit)&1);asm volatile("" : "+r"(m));
  for(unsigned k=0;k<4;k++)a.v[k]=(a.v[k]&~m)|(prod.v[k]&m);
 }
 return a;
}
/* Shell 105500..230053, covered by 876 uniform 100380..230053.
 * 38 preparation rows, degree 34; omitted j>=39 below 2^-221.
 * Envelope 65612/65536. */
__attribute__((noinline)) void pretzel44_interval_prepare_key_impl(Q192 out[35],int64_t coarse[12],uint64_t b){
 U256 pos[35],neg[35];
 for(unsigned i=0;i<175;i++){((volatile uint64_t*)pos)[i]=0;((volatile uint64_t*)neg)[i]=0;}pos[0].v[4]=1;
 for(unsigned j=1;j<=38;j++){
  Q256 power=key_power256(b*j*j);
  for(unsigned k=0;k<35;k++){
   U256 term=upmul(key_d256[j-1][k],power);
   U256 *dst=(j&1)?&neg[k]:&pos[k];W carry=0;
   for(unsigned w=0;w<5;w++){carry+=(W)term.v[w]*2+dst->v[w];dst->v[w]=(uint64_t)carry;carry>>=64;}
  }
 }
 for(unsigned k=0;k<35;k++){
  uint64_t difference[5],borrow=0;
  for(unsigned w=0;w<5;w++){W v=(W)pos[k].v[w]-neg[k].v[w]-borrow;difference[w]=(uint64_t)v;borrow=v>>127;}
  W carry=(W)1<<63;for(unsigned w=0;w<5;w++){carry+=difference[w];difference[w]=(uint64_t)carry;carry>>=64;}
  out[34-k]=(Q192){difference[1],difference[2],difference[3]};
 }
 pretzel44_interval_center6_from_full(coarse,out);
}
