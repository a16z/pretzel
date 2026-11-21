#include <arm_neon.h>
/* Complete transition. */
#define geometric pretzel55_interval_geometric
#define refine pretzel55_interval_refine
#define union28 pretzel55_interval_union28
#define union64 pretzel55_interval_union64
#include "interval-geometric-prepare.c"
typedef struct {uint64_t a,b,c;} Q192;
#include "interval-centered10-prepare.h"
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
/* Pretzel-(5,5) interval shell 131557..292635.
 * 36 preparation rows, degree 34, L squared 2^37.
 * Theta, envelope 65586/65536. */
__attribute__((noinline)) void pretzel55_interval_prepare_key_impl(Q192 out[35],int64_t coarse[12],uint64_t b){
 U256 pos[35],neg[35];
 for(unsigned i=0;i<175;i++){((volatile uint64_t*)pos)[i]=0;((volatile uint64_t*)neg)[i]=0;}pos[0].v[4]=1;
 for(unsigned j=1;j<=36;j++){
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
 pretzel55_interval_center10_from_full(coarse,out);
}
