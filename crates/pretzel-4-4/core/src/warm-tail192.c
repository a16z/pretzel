/* The caller supplies 192-bit ranks to the linked pretzel44_warm_tail192 wrapper.
 * This helper must be invoked through that wrapper, which erases its reserved
 * stack region. Emitted helper and gather frames must fit that reservation.
 * Tables below use little-endian 16-byte rows; all scan extents are public.
 * Caller owns initialized out and validated immutable table/rank descriptors. */
#include <stdint.h>
#include <stddef.h>
typedef unsigned __int128 TailWide;
typedef void (*WarmGather)(uint64_t*,const uint8_t*,size_t,const uint8_t*);
typedef struct {
 size_t levels;
 const uint8_t *low[10],*high[10];
 WarmGather gather_low[10],gather_high[10];
 const uint8_t *tags;WarmGather gather_tags;
} WarmTail;
static uint64_t select64(uint64_t m,uint64_t a,uint64_t b){return(a&m)|(b&~m);}
static uint64_t subtract192(uint64_t out[3],const uint64_t a[3],const uint64_t b[3]){
 uint64_t borrow=0;
 for(unsigned k=0;k<3;k++){TailWide v=(TailWide)a[k]-b[k]-borrow;out[k]=(uint64_t)v;borrow=(uint64_t)(v>>127);}
 return borrow;
}
void pretzel44_warm_tail192_impl(uint64_t out[16][2],const uint64_t aggregate[6],const uint64_t ranks[6][3],const WarmTail *tree){
 /* Public preconditions: levels 9 or 10, ranks<M<2^192, valid full padded rows,
  * aggregate is 0 or all ones; caller initialized output when its mask is zero. */
 struct {uint64_t v[6][3],lower[6][3],low[16][2],high[16][2],tmp[3],end[3];uint16_t node[6],tag_index[6];uint8_t indices[32];} s;
 /* Only fields read before their first defining write need initialization.
  * Individual typed volatile lvalues prohibit replacing these accesses with
  * an ordinary memset; the emitted code must be checked. */
 for(unsigned i=0;i<6;i++)for(unsigned k=0;k<3;k++)*(volatile uint64_t*)&s.lower[i][k]=0;
 for(unsigned i=0;i<6;i++)*(volatile uint16_t*)&s.node[i]=0;
 for(unsigned i=0;i<32;i++)*(volatile uint8_t*)&s.indices[i]=0;
 const uint64_t prefix[3]={1020,0,0};
 for(unsigned i=0;i<6;i++)subtract192(s.v[i],ranks[i],prefix);
 for(size_t level=0;level<tree->levels;level++){
  for(unsigned i=0;i<6;i++){s.indices[i]=(uint8_t)(s.node[i]&15);s.indices[i+16]=(uint8_t)(s.node[i]>>4);}
  tree->gather_low[level]((uint64_t*)s.low,tree->low[level],0,s.indices);
  /* Nullable function is immutable PUBLIC shape, never a private predicate. */
  if(tree->gather_high[level])tree->gather_high[level]((uint64_t*)s.high,tree->high[level],0,s.indices);
  else for(unsigned i=0;i<16;i++)for(unsigned k=0;k<2;k++)s.high[i][k]=0;
  for(unsigned i=0;i<6;i++){
   s.end[0]=s.low[i][0];s.end[1]=s.low[i][1];s.end[2]=s.high[i][0];
   uint64_t right=1-subtract192(s.tmp,s.v[i],s.end),mask=-right;
   for(unsigned k=0;k<3;k++)s.lower[i][k]=select64(mask,s.end[k],s.lower[i][k]);
   s.node[i]=(uint16_t)(2*s.node[i]+right);
  }
 }
 for(unsigned i=0;i<6;i++){s.tag_index[i]=s.node[i]>>1;s.indices[i]=(uint8_t)(s.tag_index[i]&15);s.indices[i+16]=(uint8_t)(s.tag_index[i]>>4);}
 tree->gather_tags((uint64_t*)s.low,tree->tags,0,s.indices);
 for(unsigned i=0;i<6;i++){
  uint64_t tag=(s.low[i][0]>>(16*(s.node[i]&1)))&65535;
  subtract192(s.tmp,s.v[i],s.lower[i]);
  uint64_t pair=(tag>>12)&1,count=(tag&4095)+((s.tmp[0]^(tag>>13))&pair);
  uint64_t tiny=(s.tmp[2]==0)&(s.tmp[1]==0)&(s.tmp[0]<2);
  uint64_t tie=-((tiny|(pair==0))&((tag>>14)&1));
  uint64_t prefix_mask=-((uint64_t)(ranks[i][2]==0)&(ranks[i][1]==0)&(ranks[i][0]<1020));
  count=select64(prefix_mask,ranks[i][0]+1,count);tie|=prefix_mask;
  out[i][0]=select64(aggregate[i],count,out[i][0]);out[i][1]=select64(aggregate[i],tie,out[i][1]);
 }
 /* Explicit owned scratch wipe. */
 volatile uint8_t *erase=(volatile uint8_t*)&s;for(size_t i=0;i<sizeof s;i++)erase[i]=0;
}
