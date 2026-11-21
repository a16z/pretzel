/* Standalone exact finish-only routine. All queue addresses/counts fixed.
 * Include after stdint.h and the Q192 typedef. */
typedef unsigned __int128 finish_pair_wide;
typedef Q192 finish_pair_q192;
extern uint64_t pretzel44_interval_union64(int64_t,uint64_t,uint64_t);
static inline finish_pair_q192 finish_pair_add(finish_pair_q192 a,finish_pair_q192 b){
 finish_pair_wide z=(finish_pair_wide)a.a+b.a;uint64_t x=z;
 z=(z>>64)+(finish_pair_wide)a.b+b.b;uint64_t y=z;
 z=(z>>64)+(finish_pair_wide)a.c+b.c;
 return(finish_pair_q192){x,y,(uint64_t)z};
}
static inline finish_pair_q192 finish_pair_mul(finish_pair_q192 a,uint64_t y){
 finish_pair_wide z=(finish_pair_wide)a.b*y+(((finish_pair_wide)a.a*y)>>64);
 finish_pair_wide w=(finish_pair_wide)a.c*y+(z>>64);
 return(finish_pair_q192){(uint64_t)z,(uint64_t)w,(uint64_t)(w>>64)-(y&-(uint64_t)(a.c>>63))};
}
static inline uint64_t finish_pair_abs(int64_t a){
 uint64_t neg=(uint64_t)(a>>63);return(((uint64_t)a)^neg)-neg;
}
static inline uint64_t finish_pair_y(int64_t a,uint64_t b){
 uint64_t t=finish_pair_abs(a),clipped=t^((t^b)&-(uint64_t)(t>b));
 return(clipped*clipped)<<28;
}
static inline uint64_t finish_pair_reject(finish_pair_q192 s,uint64_t b,const uint64_t q[8]){
 int64_t a=(int64_t)q[0];uint64_t t=finish_pair_abs(a);
 uint64_t im=-((t<b)|(a==-(int64_t)b));s.a&=im;s.b&=im;s.c&=im;
 uint64_t z[7];finish_pair_wide carry=0;
 for(unsigned i=0;i<6;i++){carry+=(finish_pair_wide)q[i+2]*65612;z[i]=(uint64_t)carry;carry>>=64;}z[6]=(uint64_t)carry;
 uint64_t u0=(z[3]>>16)|(z[4]<<48),u1=(z[4]>>16)|(z[5]<<48);
 uint64_t u2=(z[5]>>16)|(z[6]<<48),u3=z[6]>>16;
 carry=(finish_pair_wide)u0+s.a+65;carry=(carry>>64)+(finish_pair_wide)u1+s.b;
 carry=(carry>>64)+(finish_pair_wide)u2+s.c;
 int64_t top=(int64_t)u3-(int64_t)(s.c>>63)+(int64_t)(carry>>64);
 uint64_t accept=top<1,g=pretzel44_interval_union64((int64_t)q[1],b,t);
 return(accept|g)-1;
}
__attribute__((noinline)) uint64_t pretzel44_interval_finish_pair_tile(const finish_pair_q192 coeff[35],uint64_t b,const uint64_t q[2][8],uint64_t m0,uint64_t m1){
 uint64_t y0=finish_pair_y((int64_t)q[0][0],b),y1=finish_pair_y((int64_t)q[1][0],b);
 finish_pair_q192 h0=coeff[0],h1=coeff[0];
 for(unsigned k=1;k<35;k++){
  finish_pair_q192 c=coeff[k];
  h0=finish_pair_add(finish_pair_mul(h0,y0),c);
  h1=finish_pair_add(finish_pair_mul(h1,y1),c);
 }
 uint64_t r0=finish_pair_reject(h0,b,q[0]);
 uint64_t r1=finish_pair_reject(h1,b,q[1]);
 return(r0&m0)|(r1&m1);
}
__attribute__((noinline)) uint64_t interval_finish_pair_impl(const finish_pair_q192 coeff[35],uint64_t b,const uint64_t queue[6][8],uint64_t rank){
 uint64_t bad=-(uint64_t)(rank>6);
 for(unsigned j=0;j<6;j+=2){
  uint64_t m0=-(uint64_t)(j<rank),m1=-(uint64_t)(j+1<rank);
  asm volatile("":"+r"(m0),"+r"(m1));
  bad|=pretzel44_interval_finish_pair_tile(coeff,b,queue+j,m0,m1);
 }
 return bad;
}
