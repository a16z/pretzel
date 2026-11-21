/* Fixed four-lane decoder for the 104-bit middle thresholds. */
static inline void shift_five(uint32x4_t s[5],uint32x4_t n){
 uint32x4_t m64=vtstq_u32(n,vdupq_n_u32(64)),m32=vtstq_u32(n,vdupq_n_u32(32));
 s[0]=vbslq_u32(m64,s[2],s[0]);s[1]=vbslq_u32(m64,s[3],s[1]);s[2]=vbslq_u32(m64,s[4],s[2]);s[3]=vbicq_u32(s[3],m64);s[4]=vbicq_u32(s[4],m64);
 s[0]=vbslq_u32(m32,s[1],s[0]);s[1]=vbslq_u32(m32,s[2],s[1]);s[2]=vbslq_u32(m32,s[3],s[2]);s[3]=vbslq_u32(m32,s[4],s[3]);s[4]=vbicq_u32(s[4],m32);
 int32x4_t h=vreinterpretq_s32_u32(vandq_u32(n,vdupq_n_u32(31))),r=vsubq_s32(h,vdupq_n_s32(32));
 #pragma clang loop unroll(full)
 for(unsigned j=0;j<4;j++)s[j]=vorrq_u32(vshlq_u32(s[j],h),vshlq_u32(s[j+1],r));
 s[4]=vshlq_u32(s[4],h);
}
__attribute__((noinline)) static void decode_mid_four(uint32_t out[7][8],uint32_t flags[8],const uint32_t seed[5][8],const uint16_t columns[8][8],const uint32_t planes[4][4][16]){
 const uint32x4_t zero=vdupq_n_u32(0),one=vdupq_n_u32(1),top=vdupq_n_u32(0xff000000);
 for(unsigned group=0;group<2;group++){
  uint32x4_t s[5];for(unsigned j=0;j<5;j++)s[j]=vld1q_u32(seed[j]+4*group);
  uint32x4_t remaining=vdupq_n_u32(152),bad=zero;
  for(unsigned i=0;i<8;i++){
   uint32x4_t p[4],diff[4],z[4];for(unsigned j=0;j<4;j++)p[j]=vld1q_u32(planes[i>>1][j]+8*(i&1)+4*group);
   uint32x4_t meta=vandq_u32(p[3],vdupq_n_u32(0xffffff)),a3=vandq_u32(s[3],top),b3=vandq_u32(p[3],top);
   for(unsigned j=0;j<3;j++)diff[j]=veorq_u32(s[j],p[j]);diff[3]=veorq_u32(a3,b3);
   for(unsigned j=0;j<4;j++)z[j]=vceqq_u32(diff[j],zero);
   uint32x4_t n=vminq_u32(vaddq_u32(vclzq_u32(diff[3]),vdupq_n_u32(97)),vdupq_n_u32(104)),primary=vcltq_u32(a3,b3);
   #pragma clang loop unroll(full)
   for(int j=2;j>=0;j--){n=vbslq_u32(z[j],n,vaddq_u32(vclzq_u32(diff[j]),vdupq_n_u32(32*j+1)));primary=vbslq_u32(z[j],primary,vcltq_u32(s[j],p[j]));}
   uint32x4_t endpoint=vcgtq_u32(vshrq_n_u32(meta,9),zero);
   n=vbslq_u32(endpoint,one,n);primary=vbslq_u32(endpoint,vtstq_u32(meta,vdupq_n_u32(512)),primary);
   bad=vorrq_u32(bad,vorrq_u32(vcltq_u32(remaining,n),vbicq_u32(vandq_u32(vandq_u32(z[0],z[1]),vandq_u32(z[2],z[3])),endpoint)));
   uint32_t cc[4];for(unsigned j=0;j<4;j++)cc[j]=columns[4*group+j][i];uint32x4_t col=vld1q_u32(cc);
   uint32x4_t mag=vandq_u32(vbslq_u32(primary,col,meta),vdupq_n_u32(511));
   uint32x4_t value=vbicq_u32(vaddq_u32(vsubq_u32(vshlq_n_u32(mag,1),one),vshrq_n_u32(col,9)),vceqq_u32(mag,zero));
   uint32_t vv[4];vst1q_u32(vv,value);for(unsigned j=0;j<4;j++)if(4*group+j<7)out[4*group+j][i]=vv[j];
   uint32x4_t next;asm volatile("umin %0.4s,%1.4s,%2.4s\nsub %0.4s,%1.4s,%0.4s":"=&w"(next):"w"(remaining),"w"(n));remaining=next;
   shift_five(s,n);
  }
  vst1q_u32(flags+4*group,bad);
 }
}
