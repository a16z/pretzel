/* Select-before-normalize. Fixed public scan, defined shifts, unchanged masks. */
static inline Norm normalize(const uint64_t r[6]) {
 uint64_t w=0,next=0,base=0,seen=0;
 for(unsigned i=0;i<6;i++) {
  uint64_t x=r[i],prev=i?r[i-1]:0;
  uint64_t m=pretzel_ct_mask_u64(-(uint64_t)((x|-x)>>63));
  w=(w&~m)|(x&m);next=(next&~m)|(prev&m);
  base=(base&~m)|((uint64_t)(64*i)&m);seen|=m;
 }
 unsigned s=(unsigned)__builtin_clzll(w|1);
 uint64_t mant=((w<<s)|((next>>1)>>(63-s)))>>1;
 uint64_t m=pretzel_ct_mask_u64(seen);
 return (Norm){(mant&m)|((UINT64_C(1)<<62)&~m),(base+64-s)&m};
}

/* Test adapter exposes the selected implementation, never an alternate path. */
void pretzel55_normalization_gate(const uint64_t r[6], uint64_t out[2]) {
 Norm a=normalize(r);out[0]=a.mant;out[1]=a.bitlen;
}
