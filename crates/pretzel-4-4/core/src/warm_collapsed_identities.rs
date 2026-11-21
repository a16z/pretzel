// Warm-only reservoir identities; actual descriptor/helper integration separate.
pub(crate) struct Table {pub z:[u64;3],pub bounds:usize}
static BOUNDS_DELTA_SEC:&[u8]=include_bytes!("collapsed_bounds_sec.bin");
pub(crate) static SEC:Table=Table{z:[16670503578860915356, 1571984488978943831, 4529966466125267862],bounds:2129};
static BOUNDS_DELTA_ERR:&[u8]=include_bytes!("collapsed_bounds_err.bin");
pub(crate) static ERR:Table=Table{z:[10608502277456946135, 12739190903529042557, 6236659400935998024],bounds:2711};
pub(crate) fn for_z(z:[u64;3])->Option<&'static Table>{if z==SEC.z{Some(&SEC)}else if z==ERR.z{Some(&ERR)}else{None}}
pub(crate) fn prepare(bounds:&[[u64;3]],z:[u64;3])->Option<&'static Table>{
 let table=for_z(z)?;assert_eq!(bounds.len(),table.bounds);let encoded=if z==SEC.z{BOUNDS_DELTA_SEC}else{BOUNDS_DELTA_ERR};let mut cursor=0usize;let mut sum=[0u64;3];
 for row in bounds{let n=encoded[cursor]as usize;cursor+=1;assert!(n<=24);let mut delta=[0u64;3];for j in 0..n{delta[j/8]|=(encoded[cursor+j]as u64)<<(8*(j%8));}cursor+=n;
  let mut carry=0u128;for j in 0..3{carry+=sum[j]as u128+delta[j]as u128;sum[j]=carry as u64;carry>>=64;}assert_eq!(carry,0);assert_eq!(*row,[sum[2],sum[1],sum[0]]);
 }assert_eq!(cursor,encoded.len());Some(table)
}

