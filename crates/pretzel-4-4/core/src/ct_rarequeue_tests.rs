mod tests {
 use super::*;
 use crate::{ct_alias::Alias,gauss::Cdt,theta::ThetaCtx};
 fn rare(alias:&Alias,draw:&[u64;4],z:[u64;3])->bool{
  let top=alias.row(draw[3]as usize)[0]&PREFIX_MASK;let v=draw[0]&PREFIX_MASK;
  v==0||v==top||(top!=PREFIX_MASK&&v==top+(1<<24))||v==(z[0]&PREFIX_MASK)
 }
 // Independent scalar, allocating parser of the complete specified tape.
 fn reference(alias:&Alias,z:[u64;3],rng:&mut Xof,n:usize)->(Vec<i32>,u64){
  let mut proposals=Vec::new();
  for offset in (0..n+CAP).step_by(16){
   for _ in 0..(n+CAP-offset).min(16){
    {let k=alias.rare_parts().unwrap().k;let m=((z[0]as u128>>24)+1)<<(k+11);let base=1u128<<64;let t=base%m;
     let a=loop{let product=rng.u64()as u128*m;if product%base>=t{break(product/base)as u64;}};
     proposals.push([(a>>(k+11))<<24,0,(a>>k)&2047,a&alias.column_mask()]);}
   }
  }
  let completion=rng.bytes::<144>();let mut rank=0;let mut outputs=Vec::new();let mut abort=0;
  for mut draw in proposals{
   if rare(alias,&draw,z){if rank<CAP{
    let bytes=&completion[24*rank..24*(rank+1)];
    draw[0]|=u64::from_le_bytes(bytes[..8].try_into().unwrap())&0xffffff;
    draw[1]=u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    draw[2]|=u64::from_le_bytes(bytes[16..24].try_into().unwrap())<<11;
   }rank+=1;}
   if draw[..3]<=z[..]&&outputs.len()<n{let result=alias.reference(draw);outputs.push(result[0]as i32);abort|=result[1];}
  }
  if rank>CAP{return(vec![0;n],u64::MAX);}
  assert_eq!(outputs.len(),n);(outputs,abort)
 }
 fn check(alias:&Alias,z:[u64;3],mut actual:Xof,mut expected:Xof,n:usize){
  let parts=alias.rare_parts().unwrap();let mut out=vec![0x12345678;n+8];let mut records=[u32::MAX;crate::scratch::RECORD_WORDS];let mut work=[u32::MAX;2048];
  let abort=sample(&parts,&z,&mut actual,&mut out[4..n+4],&mut records,&mut work);
  let(want,flag)=reference(alias,z,&mut expected,n);
  assert_eq!(&out[4..n+4],want);assert_eq!(abort,flag);
  assert!(out[..4].iter().chain(&out[n+4..]).all(|&x|x==0x12345678));
  assert_eq!(actual.batch_test_consumed_pub(),expected.batch_test_consumed_pub());
  assert_eq!(actual.bytes::<96>(),expected.bytes::<96>());
 }
 fn encode(alias:&Alias,z:[u64;3],proposals:&[[u64;4]])->Vec<u8>{
  let mut tape=Vec::new();
  for batch in proposals.chunks(16){
   for u in batch{
    {let k=alias.rare_parts().unwrap().k;let m=((z[0]as u128>>24)+1)<<(k+11);let base=1u128<<64;let t=base%m;
     assert!(t>0);tape.extend_from_slice(&0u64.to_le_bytes());
     let a=((u[0]as u128>>24)<<(k+11))|(((u[2]&2047)as u128)<<k)|u[3]as u128;
     let w=(a*base+t).div_ceil(m);assert!(w<base&&w*m/base==a&&w*m%base>=t);
     tape.extend_from_slice(&(w as u64).to_le_bytes());}
   }
  }
  let mut completion=Vec::new();for u in proposals.iter().filter(|u|rare(alias,u,z)).take(CAP){completion.extend_from_slice(&(u[0]&0xffffff).to_le_bytes());completion.extend_from_slice(&u[1].to_le_bytes());completion.extend_from_slice(&(u[2]>>11).to_le_bytes());}completion.resize(144,0);tape.extend_from_slice(&completion);tape
 }
 fn fixture(tape:&[u8])->Xof{Xof::from_scheduled(crate::ct_stream_schedule::Reader::rarequeue_test_fixture(tape))}
 fn offset(mut u:[u64;3],delta:i128)->Option<[u64;3]>{let mut carry=delta;for i in(0..3).rev(){let v=u[i]as i128+carry;u[i]=v as u64;carry=v>>64;}if carry==0{Some(u)}else{None}}
 #[test]
 fn rarequeue_full_sampler_random_tapes_and_cursor(){let theta=ThetaCtx::new();for(w,even)in[(crate::params::PROPOSAL_W0,true),(crate::params::WS,false),(crate::params::WE,false)]{
  let cdt=Cdt::new(&theta,w,even);let(bounds,z)=cdt.ct_tables();let alias=Alias::new(bounds,z).unwrap();
  for n in [0,4,16,256,1024]{for seed in 0u64..16{let b=seed.to_le_bytes();check(&alias,z,Xof::new(b"RQ40-reference",&[&b]),Xof::new(b"RQ40-reference",&[&b]),n);}}
 }}
 #[test]
 fn rarequeue_boundaries_surplus_and_cross_chunk(){let theta=ThetaCtx::new();for(w,even)in[(crate::params::PROPOSAL_W0,true),(crate::params::WS,false),(crate::params::WE,false)]{
  let cdt=Cdt::new(&theta,w,even);let(bounds,z)=cdt.ct_tables();let alias=Alias::new(bounds,z).unwrap();let k=alias.rare_parts().unwrap().k;let columns=1usize<<k;
  for column in [0,1,columns/2,columns-1]{let row=alias.row(column);let t=[row[0],row[1],row[2]];let cap=(row[3]>>(31+k))&((4u64<<k)-1);
   let mut edges=vec![[0,0,(2u64<<k)-1],[0,0,2u64<<k],z,offset(z,1).unwrap()];
   for delta in [-1,0,cap as i128-1,cap as i128,cap as i128+1]{if let Some(u)=offset(t,delta){edges.push(u);}}
   for edge in edges{if edge[0]>>24>z[0]>>24{continue;}for position in [0usize,15,16,17,21]{for rejected in 0..=5usize{
    if position<rejected{continue;}
    let mut proposals=vec![[(z[0]/2)&PREFIX_MASK,0,123,0];22];
    for u in &mut proposals[..rejected]{let x=offset(z,1).unwrap();*u=[x[0],x[1],x[2],0];}
    proposals[position]=[edge[0],edge[1],edge[2],column as u64];
    let tape=encode(&alias,z,&proposals);check(&alias,z,fixture(&tape),fixture(&tape),16);
   }}}
  }
 }}
 #[test]
 fn rarequeue_overflow_all_counts_and_classes(){let theta=ThetaCtx::new();for(w,even)in[(crate::params::PROPOSAL_W0,true),(crate::params::WS,false),(crate::params::WE,false)]{
  let cdt=Cdt::new(&theta,w,even);let(bounds,z)=cdt.ct_tables();let alias=Alias::new(bounds,z).unwrap();let top=alias.row(1)[0]&PREFIX_MASK;
  for count in 0..=10{for class in 0..4{for fill in [0u64,u64::MAX]{let mut proposals=Vec::new();
   for i in 0..10{let mut v=(z[0]/2)&PREFIX_MASK;while rare(&alias,&[v,0,0,1],z){v+=1<<24;}
    if i<count{v=match class{0=>0,1=>top,2=>(top.saturating_add(1<<24)).min(z[0]&PREFIX_MASK),_=>z[0]&PREFIX_MASK};}
    proposals.push([v|(fill&0xffffff),fill,fill,1]);
   }
   let tape=encode(&alias,z,&proposals);check(&alias,z,fixture(&tape),fixture(&tape),4);
  }}}
 }}
 #[test]
 fn rarequeue_parts_validate_extents(){
  // These unsupported table shapes must be rejected.
  for(id,c,r,k,p,b)in[(257,320,640,6,32,93),(258,6224,10336,10,708,2031),(259,6736,13024,10,900,2585)]{
   assert!(Parts::new(id,&vec![0;c],&vec![0;r],k,p,b).is_none());
  }
 for(id,c,r,k,p,b)in[(257,400,992,6,54,155),(258,6272,10816,10,743,2129),(259,6864,13648,10,944,2711)]{
  let cp=vec![0;c];let rp=vec![0;r];assert!(Parts::new(id,&cp,&rp,k,p,b).is_some());assert!(Parts::new(id,&cp[..c-1],&rp,k,p,b).is_none());assert!(Parts::new(id,&cp,&rp[..r-1],k,p,b).is_none());assert!(Parts::new(id,&cp,&rp,k,p,b+1).is_none());
 }}
}
