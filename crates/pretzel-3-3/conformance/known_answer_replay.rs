
/// Known-answer replay on public test seeds; not an entropy interface for applications.
/// The first line of the output is a fixed header that enters no later value.
#[doc(hidden)]
pub fn write_known_answer_replay(out:&mut impl std::io::Write) {
    struct Tape { x:Xof, calls:usize }
    impl Tape {fn new(seed:&[u8])->Self{Self{x:Xof::new(b"PRETZEL33-SPEED-PUBLIC-AUDIT-v1",&[seed]),calls:0}}}
    impl EntropySource for Tape {fn fill(&mut self,out:&mut[u8])->Result<(),crate::EntropyError>{self.calls+=1;self.x.fill(out);Ok(())}}
    fn hex(bytes:&[u8])->String{bytes.iter().map(|b|format!("{b:02x}")).collect()}
    let ctx=Ctx::new();let v=super::verifier::PreparedVerifier::new(&ctx).unwrap();
    let mut scratch=SigningScratch::new();
    writeln!(out,"PRETZEL33 known-answer transcript v1").unwrap();
    for key in 0u64..4 {
        let pair=keygen_with_entropy(&ctx,&mut Tape::new(&key.to_le_bytes())).unwrap();
        let sk=PreparedSk::new(&pair.sk).unwrap();let pk=PreparedPk::new(&pair.pk).unwrap();
        writeln!(out,"pk {key} {}",hex(&pair.pk)).unwrap();
        for sample in 0u64..16 {
            let size=[0,32,136,4096][sample as usize%4];
            let message:Vec<u8>=(0..size).map(|i|(i as u64*131+sample*43) as u8).collect();
            let context=if sample%2==0{&b""[..]}else{&b"speed33-audit"[..]};
            let mut tape=Tape::new(&[key.to_le_bytes(),sample.to_le_bytes()].concat());
            let(sig,attempts)=sign_prepared_using_scratch(&ctx,&sk,context,&message,&mut tape,&mut scratch).unwrap();
            assert_eq!(sig.len(),1160);assert_eq!(tape.calls,attempts as usize);assert!(scratch.is_erased());
            v.verify(&pk,context,&message,&sig).unwrap();v.verify_reference(&pk,context,&message,&sig).unwrap();
            assert!(v.verify(&pk,b"wrong-context",&message,&sig).is_err());
            let mut wrong=message.clone();wrong.push(17);assert!(v.verify(&pk,context,&wrong,&sig).is_err());
            assert!(v.verify(&pk,context,&message,&sig[..1159]).is_err());
            let mut long=sig.clone();long.push(0);assert!(v.verify(&pk,context,&message,&long).is_err());
            for at in 0..1160 {
                let mut mutant=sig.clone();mutant[at]^=1<<(at%8);
                assert!(v.verify(&pk,context,&message,&mutant).is_err());
                assert!(v.verify_reference(&pk,context,&message,&mutant).is_err());
            }
            let mut continuation=[0;64];tape.x.fill(&mut continuation);
            writeln!(out,"sig {key} {sample} {attempts} {}",hex(&sig)).unwrap();
            writeln!(out,"continuation {} {}",tape.calls,hex(&continuation)).unwrap();
        }
    }
}
