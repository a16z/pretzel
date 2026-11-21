// Descriptors of the warm tail tables: for each level the table bytes and the gather
// routine that reads them (`warm-gathers.S`).
type WarmGather=unsafe extern "C" fn(*mut u64,*const u8,usize,*const u8);
#[repr(C)]
pub(crate) struct WarmTail{pub levels:usize,pub low:[*const u8;10],pub high:[*const u8;10],pub gather_low:[WarmGather;10],pub gather_high:[Option<WarmGather>;10],pub tags:*const u8,pub gather_tags:WarmGather}
// SAFETY: shared access exposes only raw pointers and unsafe function pointers, and no safe code
// mutates what they point to. The two static descriptors below point to immutable `include_bytes!`
// tables and to the gather routines; gather outputs are separate buffers owned by the caller.
unsafe impl Sync for WarmTail{}
// SAFETY: contract of every warm gather declared in this file (`warm-gathers.S` of rank four,
// assembled under this crate's symbol prefix). Each is straight-line NEON code without a branch. It
// reads 32 bytes at `i`, reads its table `t` front to back, exactly the length of the `.bin` file
// named after it, writes 256 bytes at `o` and ignores `n`. It saves and restores d8 to d15 on 64
// bytes of stack, keeps no pointer and has no global state. This one reads 16 table bytes.
unsafe extern "C"{fn pretzel33_warm_tree_sec_0(o:*mut u64,t:*const u8,n:usize,i:*const u8);}
static WARM_TREE_SEC_0:&[u8]=include_bytes!("../../pretzel-4-4/core/src/warm_tree_sec_0.bin");
// SAFETY: warm gather with the contract stated at `pretzel33_warm_tree_sec_0` above; this one reads
// 208 table bytes.
unsafe extern "C"{fn pretzel33_warm_tree_sec_1(o:*mut u64,t:*const u8,n:usize,i:*const u8);}
static WARM_TREE_SEC_1:&[u8]=include_bytes!("../../pretzel-4-4/core/src/warm_tree_sec_1.bin");
// SAFETY: warm gather with the contract stated at `pretzel33_warm_tree_sec_0` above; this one reads
// 208 table bytes.
unsafe extern "C"{fn pretzel33_warm_tree_sec_2(o:*mut u64,t:*const u8,n:usize,i:*const u8);}
static WARM_TREE_SEC_2:&[u8]=include_bytes!("../../pretzel-4-4/core/src/warm_tree_sec_2.bin");
// SAFETY: warm gather with the contract stated at `pretzel33_warm_tree_sec_0` above; this one reads
// 208 table bytes.
unsafe extern "C"{fn pretzel33_warm_tree_sec_3(o:*mut u64,t:*const u8,n:usize,i:*const u8);}
static WARM_TREE_SEC_3:&[u8]=include_bytes!("../../pretzel-4-4/core/src/warm_tree_sec_3.bin");
// SAFETY: warm gather with the contract stated at `pretzel33_warm_tree_sec_0` above; this one reads
// 208 table bytes.
unsafe extern "C"{fn pretzel33_warm_tree_sec_4(o:*mut u64,t:*const u8,n:usize,i:*const u8);}
static WARM_TREE_SEC_4:&[u8]=include_bytes!("../../pretzel-4-4/core/src/warm_tree_sec_4.bin");
// SAFETY: warm gather with the contract stated at `pretzel33_warm_tree_sec_0` above; this one reads
// 224 table bytes.
unsafe extern "C"{fn pretzel33_warm_tree_sec_5(o:*mut u64,t:*const u8,n:usize,i:*const u8);}
static WARM_TREE_SEC_5:&[u8]=include_bytes!("../../pretzel-4-4/core/src/warm_tree_sec_5.bin");
// SAFETY: warm gather with the contract stated at `pretzel33_warm_tree_sec_0` above; this one reads
// 448 table bytes.
unsafe extern "C"{fn pretzel33_warm_tree_sec_6(o:*mut u64,t:*const u8,n:usize,i:*const u8);}
static WARM_TREE_SEC_6:&[u8]=include_bytes!("../../pretzel-4-4/core/src/warm_tree_sec_6.bin");
// SAFETY: warm gather with the contract stated at `pretzel33_warm_tree_sec_0` above; this one reads
// 896 table bytes.
unsafe extern "C"{fn pretzel33_warm_tree_sec_7(o:*mut u64,t:*const u8,n:usize,i:*const u8);}
static WARM_TREE_SEC_7:&[u8]=include_bytes!("../../pretzel-4-4/core/src/warm_tree_sec_7.bin");
// SAFETY: warm gather with the contract stated at `pretzel33_warm_tree_sec_0` above; this one reads
// 1792 table bytes.
unsafe extern "C"{fn pretzel33_warm_tree_sec_8(o:*mut u64,t:*const u8,n:usize,i:*const u8);}
static WARM_TREE_SEC_8:&[u8]=include_bytes!("../../pretzel-4-4/core/src/warm_tree_sec_8.bin");
// SAFETY: warm gather with the contract stated at `pretzel33_warm_tree_sec_0` above; this one reads
// 960 table bytes.
unsafe extern "C"{fn pretzel33_warm_tree_sec_tags(o:*mut u64,t:*const u8,n:usize,i:*const u8);}
static WARM_TREE_SEC_TAGS:&[u8]=include_bytes!("../../pretzel-4-4/core/src/warm_tree_sec_tags.bin");
pub(crate) static WARM_TREE_SEC:WarmTail=WarmTail{levels:9,low:[WARM_TREE_SEC_0.as_ptr(),WARM_TREE_SEC_1.as_ptr(),WARM_TREE_SEC_2.as_ptr(),WARM_TREE_SEC_3.as_ptr(),WARM_TREE_SEC_4.as_ptr(),WARM_TREE_SEC_5.as_ptr(),WARM_TREE_SEC_6.as_ptr(),WARM_TREE_SEC_7.as_ptr(),WARM_TREE_SEC_8.as_ptr(),WARM_TREE_SEC_8.as_ptr()],high:[core::ptr::null(),core::ptr::null(),core::ptr::null(),core::ptr::null(),core::ptr::null(),core::ptr::null(),core::ptr::null(),core::ptr::null(),core::ptr::null(),core::ptr::null()],gather_low:[pretzel33_warm_tree_sec_0,pretzel33_warm_tree_sec_1,pretzel33_warm_tree_sec_2,pretzel33_warm_tree_sec_3,pretzel33_warm_tree_sec_4,pretzel33_warm_tree_sec_5,pretzel33_warm_tree_sec_6,pretzel33_warm_tree_sec_7,pretzel33_warm_tree_sec_8,pretzel33_warm_tree_sec_8],gather_high:[None,None,None,None,None,None,None,None,None,None],tags:WARM_TREE_SEC_TAGS.as_ptr(),gather_tags:pretzel33_warm_tree_sec_tags};
// SAFETY: warm gather with the contract stated at `pretzel33_warm_tree_sec_0` above; this one reads
// 256 table bytes.
unsafe extern "C"{fn pretzel33_warm_tree_err_0(o:*mut u64,t:*const u8,n:usize,i:*const u8);}
static WARM_TREE_ERR_0:&[u8]=include_bytes!("../../pretzel-4-4/core/src/warm_tree_err_0.bin");
// SAFETY: warm gather with the contract stated at `pretzel33_warm_tree_sec_0` above; this one reads
// 16 table bytes.
unsafe extern "C"{fn pretzel33_warm_tree_err_0_hi(o:*mut u64,t:*const u8,n:usize,i:*const u8);}
static WARM_TREE_ERR_0_HI:&[u8]=include_bytes!("../../pretzel-4-4/core/src/warm_tree_err_0_hi.bin");
// SAFETY: warm gather with the contract stated at `pretzel33_warm_tree_sec_0` above; this one reads
// 256 table bytes.
unsafe extern "C"{fn pretzel33_warm_tree_err_1(o:*mut u64,t:*const u8,n:usize,i:*const u8);}
static WARM_TREE_ERR_1:&[u8]=include_bytes!("../../pretzel-4-4/core/src/warm_tree_err_1.bin");
// SAFETY: warm gather with the contract stated at `pretzel33_warm_tree_sec_0` above; this one reads
// 16 table bytes.
unsafe extern "C"{fn pretzel33_warm_tree_err_1_hi(o:*mut u64,t:*const u8,n:usize,i:*const u8);}
static WARM_TREE_ERR_1_HI:&[u8]=include_bytes!("../../pretzel-4-4/core/src/warm_tree_err_1_hi.bin");
// SAFETY: warm gather with the contract stated at `pretzel33_warm_tree_sec_0` above; this one reads
// 256 table bytes.
unsafe extern "C"{fn pretzel33_warm_tree_err_2(o:*mut u64,t:*const u8,n:usize,i:*const u8);}
static WARM_TREE_ERR_2:&[u8]=include_bytes!("../../pretzel-4-4/core/src/warm_tree_err_2.bin");
// SAFETY: warm gather with the contract stated at `pretzel33_warm_tree_sec_0` above; this one reads
// 16 table bytes.
unsafe extern "C"{fn pretzel33_warm_tree_err_2_hi(o:*mut u64,t:*const u8,n:usize,i:*const u8);}
static WARM_TREE_ERR_2_HI:&[u8]=include_bytes!("../../pretzel-4-4/core/src/warm_tree_err_2_hi.bin");
// SAFETY: warm gather with the contract stated at `pretzel33_warm_tree_sec_0` above; this one reads
// 256 table bytes.
unsafe extern "C"{fn pretzel33_warm_tree_err_3(o:*mut u64,t:*const u8,n:usize,i:*const u8);}
static WARM_TREE_ERR_3:&[u8]=include_bytes!("../../pretzel-4-4/core/src/warm_tree_err_3.bin");
// SAFETY: warm gather with the contract stated at `pretzel33_warm_tree_sec_0` above; this one reads
// 16 table bytes.
unsafe extern "C"{fn pretzel33_warm_tree_err_3_hi(o:*mut u64,t:*const u8,n:usize,i:*const u8);}
static WARM_TREE_ERR_3_HI:&[u8]=include_bytes!("../../pretzel-4-4/core/src/warm_tree_err_3_hi.bin");
// SAFETY: warm gather with the contract stated at `pretzel33_warm_tree_sec_0` above; this one reads
// 256 table bytes.
unsafe extern "C"{fn pretzel33_warm_tree_err_4(o:*mut u64,t:*const u8,n:usize,i:*const u8);}
static WARM_TREE_ERR_4:&[u8]=include_bytes!("../../pretzel-4-4/core/src/warm_tree_err_4.bin");
// SAFETY: warm gather with the contract stated at `pretzel33_warm_tree_sec_0` above; this one reads
// 16 table bytes.
unsafe extern "C"{fn pretzel33_warm_tree_err_4_hi(o:*mut u64,t:*const u8,n:usize,i:*const u8);}
static WARM_TREE_ERR_4_HI:&[u8]=include_bytes!("../../pretzel-4-4/core/src/warm_tree_err_4_hi.bin");
// SAFETY: warm gather with the contract stated at `pretzel33_warm_tree_sec_0` above; this one reads
// 512 table bytes.
unsafe extern "C"{fn pretzel33_warm_tree_err_5(o:*mut u64,t:*const u8,n:usize,i:*const u8);}
static WARM_TREE_ERR_5:&[u8]=include_bytes!("../../pretzel-4-4/core/src/warm_tree_err_5.bin");
// SAFETY: warm gather with the contract stated at `pretzel33_warm_tree_sec_0` above; this one reads
// 32 table bytes.
unsafe extern "C"{fn pretzel33_warm_tree_err_5_hi(o:*mut u64,t:*const u8,n:usize,i:*const u8);}
static WARM_TREE_ERR_5_HI:&[u8]=include_bytes!("../../pretzel-4-4/core/src/warm_tree_err_5_hi.bin");
// SAFETY: warm gather with the contract stated at `pretzel33_warm_tree_sec_0` above; this one reads
// 784 table bytes.
unsafe extern "C"{fn pretzel33_warm_tree_err_6(o:*mut u64,t:*const u8,n:usize,i:*const u8);}
static WARM_TREE_ERR_6:&[u8]=include_bytes!("../../pretzel-4-4/core/src/warm_tree_err_6.bin");
// SAFETY: warm gather with the contract stated at `pretzel33_warm_tree_sec_0` above; this one reads
// 48 table bytes.
unsafe extern "C"{fn pretzel33_warm_tree_err_6_hi(o:*mut u64,t:*const u8,n:usize,i:*const u8);}
static WARM_TREE_ERR_6_HI:&[u8]=include_bytes!("../../pretzel-4-4/core/src/warm_tree_err_6_hi.bin");
// SAFETY: warm gather with the contract stated at `pretzel33_warm_tree_sec_0` above; this one reads
// 1568 table bytes.
unsafe extern "C"{fn pretzel33_warm_tree_err_7(o:*mut u64,t:*const u8,n:usize,i:*const u8);}
static WARM_TREE_ERR_7:&[u8]=include_bytes!("../../pretzel-4-4/core/src/warm_tree_err_7.bin");
// SAFETY: warm gather with the contract stated at `pretzel33_warm_tree_sec_0` above; this one reads
// 96 table bytes.
unsafe extern "C"{fn pretzel33_warm_tree_err_7_hi(o:*mut u64,t:*const u8,n:usize,i:*const u8);}
static WARM_TREE_ERR_7_HI:&[u8]=include_bytes!("../../pretzel-4-4/core/src/warm_tree_err_7_hi.bin");
// SAFETY: warm gather with the contract stated at `pretzel33_warm_tree_sec_0` above; this one reads
// 3136 table bytes.
unsafe extern "C"{fn pretzel33_warm_tree_err_8(o:*mut u64,t:*const u8,n:usize,i:*const u8);}
static WARM_TREE_ERR_8:&[u8]=include_bytes!("../../pretzel-4-4/core/src/warm_tree_err_8.bin");
// SAFETY: warm gather with the contract stated at `pretzel33_warm_tree_sec_0` above; this one reads
// 192 table bytes.
unsafe extern "C"{fn pretzel33_warm_tree_err_8_hi(o:*mut u64,t:*const u8,n:usize,i:*const u8);}
static WARM_TREE_ERR_8_HI:&[u8]=include_bytes!("../../pretzel-4-4/core/src/warm_tree_err_8_hi.bin");
// SAFETY: warm gather with the contract stated at `pretzel33_warm_tree_sec_0` above; this one reads
// 6272 table bytes.
unsafe extern "C"{fn pretzel33_warm_tree_err_9(o:*mut u64,t:*const u8,n:usize,i:*const u8);}
static WARM_TREE_ERR_9:&[u8]=include_bytes!("../../pretzel-4-4/core/src/warm_tree_err_9.bin");
// SAFETY: warm gather with the contract stated at `pretzel33_warm_tree_sec_0` above; this one reads
// 384 table bytes.
unsafe extern "C"{fn pretzel33_warm_tree_err_9_hi(o:*mut u64,t:*const u8,n:usize,i:*const u8);}
static WARM_TREE_ERR_9_HI:&[u8]=include_bytes!("../../pretzel-4-4/core/src/warm_tree_err_9_hi.bin");
// SAFETY: warm gather with the contract stated at `pretzel33_warm_tree_sec_0` above; this one reads
// 1344 table bytes.
unsafe extern "C"{fn pretzel33_warm_tree_err_tags(o:*mut u64,t:*const u8,n:usize,i:*const u8);}
static WARM_TREE_ERR_TAGS:&[u8]=include_bytes!("../../pretzel-4-4/core/src/warm_tree_err_tags.bin");
pub(crate) static WARM_TREE_ERR:WarmTail=WarmTail{levels:10,low:[WARM_TREE_ERR_0.as_ptr(),WARM_TREE_ERR_1.as_ptr(),WARM_TREE_ERR_2.as_ptr(),WARM_TREE_ERR_3.as_ptr(),WARM_TREE_ERR_4.as_ptr(),WARM_TREE_ERR_5.as_ptr(),WARM_TREE_ERR_6.as_ptr(),WARM_TREE_ERR_7.as_ptr(),WARM_TREE_ERR_8.as_ptr(),WARM_TREE_ERR_9.as_ptr()],high:[WARM_TREE_ERR_0_HI.as_ptr(),WARM_TREE_ERR_1_HI.as_ptr(),WARM_TREE_ERR_2_HI.as_ptr(),WARM_TREE_ERR_3_HI.as_ptr(),WARM_TREE_ERR_4_HI.as_ptr(),WARM_TREE_ERR_5_HI.as_ptr(),WARM_TREE_ERR_6_HI.as_ptr(),WARM_TREE_ERR_7_HI.as_ptr(),WARM_TREE_ERR_8_HI.as_ptr(),WARM_TREE_ERR_9_HI.as_ptr()],gather_low:[pretzel33_warm_tree_err_0,pretzel33_warm_tree_err_1,pretzel33_warm_tree_err_2,pretzel33_warm_tree_err_3,pretzel33_warm_tree_err_4,pretzel33_warm_tree_err_5,pretzel33_warm_tree_err_6,pretzel33_warm_tree_err_7,pretzel33_warm_tree_err_8,pretzel33_warm_tree_err_9],gather_high:[Some(pretzel33_warm_tree_err_0_hi),Some(pretzel33_warm_tree_err_1_hi),Some(pretzel33_warm_tree_err_2_hi),Some(pretzel33_warm_tree_err_3_hi),Some(pretzel33_warm_tree_err_4_hi),Some(pretzel33_warm_tree_err_5_hi),Some(pretzel33_warm_tree_err_6_hi),Some(pretzel33_warm_tree_err_7_hi),Some(pretzel33_warm_tree_err_8_hi),Some(pretzel33_warm_tree_err_9_hi)],tags:WARM_TREE_ERR_TAGS.as_ptr(),gather_tags:pretzel33_warm_tree_err_tags};
