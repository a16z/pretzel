#[repr(C)]
pub(crate) struct Reservoir{pub main:unsafe extern "C" fn(*mut u64,*const u8,usize,*const u8),pub mid:unsafe extern "C" fn(*mut u64,*const u8,usize,*const u8),pub suffix:unsafe extern "C" fn(*mut u64,*const u8,usize,*const u8),pub main_data:*const u8,pub mid_data:*const u8,pub suffix_data:*const u8,pub tree:*const WarmTail,pub mass:[u64;3]}
// SAFETY: Shared Rust access exposes only raw pointers and unsafe function pointers, with
// no safe pointee mutation. The sampler selects only RESERVOIR_SEC/ERR, whose pointers
// refer to immutable include_bytes! storage and static WarmTail descriptors; native outputs
// are separate caller-owned buffers.
unsafe impl Sync for Reservoir {}
// SAFETY: gather routine of `reservoir-tables.S`: straight-line NEON code without a branch. It
// reads 32 bytes at `i`, reads 5744 bytes of its table at `t` front to back (the whole of
// `reservoir_mid_sec.bin`), writes 256 bytes at `o` and ignores `n`. It keeps no pointer and has no
// global state.
unsafe extern "C"{fn pretzel44_reservoir_mid_sec(o:*mut u64,t:*const u8,n:usize,i:*const u8);}
// SAFETY: gather routine of `reservoir-tables.S`: straight-line NEON code without a branch. It
// reads 32 bytes at `i`, reads 5632 bytes of its table at `t` front to back (the whole of
// `reservoir_suffix_sec.bin`), writes 256 bytes at `o` and ignores `n`. It keeps no pointer and has
// no global state.
unsafe extern "C"{fn pretzel44_reservoir_suffix_sec(o:*mut u64,t:*const u8,n:usize,i:*const u8);}
pub(crate) static RESERVOIR_SEC:Reservoir=Reservoir{main:pretzel44_reservoir_main32_sec,mid:pretzel44_reservoir_mid_sec,suffix:pretzel44_reservoir_suffix_sec,main_data:include_bytes!("reservoir_main_sec.bin").as_ptr(),mid_data:include_bytes!("reservoir_mid_sec.bin").as_ptr(),suffix_data:include_bytes!("reservoir_suffix_sec.bin").as_ptr(),tree:&WARM_TREE_SEC,mass:[5993938723353355191, 58613409411, 0]};
// SAFETY: gather routine of `reservoir-tables.S`: straight-line NEON code without a branch. It
// reads 32 bytes at `i`, reads 6400 bytes of its table at `t` front to back (the whole of
// `reservoir_mid_err.bin`), writes 256 bytes at `o` and ignores `n`. It keeps no pointer and has no
// global state.
unsafe extern "C"{fn pretzel44_reservoir_mid_err(o:*mut u64,t:*const u8,n:usize,i:*const u8);}
// SAFETY: gather routine of `reservoir-tables.S`: straight-line NEON code without a branch. It
// reads 32 bytes at `i`, reads 5632 bytes of its table at `t` front to back (the whole of
// `reservoir_suffix_err.bin`), writes 256 bytes at `o` and ignores `n`. It keeps no pointer and has
// no global state.
unsafe extern "C"{fn pretzel44_reservoir_suffix_err(o:*mut u64,t:*const u8,n:usize,i:*const u8);}
pub(crate) static RESERVOIR_ERR:Reservoir=Reservoir{main:pretzel44_reservoir_main32_err,mid:pretzel44_reservoir_mid_err,suffix:pretzel44_reservoir_suffix_err,main_data:include_bytes!("reservoir_main_err.bin").as_ptr(),mid_data:include_bytes!("reservoir_mid_err.bin").as_ptr(),suffix_data:include_bytes!("reservoir_suffix_err.bin").as_ptr(),tree:&WARM_TREE_ERR,mass:[1908992111757984329, 14740274896686990316, 37]};
// SAFETY: contract of the wrapper in `reservoir-wrapper.S`, which calls
// `pretzel44_reservoir_sample_impl` (`reservoir-full.c`) with its arguments unchanged, then stores
// zero over 2048 bytes of stack below its frame and clears caller-saved registers and the flags.
// The C function reads 2632 bytes at `tape`, writes `n` `i32` at `out` four at a time (`n` a
// multiple of 4, at most 1024), and uses `work` as a 7328-byte workspace that must be initialized
// and aligned for `u64`. `t` must point to a `Reservoir` whose gather routines and tables belong
// together, as in the two statics of this file. Nothing is kept after the call. NEON only.
unsafe extern "C"{fn pretzel44_reservoir_sample(out:*mut i32,tape:*const u8,t:*const Reservoir,work:*mut u32,n:usize)->u64;}
// SAFETY: gather routine of `reservoir-tables.S`: straight-line NEON code without a branch. It
// reads 64 bytes at `i`, reads 1664 bytes of its table at `t` front to back (the whole of
// `reservoir_main_sec.bin`), writes 256 bytes at `o` and ignores `n`. It keeps no pointer and has
// no global state.
unsafe extern "C"{fn pretzel44_reservoir_main32_sec(o:*mut u64,t:*const u8,n:usize,i:*const u8);}

// SAFETY: gather routine of `reservoir-tables.S`: straight-line NEON code without a branch. It
// reads 64 bytes at `i`, reads 1920 bytes of its table at `t` front to back (the whole of
// `reservoir_main_err.bin`), writes 256 bytes at `o` and ignores `n`. It keeps no pointer and has
// no global state.
unsafe extern "C"{fn pretzel44_reservoir_main32_err(o:*mut u64,t:*const u8,n:usize,i:*const u8);}
