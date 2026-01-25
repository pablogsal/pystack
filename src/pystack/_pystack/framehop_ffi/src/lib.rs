//! FFI wrapper for framehop to expose stack unwinding functionality to C/C++.
//!
//! This crate provides a minimal C-compatible API for the framehop Rust crate,
//! allowing macOS native stack unwinding from C++ code.

use core::ops::Range;
use framehop::aarch64::{CacheAarch64, UnwindRegsAarch64, UnwinderAarch64};
use framehop::{ExplicitModuleSectionInfo, FrameAddress, MayAllocateDuringUnwind, Module, Unwinder};
use std::ffi::c_void;

/// Opaque handle to the unwinder
pub struct FramehopUnwinder {
    unwinder: UnwinderAarch64<Vec<u8>, MayAllocateDuringUnwind>,
}

/// Opaque handle to the unwinder cache
pub struct FramehopCache {
    cache: CacheAarch64<MayAllocateDuringUnwind>,
}

/// Registers for ARM64 stack unwinding
#[repr(C)]
pub struct FramehopRegs {
    pub pc: u64,
    pub lr: u64, // x30 - Link register
    pub sp: u64, // x31 - Stack pointer
    pub fp: u64, // x29 - Frame pointer
}

/// Module information for unwinding
#[repr(C)]
pub struct FramehopModule {
    /// Base address in virtual memory (AVMA - Actual Virtual Memory Address)
    pub base_avma: u64,
    /// End address in virtual memory
    pub end_avma: u64,
    /// Base address as stated in the binary (SVMA - Stated Virtual Memory Address)
    pub base_svma: u64,
    /// Pointer to __unwind_info section data (can be null)
    pub unwind_info: *const u8,
    /// Length of __unwind_info section
    pub unwind_info_len: usize,
    /// Pointer to __eh_frame section data (can be null)
    pub eh_frame: *const u8,
    /// Length of __eh_frame section
    pub eh_frame_len: usize,
    /// __text section start address (in SVMA)
    pub text_svma: u64,
    /// __text section end address (in SVMA)
    pub text_svma_end: u64,
    /// Length of __text section
    pub text_len: usize,
    /// Pointer to text section data (can be null for remote processes)
    pub text_data: *const u8,
}

/// Callback type for reading stack memory.
///
/// # Arguments
/// * `addr` - The address to read from
/// * `out` - Pointer to store the read value
/// * `ctx` - User context pointer
///
/// # Returns
/// * 0 on success
/// * -1 on error
pub type ReadStackFn = extern "C" fn(addr: u64, out: *mut u64, ctx: *mut c_void) -> i32;

/// Create a new unwinder instance.
///
/// # Returns
/// Opaque pointer to the unwinder, or null on failure.
#[no_mangle]
pub extern "C" fn framehop_unwinder_new() -> *mut FramehopUnwinder {
    let unwinder = Box::new(FramehopUnwinder {
        unwinder: UnwinderAarch64::new(),
    });
    Box::into_raw(unwinder)
}

/// Free an unwinder instance.
///
/// # Safety
/// The pointer must have been returned by `framehop_unwinder_new`.
#[no_mangle]
pub unsafe extern "C" fn framehop_unwinder_free(unwinder: *mut FramehopUnwinder) {
    if !unwinder.is_null() {
        drop(Box::from_raw(unwinder));
    }
}

/// Create a new cache instance.
///
/// # Returns
/// Opaque pointer to the cache, or null on failure.
#[no_mangle]
pub extern "C" fn framehop_cache_new() -> *mut FramehopCache {
    let cache = Box::new(FramehopCache {
        cache: CacheAarch64::new(),
    });
    Box::into_raw(cache)
}

/// Free a cache instance.
///
/// # Safety
/// The pointer must have been returned by `framehop_cache_new`.
#[no_mangle]
pub unsafe extern "C" fn framehop_cache_free(cache: *mut FramehopCache) {
    if !cache.is_null() {
        drop(Box::from_raw(cache));
    }
}

/// Add a module to the unwinder.
///
/// # Safety
/// - `unwinder` must be a valid pointer from `framehop_unwinder_new`
/// - `module` must point to a valid `FramehopModule` structure
/// - Any non-null data pointers in `module` must be valid for the specified lengths
#[no_mangle]
pub unsafe extern "C" fn framehop_add_module(
    unwinder: *mut FramehopUnwinder,
    module: *const FramehopModule,
) -> i32 {
    if unwinder.is_null() || module.is_null() {
        return -1;
    }

    let unwinder = &mut *unwinder;
    let module = &*module;

    // Copy unwind info data
    let unwind_info = if !module.unwind_info.is_null() && module.unwind_info_len > 0 {
        Some(std::slice::from_raw_parts(module.unwind_info, module.unwind_info_len).to_vec())
    } else {
        None
    };

    // Copy eh_frame data
    let eh_frame = if !module.eh_frame.is_null() && module.eh_frame_len > 0 {
        Some(std::slice::from_raw_parts(module.eh_frame, module.eh_frame_len).to_vec())
    } else {
        None
    };

    // Copy text data if available
    let text = if !module.text_data.is_null() && module.text_len > 0 {
        Some(std::slice::from_raw_parts(module.text_data, module.text_len).to_vec())
    } else {
        None
    };

    let text_svma = if module.text_svma != 0 && module.text_svma_end != 0 {
        Some(Range {
            start: module.text_svma,
            end: module.text_svma_end,
        })
    } else {
        None
    };

    let section_info = ExplicitModuleSectionInfo {
        base_svma: module.base_svma,
        text_svma,
        text,
        stubs_svma: None,
        stub_helper_svma: None,
        got_svma: None,
        unwind_info,
        eh_frame_svma: None,
        eh_frame,
        eh_frame_hdr_svma: None,
        eh_frame_hdr: None,
        debug_frame: None,
        text_segment_svma: None,
        text_segment: None,
    };

    let mod_obj = Module::new(
        String::new(), // name not needed for FFI
        Range {
            start: module.base_avma,
            end: module.end_avma,
        },
        module.base_avma,
        section_info,
    );

    unwinder.unwinder.add_module(mod_obj);

    0
}

/// Unwind a thread's stack frames.
///
/// # Arguments
/// * `unwinder` - Unwinder instance
/// * `cache` - Cache instance
/// * `regs` - Initial register state
/// * `read_stack` - Callback to read stack memory
/// * `ctx` - User context passed to read_stack
/// * `frames_out` - Output array for frame addresses (PCs)
/// * `max_frames` - Maximum number of frames to unwind
///
/// # Returns
/// Number of frames unwound, or 0 on error.
///
/// # Safety
/// All pointers must be valid. `frames_out` must have space for `max_frames` entries.
#[no_mangle]
pub unsafe extern "C" fn framehop_unwind(
    unwinder: *mut FramehopUnwinder,
    cache: *mut FramehopCache,
    regs: *const FramehopRegs,
    read_stack: ReadStackFn,
    ctx: *mut c_void,
    frames_out: *mut u64,
    max_frames: usize,
) -> usize {
    if unwinder.is_null() || cache.is_null() || regs.is_null() || frames_out.is_null() {
        return 0;
    }

    let unwinder = &*unwinder;
    let cache = &mut *cache;
    let regs = &*regs;

    // Initialize registers for unwinding
    let unwind_regs = UnwindRegsAarch64::new(regs.lr, regs.sp, regs.fp);

    let frames = std::slice::from_raw_parts_mut(frames_out, max_frames);
    let mut frame_count = 0;

    // Create a memory reader closure
    let mut read_mem = |addr: u64| -> Result<u64, ()> {
        let mut value: u64 = 0;
        if read_stack(addr, &mut value, ctx) == 0 {
            Ok(value)
        } else {
            Err(())
        }
    };

    // Use the iterator API
    let mut iter = unwinder.unwinder.iter_frames(
        regs.pc,
        unwind_regs,
        &mut cache.cache,
        &mut read_mem,
    );

    // Collect frames
    loop {
        if frame_count >= max_frames {
            break;
        }

        match iter.next() {
            Ok(Some(frame_addr)) => {
                let pc = match frame_addr {
                    FrameAddress::InstructionPointer(addr) => addr,
                    FrameAddress::ReturnAddress(addr) => addr.get(),
                };

                frames[frame_count] = pc;
                frame_count += 1;
            }
            Ok(None) => {
                // Normal end of stack
                break;
            }
            Err(_) => {
                // Error during unwinding - stop but keep frames we have
                break;
            }
        }
    }

    frame_count
}
