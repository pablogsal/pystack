#pragma once

#ifdef PYSTACK_MACOS

#include <cstddef>
#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

/// Opaque handle to the framehop unwinder
typedef struct FramehopUnwinder FramehopUnwinder;

/// Opaque handle to the framehop cache
typedef struct FramehopCache FramehopCache;

/// Registers for ARM64 stack unwinding
typedef struct {
    uint64_t pc;  // Program counter
    uint64_t lr;  // Link register (x30)
    uint64_t sp;  // Stack pointer (x31)
    uint64_t fp;  // Frame pointer (x29)
} FramehopRegs;

/// Module information for unwinding
typedef struct {
    /// Base address in virtual memory (AVMA - Actual Virtual Memory Address)
    uint64_t base_avma;
    /// End address in virtual memory
    uint64_t end_avma;
    /// Base address as stated in the binary (SVMA - Stated Virtual Memory Address)
    uint64_t base_svma;
    /// Pointer to __unwind_info section data (can be null)
    const uint8_t* unwind_info;
    /// Length of __unwind_info section
    size_t unwind_info_len;
    /// Pointer to __eh_frame section data (can be null)
    const uint8_t* eh_frame;
    /// Length of __eh_frame section
    size_t eh_frame_len;
    /// __text section start address (in SVMA)
    uint64_t text_svma;
    /// __text section end address (in SVMA)
    uint64_t text_svma_end;
    /// Length of __text section
    size_t text_len;
    /// Pointer to text section data (can be null for remote processes)
    const uint8_t* text_data;
} FramehopModule;

/// Callback type for reading stack memory.
///
/// @param addr The address to read from
/// @param out Pointer to store the 8-byte value
/// @param ctx User context pointer
/// @return 0 on success, -1 on error
typedef int (*FramehopReadStackFn)(uint64_t addr, uint64_t* out, void* ctx);

/// Create a new unwinder instance.
///
/// @return Opaque pointer to the unwinder, or NULL on failure.
FramehopUnwinder* framehop_unwinder_new(void);

/// Free an unwinder instance.
///
/// @param unwinder Pointer returned by framehop_unwinder_new
void framehop_unwinder_free(FramehopUnwinder* unwinder);

/// Create a new cache instance.
///
/// @return Opaque pointer to the cache, or NULL on failure.
FramehopCache* framehop_cache_new(void);

/// Free a cache instance.
///
/// @param cache Pointer returned by framehop_cache_new
void framehop_cache_free(FramehopCache* cache);

/// Add a module to the unwinder.
///
/// @param unwinder Unwinder instance
/// @param module Module information
/// @return 0 on success, -1 on error
int framehop_add_module(FramehopUnwinder* unwinder, const FramehopModule* module);

/// Unwind a thread's stack frames.
///
/// @param unwinder Unwinder instance
/// @param cache Cache instance
/// @param regs Initial register state
/// @param read_stack Callback to read stack memory
/// @param ctx User context passed to read_stack
/// @param frames_out Output array for frame addresses (PCs)
/// @param max_frames Maximum number of frames to unwind
/// @return Number of frames unwound, or 0 on error
size_t framehop_unwind(
        FramehopUnwinder* unwinder,
        FramehopCache* cache,
        const FramehopRegs* regs,
        FramehopReadStackFn read_stack,
        void* ctx,
        uint64_t* frames_out,
        size_t max_frames);

#ifdef __cplusplus
}
#endif

#endif  // PYSTACK_MACOS
