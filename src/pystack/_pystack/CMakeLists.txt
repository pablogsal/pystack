# PyStack C++ extension module via nanobind

# Find pthreads
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

# Collect common C++ source files (platform-independent)
set(PYSTACK_COMMON_SOURCES
    logging.cpp
    maps_parser.cpp
    mem.cpp
    process.cpp
    pycode.cpp
    pyframe.cpp
    pythread.cpp
    pytypes.cpp
    thread_builder.cpp
    version.cpp
    version_detector.cpp
    bindings.cpp
)

# Platform-specific source files
if(PYSTACK_MACOS)
    # macOS: exclude ELF/DWARF-specific files, add macOS utilities
    set(PYSTACK_SOURCES
        ${PYSTACK_COMMON_SOURCES}
        macos_utils.cpp
        macos_unwinder.cpp
    )
else()
    # Linux: include all ELF/DWARF files
    set(PYSTACK_SOURCES
        ${PYSTACK_COMMON_SOURCES}
        corefile.cpp
        elf_common.cpp
        unwinder.cpp
    )
endif()

# Create the nanobind module
nanobind_add_module(
    _pystack
    STABLE_ABI
    NB_STATIC
    ${PYSTACK_SOURCES}
)

# Include directories
# Note: We only include the source directory, not cpython/ directly.
# The cpython headers are included with "cpython/..." prefix to avoid
# conflicts with system headers (e.g., cpython/pthread.h vs /usr/include/pthread.h)
target_include_directories(_pystack PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

if(PYSTACK_MACOS)
    # macOS-specific configuration
    target_compile_definitions(_pystack PRIVATE
        PYSTACK_MACOS=1
    )

    # Build framehop FFI Rust library
    set(FRAMEHOP_FFI_DIR ${CMAKE_CURRENT_SOURCE_DIR}/framehop_ffi)
    set(FRAMEHOP_FFI_LIB ${FRAMEHOP_FFI_DIR}/target/release/libframehop_ffi.a)

    # Custom command to build the Rust library
    add_custom_command(
        OUTPUT ${FRAMEHOP_FFI_LIB}
        COMMAND cargo build --release
        WORKING_DIRECTORY ${FRAMEHOP_FFI_DIR}
        DEPENDS
            ${FRAMEHOP_FFI_DIR}/Cargo.toml
            ${FRAMEHOP_FFI_DIR}/src/lib.rs
        COMMENT "Building framehop FFI library"
        VERBATIM
    )

    # Custom target that depends on the library
    add_custom_target(framehop_ffi DEPENDS ${FRAMEHOP_FFI_LIB})

    # Make _pystack depend on framehop_ffi
    add_dependencies(_pystack framehop_ffi)

    # Link macOS frameworks and framehop FFI
    target_link_libraries(_pystack PRIVATE
        Threads::Threads
        "-framework CoreFoundation"
        ${FRAMEHOP_FFI_LIB}
    )
else()
    # Linux-specific configuration
    target_include_directories(_pystack PRIVATE
        ${LIBELF_INCLUDE_DIRS}
        ${LIBDW_INCLUDE_DIRS}
    )

    target_link_libraries(_pystack PRIVATE
        ${LIBELF_LIBRARIES}
        ${LIBDW_LIBRARIES}
        Threads::Threads
        dl
        stdc++fs
    )

    target_compile_definitions(_pystack PRIVATE
        ${LIBELF_CFLAGS_OTHER}
        ${LIBDW_CFLAGS_OTHER}
    )

    # Add pthread compile options (needed for C++ threading support on Linux)
    target_compile_options(_pystack PRIVATE -pthread)

    target_link_directories(_pystack PRIVATE
        ${LIBELF_LIBRARY_DIRS}
        ${LIBDW_LIBRARY_DIRS}
    )
endif()

# Install the module (destination is relative to wheel.install-dir in pyproject.toml)
install(TARGETS _pystack LIBRARY DESTINATION .)
