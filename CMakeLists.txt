cmake_minimum_required(VERSION 3.17...3.27)

project(pystack LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Find Python
find_package(Python 3.9 COMPONENTS Interpreter Development.Module REQUIRED)

# Find nanobind
execute_process(
    COMMAND "${Python_EXECUTABLE}" -m nanobind --cmake_dir
    OUTPUT_STRIP_TRAILING_WHITESPACE OUTPUT_VARIABLE nanobind_ROOT)
find_package(nanobind CONFIG REQUIRED)

# Platform detection
if(APPLE)
    set(PYSTACK_MACOS TRUE)
    message(STATUS "Building for macOS - ELF/DWARF support disabled")
else()
    set(PYSTACK_MACOS FALSE)
    # Find libelf and libdw via pkg-config (Linux only)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LIBELF REQUIRED libelf)
    pkg_check_modules(LIBDW REQUIRED libdw)
endif()

# Add the extension module subdirectory
add_subdirectory(src/pystack/_pystack)
