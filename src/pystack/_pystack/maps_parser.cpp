#include "maps_parser.h"

#include <algorithm>
#include <climits>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <regex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <unistd.h>
#include <unordered_map>

#ifdef PYSTACK_MACOS
#    include <libproc.h>
#    include <mach/mach.h>
#    include <mach/mach_vm.h>
#    include <mach/task_info.h>
#    include <mach-o/dyld_images.h>
#    include <mach-o/loader.h>
#    include <sys/sysctl.h>
#endif

#include "logging.h"

namespace pystack {

namespace fs = std::filesystem;

#ifdef PYSTACK_MACOS

// Helper structure to store dyld image info
struct DyldImageInfo
{
    uintptr_t load_address;
    uintptr_t end_address;  // load_address + vmsize from __TEXT segment
    std::string path;
};

// Read the Mach-O header from a remote process and extract vmsize from __TEXT segment
// For non-shared-cache libraries, this gives us the text segment size.
// The end_address field is used as a hint, but we also use sorted lookup for matching.
static bool
getMachOTextSize(mach_port_t task, uintptr_t load_address, uintptr_t& vmsize)
{
    vmsize = 0;

    // Read the Mach-O header from the target process
    struct mach_header_64 header;
    mach_vm_size_t read_size = 0;
    kern_return_t kr = mach_vm_read_overwrite(
            task,
            load_address,
            sizeof(header),
            (mach_vm_address_t)&header,
            &read_size);
    if (kr != KERN_SUCCESS || read_size != sizeof(header)) {
        return false;
    }

    // Verify it's a 64-bit Mach-O
    if (header.magic != MH_MAGIC_64) {
        return false;
    }

    // Read the load commands
    uint32_t sizeofcmds = header.sizeofcmds;
    std::vector<uint8_t> load_commands(sizeofcmds);
    kr = mach_vm_read_overwrite(
            task,
            load_address + sizeof(header),
            sizeofcmds,
            (mach_vm_address_t)load_commands.data(),
            &read_size);
    if (kr != KERN_SUCCESS || read_size != sizeofcmds) {
        return false;
    }

    // Parse load commands to find __TEXT segment vmsize
    uint32_t offset = 0;
    for (uint32_t i = 0; i < header.ncmds && offset < sizeofcmds; i++) {
        struct load_command* cmd = (struct load_command*)(load_commands.data() + offset);
        if (cmd->cmd == LC_SEGMENT_64) {
            struct segment_command_64* seg = (struct segment_command_64*)cmd;
            if (strncmp(seg->segname, "__TEXT", 16) == 0) {
                vmsize = seg->vmsize;
                return true;
            }
        }
        offset += cmd->cmdsize;
    }

    return false;
}

// Helper to read a single dyld image info
static bool
readDyldImageInfo(mach_port_t task, uintptr_t load_address, uintptr_t path_addr, DyldImageInfo& info)
{
    info.load_address = load_address;
    info.end_address = load_address;

    // Read the Mach-O header to get __TEXT vmsize
    uintptr_t vmsize = 0;
    if (getMachOTextSize(task, load_address, vmsize)) {
        info.end_address = load_address + vmsize;
    }

    // Read the file path string from the target process
    if (path_addr != 0) {
        char path_buffer[PATH_MAX];
        mach_vm_size_t read_size = 0;
        kern_return_t kr = mach_vm_read_overwrite(
                task,
                path_addr,
                sizeof(path_buffer) - 1,
                (mach_vm_address_t)path_buffer,
                &read_size);
        if (kr == KERN_SUCCESS && read_size > 0) {
            path_buffer[read_size] = '\0';
            info.path = std::string(path_buffer);
        }
    }

    return true;
}

// Get all loaded images from dyld_all_image_infos
// This follows exactly what samply does in enumerate_dyld_images()
static std::vector<DyldImageInfo>
getDyldImages(mach_port_t task)
{
    std::vector<DyldImageInfo> images;

    // Get dyld_all_image_infos address using task_info
    struct task_dyld_info dyld_info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    kern_return_t kr = task_info(task, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count);
    if (kr != KERN_SUCCESS) {
        LOG(DEBUG) << "task_info(TASK_DYLD_INFO) failed: " << mach_error_string(kr);
        return images;
    }

    if (dyld_info.all_image_info_addr == 0) {
        LOG(DEBUG) << "dyld_all_image_infos address is null";
        return images;
    }

    // Read dyld_all_image_infos structure from the target process
    struct dyld_all_image_infos all_image_infos;
    mach_vm_size_t read_size = 0;
    kr = mach_vm_read_overwrite(
            task,
            dyld_info.all_image_info_addr,
            sizeof(all_image_infos),
            (mach_vm_address_t)&all_image_infos,
            &read_size);
    if (kr != KERN_SUCCESS || read_size != sizeof(all_image_infos)) {
        LOG(DEBUG) << "Failed to read dyld_all_image_infos: " << mach_error_string(kr);
        return images;
    }

    // IMPORTANT: Add dyld itself FIRST (exactly like samply does)
    // dyld is the dynamic linker and is stored separately from the infoArray
    if (all_image_infos.dyldImageLoadAddress != nullptr) {
        DyldImageInfo dyld_itself;
        if (readDyldImageInfo(
                    task,
                    (uintptr_t)all_image_infos.dyldImageLoadAddress,
                    (uintptr_t)all_image_infos.dyldPath,
                    dyld_itself))
        {
            images.push_back(std::move(dyld_itself));
        }
    }

    if (all_image_infos.infoArray == nullptr || all_image_infos.infoArrayCount == 0) {
        LOG(DEBUG) << "dyld_all_image_infos has no images";
        return images;
    }

    // Read the image info array
    uint32_t image_count = all_image_infos.infoArrayCount;
    std::vector<struct dyld_image_info> image_infos(image_count);
    kr = mach_vm_read_overwrite(
            task,
            (mach_vm_address_t)all_image_infos.infoArray,
            image_count * sizeof(struct dyld_image_info),
            (mach_vm_address_t)image_infos.data(),
            &read_size);
    if (kr != KERN_SUCCESS) {
        LOG(DEBUG) << "Failed to read dyld_image_info array: " << mach_error_string(kr);
        return images;
    }

    // Extract information for each image
    for (uint32_t i = 0; i < image_count; i++) {
        DyldImageInfo info;
        if (readDyldImageInfo(
                    task,
                    (uintptr_t)image_infos[i].imageLoadAddress,
                    (uintptr_t)image_infos[i].imageFilePath,
                    info))
        {
            images.push_back(std::move(info));
        }
    }

    // Sort by load_address (exactly like samply does)
    std::sort(images.begin(), images.end(), [](const DyldImageInfo& a, const DyldImageInfo& b) {
        return a.load_address < b.load_address;
    });

    LOG(DEBUG) << "DYLD: Found " << images.size() << " images";
    return images;
}

// macOS implementation using Mach VM APIs
std::vector<VirtualMap>
parseMachMaps(pid_t pid)
{
    std::vector<VirtualMap> maps;

    // Get task port for the process
    mach_port_t task;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS) {
        LOG(ERROR) << "task_for_pid failed for pid " << pid << ": " << mach_error_string(kr);
        if (kr == KERN_FAILURE) {
            throw std::runtime_error(
                    "Operation not permitted. On macOS, debugging requires either:\n"
                    "1. Running as root (sudo)\n"
                    "2. The target process being signed with get-task-allow entitlement\n"
                    "3. SIP (System Integrity Protection) to be appropriately configured");
        }
        throw std::runtime_error(std::string("task_for_pid failed: ") + mach_error_string(kr));
    }

    // Get dyld images for path lookup (includes system libraries in dyld cache)
    // This reads Mach-O headers to get vmsize, exactly like samply does
    auto dyld_images = getDyldImages(task);

    mach_vm_address_t address = 0;
    mach_vm_size_t size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t info_count;
    mach_port_t object_name;

    while (true) {
        info_count = VM_REGION_BASIC_INFO_COUNT_64;
        kr = mach_vm_region(
                task,
                &address,
                &size,
                VM_REGION_BASIC_INFO_64,
                (vm_region_info_t)&info,
                &info_count,
                &object_name);

        if (kr != KERN_SUCCESS) {
            break;  // No more regions
        }

        // Build permission string (rwxp format like Linux)
        std::string flags;
        flags += (info.protection & VM_PROT_READ) ? 'r' : '-';
        flags += (info.protection & VM_PROT_WRITE) ? 'w' : '-';
        flags += (info.protection & VM_PROT_EXECUTE) ? 'x' : '-';
        flags += (info.shared) ? 's' : 'p';

        // Get the file path for this region if it's file-backed
        std::string pathname;
        char path_buffer[PROC_PIDPATHINFO_MAXSIZE];
        int ret = proc_regionfilename(pid, address, path_buffer, sizeof(path_buffer));
        if (ret > 0) {
            pathname = std::string(path_buffer);
        }

        // If proc_regionfilename didn't give us a path, try looking up in dyld images
        // This handles system libraries in the dyld shared cache
        // Images are sorted by load_address, so find the library that contains this address
        if (pathname.empty() && !dyld_images.empty()) {
            // Binary search to find the last image with load_address <= address
            auto it = std::upper_bound(
                    dyld_images.begin(),
                    dyld_images.end(),
                    address,
                    [](uintptr_t addr, const DyldImageInfo& img) { return addr < img.load_address; });

            // upper_bound returns first element > address, so go back one
            if (it != dyld_images.begin()) {
                --it;
                // Check if address is within this library's range
                if (address >= it->load_address && address < it->end_address) {
                    pathname = it->path;
                }
            }
        }

        maps.emplace_back(
                static_cast<uintptr_t>(address),
                static_cast<uintptr_t>(address + size),
                static_cast<unsigned long>(size),  // filesize
                flags,
                static_cast<unsigned long>(info.offset),
                "",  // device (not applicable on macOS)
                0,  // inode (not easily available on macOS)
                pathname);

        LOG(DEBUG) << std::hex << "Region: " << address << "-" << (address + size) << " " << flags << " "
                   << pathname;

        address += size;
    }

    mach_port_deallocate(mach_task_self(), task);

    return maps;
}

#else  // Linux

// Regex pattern for parsing /proc/pid/maps lines
// Format: start-end permissions offset dev inode pathname
static const std::regex MAPS_REGEXP(
        R"(([0-9a-f]+)-([0-9a-f]+)\s+(.{4})\s+([0-9a-f]+)\s+([0-9a-f]+:[0-9a-f]+)\s+(\d+)\s*(.*)?)");

std::vector<VirtualMap>
parseProcMaps(pid_t pid)
{
    std::vector<VirtualMap> maps;
    std::string maps_path = "/proc/" + std::to_string(pid) + "/maps";

    std::ifstream maps_file(maps_path);
    if (!maps_file.is_open()) {
        throw std::runtime_error("No such process id: " + std::to_string(pid));
    }

    std::string line;
    while (std::getline(maps_file, line)) {
        std::smatch match;
        if (!std::regex_match(line, match, MAPS_REGEXP)) {
            LOG(DEBUG) << "Line cannot be recognized: " << line;
            continue;
        }

        uintptr_t start = std::stoull(match[1].str(), nullptr, 16);
        uintptr_t end = std::stoull(match[2].str(), nullptr, 16);
        std::string permissions = match[3].str();
        unsigned long offset = std::stoul(match[4].str(), nullptr, 16);
        std::string device = match[5].str();
        unsigned long inode = std::stoul(match[6].str());
        std::string pathname = match[7].str();

        size_t start_pos = pathname.find_first_not_of(" \t");
        if (start_pos != std::string::npos) {
            pathname = pathname.substr(start_pos);
        } else {
            pathname = "";
        }

        maps.emplace_back(
                start,
                end,
                end - start,  // filesize
                permissions,
                offset,
                device,
                inode,
                pathname);
    }

    return maps;
}

#endif  // PYSTACK_MACOS

#ifndef PYSTACK_MACOS

std::vector<VirtualMap>
parseCoreFileMaps(
        const std::vector<CoreVirtualMap>& mapped_files,
        const std::vector<CoreVirtualMap>& memory_maps)
{
    std::set<std::pair<uintptr_t, uintptr_t>> memory_map_ranges;
    for (const auto& map : memory_maps) {
        memory_map_ranges.insert({map.start, map.end});
    }

    std::vector<CoreVirtualMap> missing_mapped_files;
    for (const auto& map : mapped_files) {
        if (memory_map_ranges.find({map.start, map.end}) == memory_map_ranges.end()) {
            missing_mapped_files.push_back(map);
        }
    }

    std::vector<CoreVirtualMap> all_maps;
    all_maps.reserve(memory_maps.size() + missing_mapped_files.size());
    all_maps.insert(all_maps.end(), memory_maps.begin(), memory_maps.end());
    all_maps.insert(all_maps.end(), missing_mapped_files.begin(), missing_mapped_files.end());

    std::sort(all_maps.begin(), all_maps.end(), [](const CoreVirtualMap& a, const CoreVirtualMap& b) {
        return a.start < b.start;
    });

    std::set<std::string> missing_map_paths;
    for (const auto& map : missing_mapped_files) {
        if (!map.path.empty()) {
            try {
                missing_map_paths.insert(fs::canonical(map.path).string());
            } catch (...) {
                missing_map_paths.insert(map.path);
            }
        }
    }

    std::unordered_map<std::string, std::string> file_maps;
    for (const auto& map : memory_maps) {
        if (map.path.empty()) {
            continue;
        }
        try {
            std::string resolved_path = fs::canonical(map.path).string();
            if (missing_map_paths.count(resolved_path)) {
                file_maps[resolved_path] = map.path;
            }
        } catch (...) {
            // Ignore errors resolving paths
        }
    }

    std::vector<VirtualMap> result;
    result.reserve(all_maps.size());
    for (const auto& elem : all_maps) {
        std::string path = elem.path;
        if (!path.empty()) {
            std::string resolved;
            try {
                resolved = fs::canonical(path).string();
            } catch (...) {
                resolved = path;
            }
            auto it = file_maps.find(resolved);
            if (it != file_maps.end()) {
                path = it->second;
            }
        }
        result.emplace_back(
                elem.start,
                elem.end,
                elem.filesize,
                elem.flags,
                elem.offset,
                elem.device,
                elem.inode,
                path);
    }

    return result;
}

#endif  // !PYSTACK_MACOS (for parseCoreFileMaps)

static VirtualMap
getBaseMap(const std::vector<VirtualMap>& binary_maps)
{
    for (const auto& map : binary_maps) {
        if (!map.Path().empty()) {
            return map;
        }
    }
    if (!binary_maps.empty()) {
        return binary_maps[0];
    }
    throw std::runtime_error("No maps available");
}

#ifdef PYSTACK_MACOS

// macOS: BSS section detection using Mach-O parsing
static std::optional<VirtualMap>
getBss(const std::vector<VirtualMap>& elf_maps, uintptr_t load_point)
{
    // On macOS, we don't have getSectionInfo for ELF files
    // We'll return nullopt and fall back to heuristics in the caller
    (void)load_point;  // unused
    if (elf_maps.empty()) {
        return std::nullopt;
    }
    // Fallback: look for anonymous writable regions as BSS candidates
    for (const auto& map : elf_maps) {
        if (map.Path().empty() && map.Flags().find('r') != std::string::npos
            && map.Flags().find('w') != std::string::npos)
        {
            return map;
        }
    }
    return std::nullopt;
}

#else  // Linux

static std::optional<VirtualMap>
getBss(const std::vector<VirtualMap>& elf_maps, uintptr_t load_point)
{
    if (elf_maps.empty()) {
        return std::nullopt;
    }

    VirtualMap binary_map = getBaseMap(elf_maps);
    if (binary_map.Path().empty()) {
        return std::nullopt;
    }

    SectionInfo bss_info;
    if (!getSectionInfo(binary_map.Path(), ".bss", &bss_info)) {
        return std::nullopt;
    }

    uintptr_t start = load_point + bss_info.corrected_addr;
    LOG(INFO) << "Determined exact addr of .bss section: " << std::hex << start << " (" << load_point
              << " + " << bss_info.corrected_addr << ")" << std::dec;

    unsigned long offset = 0;

    const VirtualMap* first_matching_map = nullptr;
    for (const auto& map : elf_maps) {
        if (map.containsAddr(start)) {
            first_matching_map = &map;
            break;
        }
    }

    if (!first_matching_map) {
        return std::nullopt;
    }

    offset = first_matching_map->Offset() + (start - first_matching_map->Start());

    return VirtualMap(
            start,
            start + bss_info.size,
            bss_info.size,
            "",  // flags
            offset,  // offset
            "",  // device
            0,  // inode
            "");  // path
}

#endif  // PYSTACK_MACOS (for getBss)

ProcessMemoryMapInfo
parseMapInformation(
        const std::string& binary,
        const std::vector<VirtualMap>& maps,
        const std::unordered_map<std::string, uintptr_t>* load_point_by_module)
{
    std::unordered_map<std::string, std::vector<VirtualMap>> maps_by_library;
    std::string current_lib;

    std::unordered_map<std::string, uintptr_t> computed_load_points;
    if (!load_point_by_module) {
        for (const auto& map : maps) {
            if (!map.Path().empty()) {
                std::string name = fs::path(map.Path()).filename().string();
                if (computed_load_points.find(name) == computed_load_points.end()) {
                    computed_load_points[name] = map.Start();
                } else {
                    computed_load_points[name] = std::min(computed_load_points[name], map.Start());
                }
            }
        }
        load_point_by_module = &computed_load_points;
    }

    for (const auto& memory_range : maps) {
        std::string path_name;
        if (!memory_range.Path().empty()) {
            path_name = fs::path(memory_range.Path()).filename().string();
            current_lib = path_name;
        } else {
            path_name = current_lib;
        }
        maps_by_library[path_name].push_back(memory_range);
    }

    std::string binary_name = fs::path(binary).filename().string();

    auto python_it = maps_by_library.find(binary_name);
    if (python_it == maps_by_library.end()) {
        // Construct error message with available maps
        std::ostringstream available;
        for (const auto& map : maps) {
            if (!map.Path().empty() && map.Path().find(".so") == std::string::npos) {
                available << map.Path() << ", ";
            }
        }
        std::string available_str = available.str();
        if (available_str.length() >= 2) {
            available_str = available_str.substr(0, available_str.length() - 2);
        }
        throw std::runtime_error(
                "Unable to find maps for the executable " + binary
                + ". Available executable maps: " + available_str);
    }

    const std::vector<VirtualMap>& binary_maps = python_it->second;
    VirtualMap python = getBaseMap(binary_maps);
    LOG(INFO) << "python binary first map found: " << python.Path();

    std::optional<VirtualMap> libpython;
    const std::vector<VirtualMap>* elf_maps = nullptr;
    std::string libpython_name;

    std::vector<std::string> libpython_binaries;
    for (const auto& [lib_name, _] : maps_by_library) {
        if (lib_name.find("libpython") != std::string::npos) {
            libpython_binaries.push_back(lib_name);
        }
    }

    uintptr_t load_point = 0;
    if (libpython_binaries.size() > 1) {
        throw std::runtime_error(
                "Unexpectedly found multiple libpython in process: "
                + std::to_string(libpython_binaries.size()));
    } else if (libpython_binaries.size() == 1) {
        libpython_name = libpython_binaries[0];
        const auto& libpython_maps = maps_by_library[libpython_name];
        elf_maps = &libpython_maps;
        auto load_it = load_point_by_module->find(libpython_name);
        load_point = (load_it != load_point_by_module->end()) ? load_it->second : UINTPTR_MAX;
        libpython = getBaseMap(libpython_maps);
        LOG(INFO) << libpython_name << " first map found: " << libpython->Path();
    } else {
        LOG(INFO) << "Process does not have a libpython.so, reading from binary";
        elf_maps = &binary_maps;
        auto load_it = load_point_by_module->find(binary_name);
        load_point = (load_it != load_point_by_module->end()) ? load_it->second : UINTPTR_MAX;
    }

    std::optional<VirtualMap> heap;
    auto heap_it = maps_by_library.find("[heap]");
    if (heap_it != maps_by_library.end() && !heap_it->second.empty()) {
        heap = heap_it->second.front();
        LOG(INFO) << "Heap map found";
    }

    std::optional<VirtualMap> bss = getBss(*elf_maps, load_point);
    if (!bss) {
        for (const auto& map : *elf_maps) {
            if (map.Path().empty() && map.Flags().find('r') != std::string::npos) {
                bss = map;
                break;
            }
        }
    }
    if (bss) {
        LOG(INFO) << "bss map found";
    }

    return ProcessMemoryMapInfo{heap, bss, python, libpython};
}

ProcessMemoryMapInfo
parseMapInformationForProcess(pid_t pid, const std::vector<VirtualMap>& maps)
{
#ifdef PYSTACK_MACOS
    char exe_path[PROC_PIDPATHINFO_MAXSIZE];
    int ret = proc_pidpath(pid, exe_path, sizeof(exe_path));
    if (ret <= 0) {
        throw std::runtime_error("Failed to get executable path for pid " + std::to_string(pid));
    }
#else
    std::string exe_link = "/proc/" + std::to_string(pid) + "/exe";
    char exe_path[PATH_MAX];
    ssize_t len = readlink(exe_link.c_str(), exe_path, sizeof(exe_path) - 1);
    if (len == -1) {
        throw std::runtime_error("Failed to read /proc/" + std::to_string(pid) + "/exe");
    }
    exe_path[len] = '\0';
#endif
    return parseMapInformation(exe_path, maps);
}

std::optional<std::string>
getThreadName(pid_t pid, pid_t tid)
{
#ifdef PYSTACK_MACOS
    // On macOS, thread names are not easily accessible for remote processes
    // We would need task_threads() + thread_info() with THREAD_EXTENDED_INFO
    // For simplicity, return nullopt and the caller can use the tid as an identifier
    (void)pid;
    (void)tid;
    return std::nullopt;
#else
    std::string comm_path = "/proc/" + std::to_string(pid) + "/task/" + std::to_string(tid) + "/comm";
    std::ifstream comm_file(comm_path);
    if (!comm_file.is_open()) {
        return std::nullopt;
    }

    std::string name;
    std::getline(comm_file, name);

    size_t end = name.find_last_not_of(" \t\n\r");
    if (end != std::string::npos) {
        name = name.substr(0, end + 1);
    }

    return name;
#endif
}

}  // namespace pystack
