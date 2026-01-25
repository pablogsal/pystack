#ifdef PYSTACK_MACOS

#include "macos_unwinder.h"

#include <algorithm>
#include <climits>
#include <cstdint>
#include <cstring>
#include <cxxabi.h>
#include <dirent.h>
#include <fcntl.h>
#include <mach-o/dyld_images.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/task_info.h>
#include <mach/thread_act.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <unistd.h>

#include "framehop_ffi.h"
#include "logging.h"
#include "macos_utils.h"

namespace pystack {

namespace {

// ============================================================================
// dyld_shared_cache structures (from dyld source)
// ============================================================================

struct dyld_cache_header
{
    char magic[16];                 // "dyld_v1  arm64e" etc
    uint32_t mappingOffset;         // file offset to dyld_cache_mapping_info
    uint32_t mappingCount;
    uint32_t imagesOffsetOld;       // UNUSED: file offset to dyld_cache_image_info
    uint32_t imagesCountOld;        // UNUSED
    uint64_t dyldBaseAddress;
    uint64_t codeSignatureOffset;
    uint64_t codeSignatureSize;
    uint64_t slideInfoOffsetUnused;
    uint64_t slideInfoSizeUnused;
    uint64_t localSymbolsOffset;    // file offset of local symbols
    uint64_t localSymbolsSize;
    uint8_t uuid[16];
    uint64_t cacheType;
    uint32_t branchPoolsOffset;
    uint32_t branchPoolsCount;
    uint64_t accelerateInfoAddr_UNUSED;
    uint64_t accelerateInfoSize_UNUSED;
    uint64_t imagesTextOffset;      // file offset to dyld_cache_image_text_info
    uint64_t imagesTextCount;
    uint64_t patchInfoAddr;
    uint64_t patchInfoSize;
    uint64_t otherImageGroupAddrUnused;
    uint64_t otherImageGroupSizeUnused;
    uint64_t progClosuresAddr;
    uint64_t progClosuresSize;
    uint64_t progClosuresTrieAddr;
    uint64_t progClosuresTrieSize;
    uint32_t platform;
    uint32_t formatVersion : 8, dylibsExpectedOnDisk : 1, simulator : 1, locallyBuiltCache : 1,
            builtFromChainedFixups : 1, padding : 20;
    uint64_t sharedRegionStart;
    uint64_t sharedRegionSize;
    uint64_t maxSlide;
    uint64_t dylibsImageArrayAddr;
    uint64_t dylibsImageArraySize;
    uint64_t dylibsTrieAddr;
    uint64_t dylibsTrieSize;
    uint64_t otherImageArrayAddr;
    uint64_t otherImageArraySize;
    uint64_t otherTrieAddr;
    uint64_t otherTrieSize;
    uint32_t mappingWithSlideOffset;
    uint32_t mappingWithSlideCount;
    uint64_t dylibsPBLStateArrayAddrUnused;
    uint64_t dylibsPBLSetAddr;
    uint64_t programsPBLSetPoolAddr;
    uint64_t programsPBLSetPoolSize;
    uint64_t programTrieAddr;
    uint32_t programTrieSize;
    uint32_t osVersion;
    uint32_t altPlatform;
    uint32_t altOsVersion;
    uint64_t swiftOptsOffset;
    uint64_t swiftOptsSize;
    uint32_t subCacheArrayOffset;
    uint32_t subCacheArrayCount;
    uint8_t symbolFileUUID[16];
    uint64_t rosettaReadOnlyAddr;
    uint64_t rosettaReadOnlySize;
    uint64_t rosettaReadWriteAddr;
    uint64_t rosettaReadWriteSize;
    uint32_t imagesOffset;          // file offset to dyld_cache_image_info
    uint32_t imagesCount;
};

struct dyld_cache_mapping_info
{
    uint64_t address;
    uint64_t size;
    uint64_t fileOffset;
    uint32_t maxProt;
    uint32_t initProt;
};

struct dyld_cache_image_info
{
    uint64_t address;
    uint64_t modTime;
    uint64_t inode;
    uint32_t pathFileOffset;
    uint32_t pad;
};

// ============================================================================
// DyldSharedCache - helper class to parse the dyld shared cache
// ============================================================================

class DyldSharedCache
{
  public:
    struct CacheFile
    {
        int fd;
        void* map;
        size_t size;
        const dyld_cache_header* header;
        const dyld_cache_mapping_info* mappings;
        uint32_t mapping_count;

        CacheFile()
        : fd(-1)
        , map(MAP_FAILED)
        , size(0)
        , header(nullptr)
        , mappings(nullptr)
        , mapping_count(0)
        {
        }
        ~CacheFile()
        {
            if (map != MAP_FAILED) {
                munmap(map, size);
            }
            if (fd >= 0) {
                close(fd);
            }
        }
        CacheFile(const CacheFile&) = delete;
        CacheFile& operator=(const CacheFile&) = delete;

        bool open(const std::string& path)
        {
            fd = ::open(path.c_str(), O_RDONLY);
            if (fd < 0) {
                return false;
            }
            struct stat st;
            if (fstat(fd, &st) < 0) {
                close(fd);
                fd = -1;
                return false;
            }
            size = st.st_size;
            map = mmap(nullptr, size, PROT_READ, MAP_SHARED, fd, 0);
            if (map == MAP_FAILED) {
                close(fd);
                fd = -1;
                return false;
            }

            // Parse header and mappings for this cache file
            if (size >= sizeof(dyld_cache_header)) {
                header = static_cast<const dyld_cache_header*>(map);
                if (header->mappingOffset + header->mappingCount * sizeof(dyld_cache_mapping_info) <= size) {
                    mappings = reinterpret_cast<const dyld_cache_mapping_info*>(
                            static_cast<const char*>(map) + header->mappingOffset);
                    mapping_count = header->mappingCount;
                }
            }
            return true;
        }

        bool valid() const
        {
            return map != MAP_FAILED;
        }

        // Check if this file contains the given address and return the file offset
        std::pair<bool, uint64_t> addressToFileOffset(uint64_t addr) const
        {
            if (!mappings) {
                return {false, 0};
            }
            for (uint32_t i = 0; i < mapping_count; i++) {
                const auto& mapping = mappings[i];
                if (addr >= mapping.address && addr < mapping.address + mapping.size) {
                    uint64_t offset = mapping.fileOffset + (addr - mapping.address);
                    if (offset < size) {
                        return {true, offset};
                    }
                }
            }
            return {false, 0};
        }
    };

    DyldSharedCache() = default;

    bool load()
    {
        // Try macOS 13+ location first
        std::string base_path = "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/";
        std::string arch = "arm64e";  // TODO: detect architecture

        std::string main_path = base_path + "dyld_shared_cache_" + arch;
        if (!d_main_cache.open(main_path)) {
            // Try macOS 11-12 location
            base_path = "/System/Library/dyld/";
            main_path = base_path + "dyld_shared_cache_" + arch;
            if (!d_main_cache.open(main_path)) {
                LOG(DEBUG) << "Failed to open dyld shared cache";
                return false;
            }
        }

        // Load subcaches (.01, .02, ... or .1, .2, ...)
        for (int i = 1; i < 100; i++) {
            char suffix[16];
            snprintf(suffix, sizeof(suffix), ".%02d", i);
            std::string subcache_path = main_path + suffix;

            auto subcache = std::make_unique<CacheFile>();
            if (!subcache->open(subcache_path)) {
                // Try single-digit suffix
                snprintf(suffix, sizeof(suffix), ".%d", i);
                subcache_path = main_path + suffix;
                if (!subcache->open(subcache_path)) {
                    break;  // No more subcaches
                }
            }
            d_subcaches.push_back(std::move(subcache));
        }

        // Load .symbols subcache if it exists
        std::string symbols_path = main_path + ".symbols";
        d_symbols_cache.open(symbols_path);  // OK if this fails

        // Get header info from main cache
        d_header = d_main_cache.header;
        if (!d_header) {
            return false;
        }

        // Parse images from main cache
        if (d_header->imagesOffset + d_header->imagesCount * sizeof(dyld_cache_image_info)
            > d_main_cache.size)
        {
            return false;
        }
        d_images = reinterpret_cast<const dyld_cache_image_info*>(
                static_cast<const char*>(d_main_cache.map) + d_header->imagesOffset);

        LOG(DEBUG) << "Loaded dyld shared cache with " << d_header->imagesCount << " images and "
                   << d_subcaches.size() << " subcaches";
        return true;
    }

    // Find the image info for a given path
    const dyld_cache_image_info* findImage(const std::string& path) const
    {
        if (!d_header || !d_images) {
            return nullptr;
        }
        for (uint32_t i = 0; i < d_header->imagesCount; i++) {
            const char* img_path =
                    static_cast<const char*>(d_main_cache.map) + d_images[i].pathFileOffset;
            if (path == img_path) {
                return &d_images[i];
            }
        }
        return nullptr;
    }

    // Translate a cache address to (file_data, file_offset)
    // Search ALL cache files (main + subcaches) like samply does
    std::pair<const void*, uint64_t> addressToData(uint64_t addr) const
    {
        // Check main cache first
        auto [found, offset] = d_main_cache.addressToFileOffset(addr);
        if (found) {
            return {d_main_cache.map, offset};
        }

        // Check each subcache
        for (const auto& subcache : d_subcaches) {
            auto [found, offset] = subcache->addressToFileOffset(addr);
            if (found) {
                return {subcache->map, offset};
            }
        }

        // Check symbols cache
        if (d_symbols_cache.valid()) {
            auto [found, offset] = d_symbols_cache.addressToFileOffset(addr);
            if (found) {
                return {d_symbols_cache.map, offset};
            }
        }

        return {nullptr, 0};
    }

    // Get the slide (difference between cache address and runtime address)
    uint64_t getSlide(uint64_t runtime_load_addr, const std::string& path) const
    {
        const dyld_cache_image_info* img = findImage(path);
        if (!img) {
            return 0;
        }
        return runtime_load_addr - img->address;
    }

    // Extract unwind sections from an image in the shared cache
    bool extractUnwindSectionsFromImage(const std::string& path, MachOUnwindSections& sections) const
    {
        sections.valid = false;

        const dyld_cache_image_info* img = findImage(path);
        if (!img) {
            LOG(DEBUG) << "Image not found in cache: " << path;
            return false;
        }

        // Get Mach-O header from cache
        auto [hdr_data, hdr_offset] = addressToData(img->address);
        if (!hdr_data) {
            LOG(DEBUG) << "Failed to get Mach-O header for: " << path;
            return false;
        }

        const auto* hdr = reinterpret_cast<const struct mach_header_64*>(
                static_cast<const char*>(hdr_data) + hdr_offset);

        if (hdr->magic != MH_MAGIC_64) {
            LOG(DEBUG) << "Not a 64-bit Mach-O: " << path;
            return false;
        }

        int ncmds = hdr->ncmds;
        const auto* cmd = reinterpret_cast<const struct load_command*>(
                reinterpret_cast<const char*>(hdr) + sizeof(struct mach_header_64));

        sections.text_vmaddr = 0;

        for (int i = 0; i < ncmds; i++) {
            if (cmd->cmd == LC_SEGMENT_64) {
                const auto* seg = reinterpret_cast<const struct segment_command_64*>(cmd);

                if (strcmp(seg->segname, "__TEXT") == 0) {
                    sections.text_vmaddr = seg->vmaddr;

                    int nsects = seg->nsects;
                    const auto* sec = reinterpret_cast<const struct section_64*>(
                            reinterpret_cast<const char*>(seg) + sizeof(struct segment_command_64));

                    for (int j = 0; j < nsects; j++) {
                        if (strcmp(sec[j].sectname, "__text") == 0) {
                            sections.text_info.vm_addr = sec[j].addr;
                            sections.text_info.size = sec[j].size;
                        } else if (strcmp(sec[j].sectname, "__unwind_info") == 0) {
                            // For shared cache, section addr is the virtual address
                            auto [data, offset] = addressToData(sec[j].addr);
                            if (data) {
                                const uint8_t* sect_data =
                                        static_cast<const uint8_t*>(data) + offset;
                                sections.unwind_info.assign(sect_data, sect_data + sec[j].size);
                            }
                        } else if (strcmp(sec[j].sectname, "__eh_frame") == 0) {
                            auto [data, offset] = addressToData(sec[j].addr);
                            if (data) {
                                const uint8_t* sect_data =
                                        static_cast<const uint8_t*>(data) + offset;
                                sections.eh_frame.assign(sect_data, sect_data + sec[j].size);
                            }
                        }
                    }
                }
            }

            cmd = reinterpret_cast<const struct load_command*>(
                    reinterpret_cast<const char*>(cmd) + cmd->cmdsize);
        }

        sections.valid = true;
        LOG(DEBUG) << "Extracted unwind sections from shared cache for: " << path
                   << " text_vmaddr=" << std::hex << sections.text_vmaddr
                   << " unwind_info_size=" << std::dec << sections.unwind_info.size()
                   << " eh_frame_size=" << sections.eh_frame.size();
        return true;
    }

    bool valid() const
    {
        return d_main_cache.valid() && d_header != nullptr;
    }

  private:
    CacheFile d_main_cache;
    std::vector<std::unique_ptr<CacheFile>> d_subcaches;
    CacheFile d_symbols_cache;
    const dyld_cache_header* d_header = nullptr;
    const dyld_cache_image_info* d_images = nullptr;
};

// Global shared cache instance (loaded once, used for all symbol lookups)
static std::unique_ptr<DyldSharedCache> g_shared_cache;
static bool g_shared_cache_loaded = false;

static DyldSharedCache*
getSharedCache()
{
    if (!g_shared_cache_loaded) {
        g_shared_cache_loaded = true;
        g_shared_cache = std::make_unique<DyldSharedCache>();
        if (!g_shared_cache->load()) {
            g_shared_cache.reset();
        }
    }
    return g_shared_cache.get();
}

// Get the host CPU type for fat binary selection
static bool
getHostCpuType(cpu_type_t* cpu)
{
    int is_abi64;
    size_t cpu_size = sizeof(*cpu);
    size_t abi64_size = sizeof(is_abi64);

    if (sysctlbyname("hw.cputype", cpu, &cpu_size, nullptr, 0) != 0) {
        return false;
    }
    if (sysctlbyname("hw.cpu64bit_capable", &is_abi64, &abi64_size, nullptr, 0) != 0) {
        return false;
    }

    *cpu |= is_abi64 * CPU_ARCH_ABI64;
    return true;
}

// Helper to extract sections from a 64-bit Mach-O binary
static bool
extractSections64(
        void* map,
        size_t file_size,
        MachOUnwindSections& sections,
        uint64_t base_offset = 0)
{
    auto* hdr = reinterpret_cast<struct mach_header_64*>(static_cast<char*>(map) + base_offset);

    if (base_offset + sizeof(struct mach_header_64) > file_size) {
        return false;
    }

    int ncmds = hdr->ncmds;
    auto* cmd = reinterpret_cast<struct load_command*>(
            static_cast<char*>(map) + base_offset + sizeof(struct mach_header_64));

    sections.valid = false;
    sections.text_vmaddr = 0;

    for (int i = 0; i < ncmds; i++) {
        if (reinterpret_cast<char*>(cmd) + sizeof(struct load_command)
            > static_cast<char*>(map) + file_size)
        {
            break;
        }

        if (cmd->cmd == LC_SEGMENT_64) {
            auto* seg = reinterpret_cast<struct segment_command_64*>(cmd);

            if (strcmp(seg->segname, "__TEXT") == 0) {
                sections.text_vmaddr = seg->vmaddr;

                // Find __text, __unwind_info sections in __TEXT segment
                int nsects = seg->nsects;
                auto* sec = reinterpret_cast<struct section_64*>(
                        reinterpret_cast<char*>(seg) + sizeof(struct segment_command_64));

                for (int j = 0; j < nsects; j++) {
                    if (strcmp(sec[j].sectname, "__text") == 0) {
                        sections.text_info.vm_addr = sec[j].addr;
                        sections.text_info.size = sec[j].size;
                    } else if (strcmp(sec[j].sectname, "__unwind_info") == 0) {
                        if (base_offset + sec[j].offset + sec[j].size <= file_size) {
                            const uint8_t* data = reinterpret_cast<const uint8_t*>(
                                    static_cast<char*>(map) + base_offset + sec[j].offset);
                            sections.unwind_info.assign(data, data + sec[j].size);
                        }
                    } else if (strcmp(sec[j].sectname, "__eh_frame") == 0) {
                        if (base_offset + sec[j].offset + sec[j].size <= file_size) {
                            const uint8_t* data = reinterpret_cast<const uint8_t*>(
                                    static_cast<char*>(map) + base_offset + sec[j].offset);
                            sections.eh_frame.assign(data, data + sec[j].size);
                        }
                    }
                }
            }
        }

        cmd = reinterpret_cast<struct load_command*>(reinterpret_cast<char*>(cmd) + cmd->cmdsize);
    }

    sections.valid = (sections.text_vmaddr != 0);
    return sections.valid;
}

// Helper to extract sections from a fat binary
static bool
extractSectionsFat(void* map, size_t file_size, MachOUnwindSections& sections)
{
    auto* fat_hdr = reinterpret_cast<struct fat_header*>(map);

    cpu_type_t cpu;
    if (!getHostCpuType(&cpu)) {
        LOG(WARNING) << "Failed to determine CPU type for fat binary analysis";
        return false;
    }

    int swap = fat_hdr->magic == FAT_CIGAM;
    auto* arch =
            reinterpret_cast<struct fat_arch*>(static_cast<char*>(map) + sizeof(struct fat_header));

    uint32_t nfat_arch = swap ? __builtin_bswap32(fat_hdr->nfat_arch) : fat_hdr->nfat_arch;

    for (uint32_t i = 0; i < nfat_arch; i++) {
        cpu_type_t arch_cpu = swap ? __builtin_bswap32(arch[i].cputype) : arch[i].cputype;

        if (arch_cpu == cpu) {
            uint32_t offset = swap ? __builtin_bswap32(arch[i].offset) : arch[i].offset;
            uint32_t size = swap ? __builtin_bswap32(arch[i].size) : arch[i].size;

            if (offset + size > file_size) {
                return false;
            }

            auto* inner_hdr =
                    reinterpret_cast<struct mach_header_64*>(static_cast<char*>(map) + offset);

            if (inner_hdr->magic == MH_MAGIC_64 || inner_hdr->magic == MH_CIGAM_64) {
                return extractSections64(map, file_size, sections, offset);
            }
        }
    }

    return false;
}

// Find symbol in 64-bit Mach-O binary
static std::string
findSymbolInMachO64(void* map, size_t file_size, uint64_t addr, uint64_t /* base_svma */, uint64_t base_offset = 0)
{
    auto* hdr = reinterpret_cast<struct mach_header_64*>(static_cast<char*>(map) + base_offset);
    int ncmds = hdr->ncmds;

    auto* cmd = reinterpret_cast<struct load_command*>(
            static_cast<char*>(map) + base_offset + sizeof(struct mach_header_64));

    struct symtab_command* symtab = nullptr;

    // Find symtab command
    for (int i = 0; i < ncmds; i++) {
        if (cmd->cmd == LC_SYMTAB) {
            symtab = reinterpret_cast<struct symtab_command*>(cmd);
            break;
        }
        cmd = reinterpret_cast<struct load_command*>(reinterpret_cast<char*>(cmd) + cmd->cmdsize);
    }

    if (!symtab) {
        return "???";
    }

    // Validate offsets
    if (base_offset + symtab->symoff + symtab->nsyms * sizeof(struct nlist_64) > file_size) {
        return "???";
    }
    if (base_offset + symtab->stroff >= file_size) {
        return "???";
    }

    auto* symbols = reinterpret_cast<struct nlist_64*>(
            static_cast<char*>(map) + base_offset + symtab->symoff);
    const char* strtab = static_cast<char*>(map) + base_offset + symtab->stroff;
    size_t strtab_size = file_size - base_offset - symtab->stroff;

    // addr is already in the file's virtual address space (file_addr from caller)
    // Compare directly to symbol n_value which is also in file's virtual address space
    uint64_t target = addr;

    // Find the best matching symbol (closest symbol at or before the address)
    const char* best_name = nullptr;
    uint64_t best_addr = 0;

    for (uint32_t i = 0; i < symtab->nsyms; i++) {
        // Skip undefined and debug symbols
        if ((symbols[i].n_type & N_TYPE) == N_UNDF) {
            continue;
        }
        if (symbols[i].n_type & N_STAB) {
            continue;
        }

        uint32_t strx = symbols[i].n_un.n_strx;
        if (strx >= strtab_size) {
            continue;
        }

        uint64_t sym_addr = symbols[i].n_value;

        // Check if this symbol is at or before our target and closer than the current best
        if (sym_addr <= target && sym_addr > best_addr) {
            best_addr = sym_addr;
            best_name = strtab + strx;
        }
    }

    if (best_name && best_name[0] != '\0') {
        // Remove leading underscore if present (Mach-O convention)
        if (best_name[0] == '_') {
            best_name++;
        }
        return std::string(best_name);
    }

    return "???";
}

// Find symbol in fat binary
static std::string
findSymbolInFat(void* map, size_t file_size, uint64_t addr, uint64_t base_svma)
{
    auto* fat_hdr = reinterpret_cast<struct fat_header*>(map);

    cpu_type_t cpu;
    if (!getHostCpuType(&cpu)) {
        return "???";
    }

    int swap = fat_hdr->magic == FAT_CIGAM;
    auto* arch =
            reinterpret_cast<struct fat_arch*>(static_cast<char*>(map) + sizeof(struct fat_header));

    uint32_t nfat_arch = swap ? __builtin_bswap32(fat_hdr->nfat_arch) : fat_hdr->nfat_arch;

    for (uint32_t i = 0; i < nfat_arch; i++) {
        cpu_type_t arch_cpu = swap ? __builtin_bswap32(arch[i].cputype) : arch[i].cputype;

        if (arch_cpu == cpu) {
            uint32_t offset = swap ? __builtin_bswap32(arch[i].offset) : arch[i].offset;
            uint32_t size = swap ? __builtin_bswap32(arch[i].size) : arch[i].size;

            if (offset + size > file_size) {
                return "???";
            }

            auto* inner_hdr =
                    reinterpret_cast<struct mach_header_64*>(static_cast<char*>(map) + offset);

            if (inner_hdr->magic == MH_MAGIC_64 || inner_hdr->magic == MH_CIGAM_64) {
                return findSymbolInMachO64(map, file_size, addr, base_svma, offset);
            }
        }
    }

    return "???";
}

}  // anonymous namespace

MacOSUnwinder::MacOSUnwinder(mach_port_t task, const std::vector<VirtualMap>& maps)
: d_task(task)
, d_maps(maps)
, d_unwinder(nullptr)
, d_cache(nullptr)
, d_modules_loaded(false)
{
    d_unwinder = framehop_unwinder_new();
    d_cache = framehop_cache_new();

    if (!d_unwinder || !d_cache) {
        LOG(ERROR) << "Failed to create framehop unwinder or cache";
        if (d_unwinder) {
            framehop_unwinder_free(d_unwinder);
            d_unwinder = nullptr;
        }
        if (d_cache) {
            framehop_cache_free(d_cache);
            d_cache = nullptr;
        }
    }

    // Load dyld images for direct address-to-library mapping
    loadDyldImages();
}

MacOSUnwinder::~MacOSUnwinder()
{
    if (d_unwinder) {
        framehop_unwinder_free(d_unwinder);
    }
    if (d_cache) {
        framehop_cache_free(d_cache);
    }

    // Deallocate cached thread ports
    for (auto& [tid, port] : d_thread_ports) {
        if (port != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), port);
        }
    }
}

bool
MacOSUnwinder::readMemory(uint64_t addr, uint64_t* value) const
{
    mach_vm_size_t size = sizeof(uint64_t);
    mach_vm_size_t read_size = 0;

    kern_return_t kr =
            mach_vm_read_overwrite(d_task, addr, size, reinterpret_cast<mach_vm_address_t>(value), &read_size);

    return kr == KERN_SUCCESS && read_size == size;
}

bool
MacOSUnwinder::getThreadRegisters(
        thread_act_t thread,
        uint64_t& pc,
        uint64_t& lr,
        uint64_t& sp,
        uint64_t& fp) const
{
#if defined(__arm64__) || defined(__aarch64__)
    arm_thread_state64_t state;
    mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;

    kern_return_t kr = thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t)&state, &count);

    if (kr != KERN_SUCCESS) {
        LOG(ERROR) << "thread_get_state failed: " << mach_error_string(kr);
        return false;
    }

    // Use the ARM64 accessors that handle pointer authentication
    pc = arm_thread_state64_get_pc(state);
    lr = arm_thread_state64_get_lr(state);
    sp = arm_thread_state64_get_sp(state);
    fp = arm_thread_state64_get_fp(state);

    return true;
#else
    (void)thread;
    (void)pc;
    (void)lr;
    (void)sp;
    (void)fp;
    LOG(ERROR) << "Native unwinding not supported on this architecture";
    return false;
#endif
}

MachOUnwindSections
MacOSUnwinder::extractUnwindSections(const std::string& path) const
{
    // Check cache first
    auto it = d_unwind_cache.find(path);
    if (it != d_unwind_cache.end()) {
        return it->second;
    }

    MachOUnwindSections sections;
    sections.valid = false;

    int fd = open(path.c_str(), O_RDONLY);
    if (fd == -1) {
        LOG(DEBUG) << "Cannot open binary file for unwind section extraction: " << path;
        d_unwind_cache[path] = sections;
        return sections;
    }

    struct stat fs;
    if (fstat(fd, &fs) == -1) {
        close(fd);
        d_unwind_cache[path] = sections;
        return sections;
    }

    void* map = mmap(nullptr, fs.st_size, PROT_READ, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        close(fd);
        d_unwind_cache[path] = sections;
        return sections;
    }

    uint32_t magic = *reinterpret_cast<uint32_t*>(map);

    switch (magic) {
        case MH_MAGIC_64:
        case MH_CIGAM_64:
            extractSections64(map, fs.st_size, sections);
            break;
        case FAT_MAGIC:
        case FAT_CIGAM:
            extractSectionsFat(map, fs.st_size, sections);
            break;
        default:
            LOG(DEBUG) << "Unrecognized Mach-O magic number: " << std::hex << magic;
            break;
    }

    munmap(map, fs.st_size);
    close(fd);

    d_unwind_cache[path] = sections;
    return sections;
}

std::string
MacOSUnwinder::findSymbol(uint64_t addr) const
{
    // Helper lambda to look up symbol from dyld shared cache
    // This follows samply's algorithm: load cache, find image, translate address, extract symbol
    auto lookupSymbolFromCache =
            [this](const std::string& path, uint64_t runtime_load_addr, uint64_t addr) -> std::string {
        DyldSharedCache* cache = getSharedCache();
        if (!cache || !cache->valid()) {
            return "???";
        }

        // Step 7: Find image in cache by path
        const dyld_cache_image_info* img = cache->findImage(path);
        if (!img) {
            return "???";
        }

        // Step 8: Calculate slide (runtime - cache address)
        uint64_t slide = runtime_load_addr - img->address;

        // Convert runtime address to cache address
        uint64_t cache_addr = addr - slide;

        // Step 8 continued: Use mappings to find file data
        auto [data, offset] = cache->addressToData(cache_addr);
        if (!data) {
            return "???";
        }

        // Step 9: Parse Mach-O at image address
        auto [hdr_data, hdr_offset] = cache->addressToData(img->address);
        if (!hdr_data) {
            return "???";
        }

        const auto* hdr = reinterpret_cast<const struct mach_header_64*>(
                static_cast<const char*>(hdr_data) + hdr_offset);

        if (hdr->magic != MH_MAGIC_64) {
            return "???";
        }

        // Find symtab and linkedit info
        const auto* cmd = reinterpret_cast<const struct load_command*>(
                reinterpret_cast<const char*>(hdr) + sizeof(struct mach_header_64));

        const struct symtab_command* symtab_cmd = nullptr;
        uint64_t linkedit_vmaddr = 0;
        uint64_t linkedit_fileoff = 0;

        for (uint32_t i = 0; i < hdr->ncmds; i++) {
            if (cmd->cmd == LC_SYMTAB) {
                symtab_cmd = reinterpret_cast<const struct symtab_command*>(cmd);
            } else if (cmd->cmd == LC_SEGMENT_64) {
                const auto* seg = reinterpret_cast<const struct segment_command_64*>(cmd);
                if (strncmp(seg->segname, "__LINKEDIT", 16) == 0) {
                    linkedit_vmaddr = seg->vmaddr;
                    linkedit_fileoff = seg->fileoff;
                }
            }
            cmd = reinterpret_cast<const struct load_command*>(
                    reinterpret_cast<const char*>(cmd) + cmd->cmdsize);
        }

        if (!symtab_cmd || linkedit_vmaddr == 0) {
            return "???";
        }

        // Step 10: Extract symbols from LC_SYMTAB
        // Symbol table is at linkedit_vmaddr + (symoff - linkedit_fileoff)
        uint64_t symtab_cache_addr = linkedit_vmaddr + (symtab_cmd->symoff - linkedit_fileoff);
        uint64_t strtab_cache_addr = linkedit_vmaddr + (symtab_cmd->stroff - linkedit_fileoff);

        auto [symtab_data, symtab_off] = cache->addressToData(symtab_cache_addr);
        auto [strtab_data, strtab_off] = cache->addressToData(strtab_cache_addr);

        if (!symtab_data || !strtab_data) {
            return "???";
        }

        const auto* symbols = reinterpret_cast<const struct nlist_64*>(
                static_cast<const char*>(symtab_data) + symtab_off);
        const char* strtab = static_cast<const char*>(strtab_data) + strtab_off;

        // Step 11: Binary search for address
        // Find the best matching symbol (closest symbol at or before cache_addr)
        const char* best_name = nullptr;
        uint64_t best_addr = 0;

        for (uint32_t i = 0; i < symtab_cmd->nsyms; i++) {
            // Skip undefined and debug symbols
            if ((symbols[i].n_type & N_TYPE) == N_UNDF) {
                continue;
            }
            if (symbols[i].n_type & N_STAB) {
                continue;
            }

            uint64_t sym_addr = symbols[i].n_value;

            // Check if this symbol is at or before our target and closer than the current best
            if (sym_addr <= cache_addr && sym_addr > best_addr) {
                best_addr = sym_addr;
                best_name = strtab + symbols[i].n_un.n_strx;
            }
        }

        if (best_name && best_name[0] != '\0') {
            // Remove leading underscore if present (Mach-O convention)
            if (best_name[0] == '_') {
                best_name++;
            }
            return demangleSymbol(std::string(best_name));
        }

        return "???";
    };

    // Helper lambda to look up symbol from a file on disk (for non-shared-cache libraries)
    auto lookupSymbolFromFile =
            [this](const std::string& path, uint64_t load_addr, uint64_t addr) -> std::string {
        if (path.empty()) {
            return "???";
        }

        // Open and parse the Mach-O file
        int fd = open(path.c_str(), O_RDONLY);
        if (fd == -1) {
            return "???";
        }

        struct stat fs;
        if (fstat(fd, &fs) == -1) {
            close(fd);
            return "???";
        }

        void* file_map = mmap(nullptr, fs.st_size, PROT_READ, MAP_SHARED, fd, 0);
        if (file_map == MAP_FAILED) {
            close(fd);
            return "???";
        }

        // Get the base SVMA from cached sections
        auto sections = extractUnwindSections(path);
        uint64_t base_svma = sections.valid ? sections.text_vmaddr : 0;

        // Compute the file-relative address
        uint64_t file_addr = addr - load_addr + base_svma;

        uint32_t magic = *reinterpret_cast<uint32_t*>(file_map);
        std::string symbol;

        switch (magic) {
            case MH_MAGIC_64:
            case MH_CIGAM_64:
                symbol = findSymbolInMachO64(file_map, fs.st_size, file_addr, base_svma);
                break;
            case FAT_MAGIC:
            case FAT_CIGAM:
                symbol = findSymbolInFat(file_map, fs.st_size, file_addr, base_svma);
                break;
            default:
                symbol = "???";
                break;
        }

        munmap(file_map, fs.st_size);
        close(fd);

        return demangleSymbol(symbol);
    };

    // First try using dyld images (for direct address-to-library mapping)
    if (!d_dyld_images.empty()) {
        auto it = std::upper_bound(
                d_dyld_images.begin(),
                d_dyld_images.end(),
                addr,
                [](uint64_t a, const DyldImageInfo& img) { return a < img.load_address; });

        if (it != d_dyld_images.begin()) {
            --it;
            if (addr >= it->load_address && addr < it->end_address) {
                // Step 4: Check if path starts with /usr/ or /System/ → use dyld_shared_cache
                if (it->path.find("/usr/") == 0 || it->path.find("/System/") == 0) {
                    std::string sym = lookupSymbolFromCache(it->path, it->load_address, addr);
                    if (sym != "???") {
                        return sym;
                    }
                }
                // For other libraries (or if cache lookup failed), try file on disk
                return lookupSymbolFromFile(it->path, it->load_address, addr);
            }
        }
    }

    // Fallback to VirtualMaps
    for (const auto& map : d_maps) {
        if (addr >= map.Start() && addr < map.End()) {
            return lookupSymbolFromFile(map.Path(), map.Start(), addr);
        }
    }

    return "???";
}

std::string
MacOSUnwinder::findLibrary(uint64_t addr) const
{
    // Use dyld images for direct address-to-library mapping (like samply does)
    if (!d_dyld_images.empty()) {
        // Binary search to find the last image with load_address <= addr
        auto it = std::upper_bound(
                d_dyld_images.begin(),
                d_dyld_images.end(),
                addr,
                [](uint64_t a, const DyldImageInfo& img) { return a < img.load_address; });

        if (it != d_dyld_images.begin()) {
            --it;
            if (addr >= it->load_address && addr < it->end_address) {
                const std::string& path = it->path;
                if (!path.empty()) {
                    // Extract just the filename
                    size_t pos = path.rfind('/');
                    if (pos != std::string::npos) {
                        return path.substr(pos + 1);
                    }
                    return path;
                }
            }
        }
    }

    // Fallback to VirtualMaps
    for (const auto& map : d_maps) {
        if (addr >= map.Start() && addr < map.End()) {
            const std::string& path = map.Path();
            if (path.empty()) {
                return "???";
            }
            // Extract just the filename
            size_t pos = path.rfind('/');
            if (pos != std::string::npos) {
                return path.substr(pos + 1);
            }
            return path;
        }
    }
    return "???";
}

std::string
MacOSUnwinder::demangleSymbol(const std::string& symbol)
{
    if (symbol.empty() || symbol == "???") {
        return symbol;
    }

    // Try C++ demangling (requires _Z prefix)
    if (symbol.size() >= 2 && symbol[0] == '_' && symbol[1] == 'Z') {
        int status = -1;
        char* demangled = abi::__cxa_demangle(symbol.c_str(), nullptr, nullptr, &status);
        if (status == 0 && demangled) {
            std::string result(demangled);
            free(demangled);
            return result;
        }
    }

    return symbol;
}

/// Extract unwind sections by reading Mach-O headers from the target process memory
/// This is how samply does it - works for all libraries including shared cache ones
MachOUnwindSections
MacOSUnwinder::extractUnwindSectionsFromProcess(uint64_t base_avma) const
{
    MachOUnwindSections sections;
    sections.valid = false;

    // Read the Mach-O header from target process
    struct mach_header_64 header;
    mach_vm_size_t read_size = 0;
    kern_return_t kr = mach_vm_read_overwrite(
            d_task,
            base_avma,
            sizeof(header),
            reinterpret_cast<mach_vm_address_t>(&header),
            &read_size);

    if (kr != KERN_SUCCESS || read_size != sizeof(header) || header.magic != MH_MAGIC_64) {
        return sections;
    }

    // Read load commands
    size_t cmds_size = header.sizeofcmds;
    std::vector<uint8_t> cmds_buf(cmds_size);
    kr = mach_vm_read_overwrite(
            d_task,
            base_avma + sizeof(header),
            cmds_size,
            reinterpret_cast<mach_vm_address_t>(cmds_buf.data()),
            &read_size);

    if (kr != KERN_SUCCESS || read_size != cmds_size) {
        return sections;
    }

    // Parse load commands to find __TEXT segment and sections
    uint64_t base_svma = 0;
    uint64_t unwind_info_svma = 0, unwind_info_size = 0;
    uint64_t eh_frame_svma = 0, eh_frame_size = 0;
    uint64_t text_svma = 0, text_size = 0;

    auto* cmd = reinterpret_cast<struct load_command*>(cmds_buf.data());
    for (uint32_t i = 0; i < header.ncmds; i++) {
        if (cmd->cmd == LC_SEGMENT_64) {
            auto* seg = reinterpret_cast<struct segment_command_64*>(cmd);
            if (strcmp(seg->segname, "__TEXT") == 0) {
                base_svma = seg->vmaddr;

                // Iterate sections in __TEXT
                auto* sec = reinterpret_cast<struct section_64*>(
                        reinterpret_cast<char*>(seg) + sizeof(struct segment_command_64));
                for (uint32_t j = 0; j < seg->nsects; j++) {
                    if (strcmp(sec[j].sectname, "__text") == 0) {
                        text_svma = sec[j].addr;
                        text_size = sec[j].size;
                    } else if (strcmp(sec[j].sectname, "__unwind_info") == 0) {
                        unwind_info_svma = sec[j].addr;
                        unwind_info_size = sec[j].size;
                    } else if (strcmp(sec[j].sectname, "__eh_frame") == 0) {
                        eh_frame_svma = sec[j].addr;
                        eh_frame_size = sec[j].size;
                    }
                }
            }
        }
        cmd = reinterpret_cast<struct load_command*>(reinterpret_cast<char*>(cmd) + cmd->cmdsize);
    }

    sections.text_vmaddr = base_svma;
    sections.text_info.vm_addr = text_svma;
    sections.text_info.size = text_size;

    // Read unwind_info section data from target process
    if (unwind_info_size > 0) {
        uint64_t unwind_info_avma = unwind_info_svma - base_svma + base_avma;
        sections.unwind_info.resize(unwind_info_size);
        kr = mach_vm_read_overwrite(
                d_task,
                unwind_info_avma,
                unwind_info_size,
                reinterpret_cast<mach_vm_address_t>(sections.unwind_info.data()),
                &read_size);
        if (kr != KERN_SUCCESS || read_size != unwind_info_size) {
            sections.unwind_info.clear();
        }
    }

    // Read eh_frame section data from target process
    if (eh_frame_size > 0) {
        uint64_t eh_frame_avma = eh_frame_svma - base_svma + base_avma;
        sections.eh_frame.resize(eh_frame_size);
        kr = mach_vm_read_overwrite(
                d_task,
                eh_frame_avma,
                eh_frame_size,
                reinterpret_cast<mach_vm_address_t>(sections.eh_frame.data()),
                &read_size);
        if (kr != KERN_SUCCESS || read_size != eh_frame_size) {
            sections.eh_frame.clear();
        }
    }

    sections.valid = true;
    return sections;
}

void
MacOSUnwinder::loadModules()
{
    if (d_modules_loaded || !d_unwinder) {
        return;
    }

    // Use dyld images (like samply does) - this works for shared cache libraries
    for (const auto& img : d_dyld_images) {
        // Read unwind sections from target process memory
        auto sections = extractUnwindSectionsFromProcess(img.load_address);
        if (!sections.valid) {
            LOG(DEBUG) << "Failed to extract unwind sections from process for: " << img.path;
            continue;
        }

        FramehopModule module = {};
        module.base_avma = img.load_address;
        module.end_avma = img.end_address;
        module.base_svma = sections.text_vmaddr;

        if (!sections.unwind_info.empty()) {
            module.unwind_info = sections.unwind_info.data();
            module.unwind_info_len = sections.unwind_info.size();
        }

        if (!sections.eh_frame.empty()) {
            module.eh_frame = sections.eh_frame.data();
            module.eh_frame_len = sections.eh_frame.size();
        }

        module.text_svma = sections.text_info.vm_addr;
        module.text_svma_end = sections.text_info.vm_addr + sections.text_info.size;
        module.text_len = sections.text_info.size;
        module.text_data = nullptr;  // We don't have text data, will use fp unwinding

        framehop_add_module(d_unwinder, &module);

        // Cache the sections so they stay alive while the module is registered
        d_unwind_cache[img.path] = std::move(sections);

        LOG(DEBUG) << "Loaded module from process memory: " << img.path
                   << " base_avma=" << std::hex << img.load_address << " end_avma=" << img.end_address
                   << " base_svma=" << d_unwind_cache[img.path].text_vmaddr;
    }

    d_modules_loaded = true;
}

thread_act_t
MacOSUnwinder::getThreadPort(int tid) const
{
    // Check cache
    auto it = d_thread_ports.find(tid);
    if (it != d_thread_ports.end()) {
        return it->second;
    }

    // Get all threads and find the matching one
    thread_act_array_t threads;
    mach_msg_type_number_t thread_count;
    kern_return_t kr = task_threads(d_task, &threads, &thread_count);
    if (kr != KERN_SUCCESS) {
        return MACH_PORT_NULL;
    }

    thread_act_t result = MACH_PORT_NULL;
    for (mach_msg_type_number_t i = 0; i < thread_count; i++) {
        thread_identifier_info_data_t thread_id_info;
        mach_msg_type_number_t info_count = THREAD_IDENTIFIER_INFO_COUNT;
        kr = thread_info(threads[i], THREAD_IDENTIFIER_INFO, (thread_info_t)&thread_id_info, &info_count);

        int thread_tid = (kr == KERN_SUCCESS) ? static_cast<int>(thread_id_info.thread_id)
                                              : static_cast<int>(threads[i]);

        if (thread_tid == tid) {
            result = threads[i];
            d_thread_ports[tid] = result;  // Cache it
        } else {
            mach_port_deallocate(mach_task_self(), threads[i]);
        }
    }

    vm_deallocate(mach_task_self(), (vm_address_t)threads, thread_count * sizeof(thread_act_t));

    return result;
}

// Memory read callback for framehop - defined outside the class
static int
readStackCallback(uint64_t addr, uint64_t* out, void* ctx)
{
    auto* unwinder = static_cast<MacOSUnwinder*>(ctx);
    return unwinder->readMemory(addr, out) ? 0 : -1;
}

std::vector<NativeFrame>
MacOSUnwinder::unwindThread(thread_act_t thread)
{
    std::vector<NativeFrame> frames;

    if (!d_unwinder || !d_cache) {
        LOG(ERROR) << "Unwinder not initialized";
        return frames;
    }

    // Load modules if not already done
    loadModules();

    // Get thread registers
    uint64_t pc, lr, sp, fp;
    if (!getThreadRegisters(thread, pc, lr, sp, fp)) {
        LOG(ERROR) << "Failed to get thread registers";
        return frames;
    }

    LOG(DEBUG) << "Thread registers: pc=" << std::hex << pc << " lr=" << lr << " sp=" << sp
               << " fp=" << fp;

    // Prepare registers for framehop
    FramehopRegs regs;
    regs.pc = pc;
    regs.lr = lr;
    regs.sp = sp;
    regs.fp = fp;

    // Allocate space for frame addresses
    constexpr size_t MAX_FRAMES = 256;
    std::vector<uint64_t> frame_addrs(MAX_FRAMES);

    // Unwind
    size_t frame_count = framehop_unwind(
            d_unwinder,
            d_cache,
            &regs,
            reinterpret_cast<FramehopReadStackFn>(readStackCallback),
            const_cast<MacOSUnwinder*>(this),
            frame_addrs.data(),
            MAX_FRAMES);

    LOG(DEBUG) << "Unwound " << frame_count << " frames";

    // Convert addresses to NativeFrame objects
    frames.reserve(frame_count);
    for (size_t i = 0; i < frame_count; i++) {
        uint64_t addr = frame_addrs[i];
        NativeFrame frame;
        frame.address = addr;
        frame.symbol = findSymbol(addr);
        frame.path = "???";  // Path to source file (not available without DWARF)
        frame.linenumber = 0;
        frame.colnumber = 0;
        frame.library = findLibrary(addr);

        frames.push_back(std::move(frame));
    }

    return frames;
}

void
MacOSUnwinder::loadDyldImages()
{
    // Get dyld_all_image_infos address using task_info
    struct task_dyld_info dyld_info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    kern_return_t kr = task_info(d_task, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count);
    if (kr != KERN_SUCCESS) {
        LOG(DEBUG) << "task_info(TASK_DYLD_INFO) failed: " << mach_error_string(kr);
        return;
    }

    if (dyld_info.all_image_info_addr == 0) {
        LOG(DEBUG) << "dyld_all_image_infos address is null";
        return;
    }

    // Read dyld_all_image_infos structure from the target process
    struct dyld_all_image_infos all_image_infos;
    mach_vm_size_t read_size = 0;
    kr = mach_vm_read_overwrite(
            d_task,
            dyld_info.all_image_info_addr,
            sizeof(all_image_infos),
            (mach_vm_address_t)&all_image_infos,
            &read_size);
    if (kr != KERN_SUCCESS || read_size != sizeof(all_image_infos)) {
        LOG(DEBUG) << "Failed to read dyld_all_image_infos: " << mach_error_string(kr);
        return;
    }

    // Helper lambda to read a single image info
    auto readImageInfo = [this](uint64_t load_addr, uint64_t path_addr) -> DyldImageInfo {
        DyldImageInfo info;
        info.load_address = load_addr;
        info.end_address = load_addr;

        // Read the Mach-O header to get __TEXT vmsize
        struct mach_header_64 header;
        mach_vm_size_t read_size = 0;
        kern_return_t kr = mach_vm_read_overwrite(
                d_task,
                load_addr,
                sizeof(header),
                (mach_vm_address_t)&header,
                &read_size);
        if (kr == KERN_SUCCESS && read_size == sizeof(header) && header.magic == MH_MAGIC_64) {
            // Read load commands to find __TEXT segment
            std::vector<uint8_t> load_commands(header.sizeofcmds);
            kr = mach_vm_read_overwrite(
                    d_task,
                    load_addr + sizeof(header),
                    header.sizeofcmds,
                    (mach_vm_address_t)load_commands.data(),
                    &read_size);
            if (kr == KERN_SUCCESS && read_size == header.sizeofcmds) {
                uint32_t offset = 0;
                for (uint32_t i = 0; i < header.ncmds && offset < header.sizeofcmds; i++) {
                    auto* cmd = (struct load_command*)(load_commands.data() + offset);
                    if (cmd->cmd == LC_SEGMENT_64) {
                        auto* seg = (struct segment_command_64*)cmd;
                        if (strncmp(seg->segname, "__TEXT", 16) == 0) {
                            info.end_address = load_addr + seg->vmsize;
                            break;
                        }
                    }
                    offset += cmd->cmdsize;
                }
            }
        }

        // Read the file path
        if (path_addr != 0) {
            char path_buffer[PATH_MAX];
            kr = mach_vm_read_overwrite(
                    d_task,
                    path_addr,
                    sizeof(path_buffer) - 1,
                    (mach_vm_address_t)path_buffer,
                    &read_size);
            if (kr == KERN_SUCCESS && read_size > 0) {
                path_buffer[read_size] = '\0';
                info.path = std::string(path_buffer);
            }
        }

        return info;
    };

    // Add dyld itself FIRST (exactly like samply does)
    if (all_image_infos.dyldImageLoadAddress != nullptr) {
        d_dyld_images.push_back(readImageInfo(
                (uint64_t)all_image_infos.dyldImageLoadAddress,
                (uint64_t)all_image_infos.dyldPath));
    }

    // Read the image info array
    if (all_image_infos.infoArray != nullptr && all_image_infos.infoArrayCount > 0) {
        uint32_t image_count = all_image_infos.infoArrayCount;
        std::vector<struct dyld_image_info> image_infos(image_count);
        kr = mach_vm_read_overwrite(
                d_task,
                (mach_vm_address_t)all_image_infos.infoArray,
                image_count * sizeof(struct dyld_image_info),
                (mach_vm_address_t)image_infos.data(),
                &read_size);
        if (kr == KERN_SUCCESS) {
            for (uint32_t i = 0; i < image_count; i++) {
                d_dyld_images.push_back(readImageInfo(
                        (uint64_t)image_infos[i].imageLoadAddress,
                        (uint64_t)image_infos[i].imageFilePath));
            }
        }
    }

    // Sort by load_address for binary search (exactly like samply does)
    std::sort(d_dyld_images.begin(), d_dyld_images.end(), [](const DyldImageInfo& a, const DyldImageInfo& b) {
        return a.load_address < b.load_address;
    });

    LOG(DEBUG) << "Loaded " << d_dyld_images.size() << " dyld images";
}

}  // namespace pystack

#endif  // PYSTACK_MACOS
