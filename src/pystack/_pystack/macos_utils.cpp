#ifdef PYSTACK_MACOS

#include "macos_utils.h"

#include <cstring>
#include <fcntl.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach/machine.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <unistd.h>

#include "logging.h"

namespace pystack {
namespace macos {

namespace {

// Helper to get CPU type for fat binary selection
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

// Helper to find a section address in a 64-bit Mach-O binary
static uintptr_t
findSectionAddress64(const char* section_name, void* map, uintptr_t base_addr)
{
    struct mach_header_64* hdr = reinterpret_cast<struct mach_header_64*>(map);
    int ncmds = hdr->ncmds;

    struct segment_command_64* cmd =
            reinterpret_cast<struct segment_command_64*>(static_cast<char*>(map)
                                                         + sizeof(struct mach_header_64));

    uintptr_t text_vmaddr = 0;

    for (int i = 0; i < ncmds; i++) {
        if (cmd->cmd == LC_SEGMENT_64 && strcmp(cmd->segname, "__TEXT") == 0) {
            text_vmaddr = cmd->vmaddr;
        }
        if (cmd->cmd == LC_SEGMENT_64 && strcmp(cmd->segname, "__DATA") == 0) {
            int nsects = cmd->nsects;
            struct section_64* sec = reinterpret_cast<struct section_64*>(
                    reinterpret_cast<char*>(cmd) + sizeof(struct segment_command_64));
            for (int j = 0; j < nsects; j++) {
                if (strcmp(sec[j].sectname, section_name) == 0) {
                    return base_addr + sec[j].addr - text_vmaddr;
                }
            }
        }
        cmd = reinterpret_cast<struct segment_command_64*>(reinterpret_cast<char*>(cmd)
                                                           + cmd->cmdsize);
    }

    return 0;
}

// Helper to find a section address in a fat (universal) Mach-O binary
static uintptr_t
findSectionAddressFat(const char* section_name, void* map, uintptr_t base_addr)
{
    struct fat_header* fat_hdr = reinterpret_cast<struct fat_header*>(map);

    cpu_type_t cpu;
    if (!getHostCpuType(&cpu)) {
        LOG(WARNING) << "Failed to determine CPU type for fat binary analysis";
        return 0;
    }

    // Check endianness
    int swap = fat_hdr->magic == FAT_CIGAM;
    struct fat_arch* arch = reinterpret_cast<struct fat_arch*>(static_cast<char*>(map)
                                                               + sizeof(struct fat_header));

    uint32_t nfat_arch = swap ? __builtin_bswap32(fat_hdr->nfat_arch) : fat_hdr->nfat_arch;

    for (uint32_t i = 0; i < nfat_arch; i++) {
        cpu_type_t arch_cpu = swap ? __builtin_bswap32(arch[i].cputype) : arch[i].cputype;

        if (arch_cpu == cpu) {
            uint32_t offset = swap ? __builtin_bswap32(arch[i].offset) : arch[i].offset;
            struct mach_header_64* inner_hdr =
                    reinterpret_cast<struct mach_header_64*>(static_cast<char*>(map) + offset);

            if (inner_hdr->magic == MH_MAGIC_64 || inner_hdr->magic == MH_CIGAM_64) {
                return findSectionAddress64(section_name, inner_hdr, base_addr);
            }
        }
    }

    return 0;
}

// Helper to find a symbol in a 64-bit Mach-O binary
static uintptr_t
findSymbolInMachO64(const char* symbol_name, void* map, size_t file_size, uintptr_t base_addr)
{
    struct mach_header_64* hdr = reinterpret_cast<struct mach_header_64*>(map);
    int ncmds = hdr->ncmds;

    struct load_command* cmd = reinterpret_cast<struct load_command*>(
            static_cast<char*>(map) + sizeof(struct mach_header_64));

    uintptr_t text_vmaddr = 0;
    struct symtab_command* symtab = nullptr;

    // First pass: find __TEXT segment vmaddr and symtab command
    for (int i = 0; i < ncmds; i++) {
        if (cmd->cmd == LC_SEGMENT_64) {
            struct segment_command_64* seg = reinterpret_cast<struct segment_command_64*>(cmd);
            if (strcmp(seg->segname, "__TEXT") == 0) {
                text_vmaddr = seg->vmaddr;
            }
        } else if (cmd->cmd == LC_SYMTAB) {
            symtab = reinterpret_cast<struct symtab_command*>(cmd);
        }
        cmd = reinterpret_cast<struct load_command*>(reinterpret_cast<char*>(cmd) + cmd->cmdsize);
    }

    if (!symtab) {
        LOG(DEBUG) << "No symbol table found in Mach-O binary";
        return 0;
    }

    // Validate symtab offsets are within file bounds
    if (symtab->symoff + symtab->nsyms * sizeof(struct nlist_64) > file_size) {
        LOG(DEBUG) << "Symbol table extends beyond file bounds";
        return 0;
    }
    if (symtab->stroff >= file_size) {
        LOG(DEBUG) << "String table offset beyond file bounds";
        return 0;
    }

    struct nlist_64* symbols =
            reinterpret_cast<struct nlist_64*>(static_cast<char*>(map) + symtab->symoff);
    const char* strtab = static_cast<char*>(map) + symtab->stroff;
    size_t strtab_size = file_size - symtab->stroff;

    // Search for the symbol (with leading underscore as Mach-O convention)
    std::string mangled_name = std::string("_") + symbol_name;

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

        const char* name = strtab + strx;
        if (strcmp(name, mangled_name.c_str()) == 0 || strcmp(name, symbol_name) == 0) {
            // Calculate runtime address
            uintptr_t sym_addr = symbols[i].n_value;
            return base_addr + sym_addr - text_vmaddr;
        }
    }

    return 0;
}

// Helper to find a symbol in a fat (universal) Mach-O binary
static uintptr_t
findSymbolInMachOFat(const char* symbol_name, void* map, size_t file_size, uintptr_t base_addr)
{
    struct fat_header* fat_hdr = reinterpret_cast<struct fat_header*>(map);

    cpu_type_t cpu;
    if (!getHostCpuType(&cpu)) {
        LOG(WARNING) << "Failed to determine CPU type for fat binary symbol lookup";
        return 0;
    }

    int swap = fat_hdr->magic == FAT_CIGAM;
    struct fat_arch* arch = reinterpret_cast<struct fat_arch*>(
            static_cast<char*>(map) + sizeof(struct fat_header));

    uint32_t nfat_arch = swap ? __builtin_bswap32(fat_hdr->nfat_arch) : fat_hdr->nfat_arch;

    for (uint32_t i = 0; i < nfat_arch; i++) {
        cpu_type_t arch_cpu = swap ? __builtin_bswap32(arch[i].cputype) : arch[i].cputype;

        if (arch_cpu == cpu) {
            uint32_t offset = swap ? __builtin_bswap32(arch[i].offset) : arch[i].offset;
            uint32_t size = swap ? __builtin_bswap32(arch[i].size) : arch[i].size;

            if (offset + size > file_size) {
                LOG(DEBUG) << "Fat arch slice extends beyond file bounds";
                return 0;
            }

            struct mach_header_64* inner_hdr =
                    reinterpret_cast<struct mach_header_64*>(static_cast<char*>(map) + offset);

            if (inner_hdr->magic == MH_MAGIC_64 || inner_hdr->magic == MH_CIGAM_64) {
                return findSymbolInMachO64(symbol_name, inner_hdr, size, base_addr);
            }
        }
    }

    return 0;
}

}  // anonymous namespace

uintptr_t
searchMachOFileForSection(const std::string& path, const char* section_name, uintptr_t base_addr)
{
    int fd = open(path.c_str(), O_RDONLY);
    if (fd == -1) {
        LOG(DEBUG) << "Cannot open binary file for section search: " << path;
        return 0;
    }

    struct stat fs;
    if (fstat(fd, &fs) == -1) {
        close(fd);
        LOG(DEBUG) << "Cannot get file size for: " << path;
        return 0;
    }

    void* map = mmap(nullptr, fs.st_size, PROT_READ, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        close(fd);
        LOG(DEBUG) << "Cannot memory map binary file: " << path;
        return 0;
    }

    uintptr_t result = 0;
    uint32_t magic = *reinterpret_cast<uint32_t*>(map);

    switch (magic) {
        case MH_MAGIC_64:
        case MH_CIGAM_64:
            result = findSectionAddress64(section_name, map, base_addr);
            break;
        case FAT_MAGIC:
        case FAT_CIGAM:
            result = findSectionAddressFat(section_name, map, base_addr);
            break;
        default:
            LOG(DEBUG) << "Unrecognized Mach-O magic number: " << std::hex << magic;
            break;
    }

    munmap(map, fs.st_size);
    close(fd);

    return result;
}

uintptr_t
findSymbolInMachO(const std::string& path, const char* symbol_name, uintptr_t base_addr)
{
    int fd = open(path.c_str(), O_RDONLY);
    if (fd == -1) {
        LOG(DEBUG) << "Cannot open binary file for symbol search: " << path;
        return 0;
    }

    struct stat fs;
    if (fstat(fd, &fs) == -1) {
        close(fd);
        LOG(DEBUG) << "Cannot get file size for: " << path;
        return 0;
    }

    void* map = mmap(nullptr, fs.st_size, PROT_READ, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        close(fd);
        LOG(DEBUG) << "Cannot memory map binary file: " << path;
        return 0;
    }

    uintptr_t result = 0;
    uint32_t magic = *reinterpret_cast<uint32_t*>(map);

    switch (magic) {
        case MH_MAGIC_64:
        case MH_CIGAM_64:
            result = findSymbolInMachO64(symbol_name, map, fs.st_size, base_addr);
            break;
        case FAT_MAGIC:
        case FAT_CIGAM:
            result = findSymbolInMachOFat(symbol_name, map, fs.st_size, base_addr);
            break;
        default:
            LOG(DEBUG) << "Unrecognized Mach-O magic number for symbol search: " << std::hex << magic;
            break;
    }

    munmap(map, fs.st_size);
    close(fd);

    return result;
}

}  // namespace macos
}  // namespace pystack

#endif  // PYSTACK_MACOS
