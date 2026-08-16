#include "filesystem.hpp"
#include "fat_filesystem.hpp"
#include "iso9660_filesystem.hpp"
#include "exfat_ntfs_filesystem.hpp"
#include "ext_filesystem.hpp"
#include "partition.hpp"
#include <algorithm>
#include <cstring>
#include <limits>

namespace {

uint16_t ReadLe16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
}

uint32_t ReadLe32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

bool IsPowerOfTwo(uint32_t value) {
    return value != 0 && (value & (value - 1)) == 0;
}

bool HasBootSectorSignature(const uint8_t* sector) {
    return sector[510] == 0x55 && sector[511] == 0xAA;
}

bool HasPlausibleFatBpb(const uint8_t* sector, uint64_t device_size, bool fat32) {
    if (!HasBootSectorSignature(sector)) return false;

    const uint32_t bytes_per_sector = ReadLe16(sector + 11);
    if (!(bytes_per_sector == 512 || bytes_per_sector == 1024 || bytes_per_sector == 2048 || bytes_per_sector == 4096)) return false;
    if (device_size < bytes_per_sector) return false;

    const uint32_t sectors_per_cluster = sector[13];
    if (!IsPowerOfTwo(sectors_per_cluster) || sectors_per_cluster > 128) return false;

    const uint16_t reserved_sectors = ReadLe16(sector + 14);
    const uint8_t fat_count = sector[16];
    if (reserved_sectors == 0 || fat_count == 0 || fat_count > 2) return false;

    const uint16_t root_entries = ReadLe16(sector + 17);
    const uint32_t total_sectors = ReadLe16(sector + 19) != 0 ? ReadLe16(sector + 19) : ReadLe32(sector + 32);
    if (total_sectors == 0) return false;
    if (total_sectors > device_size / bytes_per_sector) return false;

    const uint32_t fat_size = fat32 ? ReadLe32(sector + 36) : ReadLe16(sector + 22);
    if (fat_size == 0) return false;
    if (fat32 && root_entries != 0) return false;
    if (!fat32 && root_entries == 0) return false;

    const uint64_t reserved_and_fats = static_cast<uint64_t>(reserved_sectors) + static_cast<uint64_t>(fat_count) * fat_size;
    return reserved_and_fats < total_sectors;
}

bool HasPlausibleExFatBpb(const uint8_t* sector, uint64_t device_size) {
    if (!HasBootSectorSignature(sector)) return false;
    const uint8_t bytes_per_sector_shift = sector[108];
    const uint8_t sectors_per_cluster_shift = sector[109];
    if (bytes_per_sector_shift < 9 || bytes_per_sector_shift > 12) return false;
    if (sectors_per_cluster_shift > 25) return false;
    const uint64_t bytes_per_sector = uint64_t{1} << bytes_per_sector_shift;
    const uint64_t partition_sectors =
        static_cast<uint64_t>(sector[72]) | (static_cast<uint64_t>(sector[73]) << 8) |
        (static_cast<uint64_t>(sector[74]) << 16) | (static_cast<uint64_t>(sector[75]) << 24) |
        (static_cast<uint64_t>(sector[76]) << 32) | (static_cast<uint64_t>(sector[77]) << 40) |
        (static_cast<uint64_t>(sector[78]) << 48) | (static_cast<uint64_t>(sector[79]) << 56);
    return partition_sectors != 0 && partition_sectors <= device_size / bytes_per_sector;
}

bool HasPlausibleNtfsBpb(const uint8_t* sector, uint64_t device_size) {
    if (!HasBootSectorSignature(sector)) return false;
    const uint32_t bytes_per_sector = ReadLe16(sector + 11);
    const uint8_t sectors_per_cluster = sector[13];
    if (!(bytes_per_sector == 512 || bytes_per_sector == 1024 || bytes_per_sector == 2048 || bytes_per_sector == 4096)) return false;
    if (!IsPowerOfTwo(sectors_per_cluster)) return false;
    const uint64_t total_sectors =
        static_cast<uint64_t>(sector[40]) | (static_cast<uint64_t>(sector[41]) << 8) |
        (static_cast<uint64_t>(sector[42]) << 16) | (static_cast<uint64_t>(sector[43]) << 24) |
        (static_cast<uint64_t>(sector[44]) << 32) | (static_cast<uint64_t>(sector[45]) << 40) |
        (static_cast<uint64_t>(sector[46]) << 48) | (static_cast<uint64_t>(sector[47]) << 56);
    return total_sectors != 0 && total_sectors <= device_size / bytes_per_sector;
}

} // namespace

namespace disk_analyzer {

std::shared_ptr<IFileSystem> FileSystemFactory::ProbeAndOpen(std::shared_ptr<IBlockDevice> device) {
    if (!device || !device->IsValid()) {
        return nullptr;
    }

    if (auto fat = FatFileSystem::Open(device)) return fat;
    if (auto exfat = ExFatFileSystem::Open(device)) return exfat;
    if (auto ntfs = NtfsFileSystem::Open(device)) return ntfs;
    if (auto ext = ExtFileSystem::Open(device)) return ext;
    if (auto iso = Iso9660FileSystem::Open(device)) return iso;

    return nullptr;
}

std::string FileSystemFactory::ProbeNameOnly(std::shared_ptr<IBlockDevice> device) {
    if (!device || !device->IsValid() || device->GetSize() < 1024) return "Unknown";

    uint8_t buf[2048];
    size_t read_bytes = device->ReadAt(0, buf, sizeof(buf));

    if (read_bytes >= 512 && std::memcmp(buf + 54, "FAT12", 5) == 0 && HasPlausibleFatBpb(buf, device->GetSize(), false)) return "FAT12";
    if (read_bytes >= 512 && std::memcmp(buf + 54, "FAT16", 5) == 0 && HasPlausibleFatBpb(buf, device->GetSize(), false)) return "FAT16";
    if (read_bytes >= 512 && std::memcmp(buf + 82, "FAT32", 5) == 0 && HasPlausibleFatBpb(buf, device->GetSize(), true)) return "FAT32";
    if (read_bytes >= 512 && std::memcmp(buf + 3, "EXFAT   ", 8) == 0 && HasPlausibleExFatBpb(buf, device->GetSize())) return "exFAT";
    if (read_bytes >= 512 && std::memcmp(buf + 3, "NTFS    ", 8) == 0 && HasPlausibleNtfsBpb(buf, device->GetSize())) return "NTFS";

    // Ext2/3/4 magic 0xEF53 at offset 1024 + 56
    if (device->GetSize() >= 2048) {
        uint8_t ext_buf[1024];
        if (device->ReadAt(1024, ext_buf, 1024) >= 1024) {
            uint16_t magic = ReadLe16(ext_buf + 56);
            if (magic == 0xEF53) return "Ext2/3/4";
        }
    }

    // ISO9660
    if (device->GetSize() >= 16 * 2048 + 6) {
        uint8_t iso_hdr[6];
        if (device->ReadAt(16 * 2048, iso_hdr, 6) >= 6) {
            if (std::memcmp(iso_hdr + 1, "CD001", 5) == 0) return "ISO9660";
        }
    }

    // SquashFS
    if (read_bytes >= 4 && std::memcmp(buf, "hsqs", 4) == 0) return "SquashFS";

    // APFS
    if (read_bytes >= 36 && std::memcmp(buf + 32, "NXSB", 4) == 0) return "APFS";

    // HFS+
    if (read_bytes >= 1024 + 2) {
        uint8_t hfs_buf[512];
        if (device->ReadAt(1024, hfs_buf, 512) >= 2) {
            if (std::memcmp(hfs_buf, "H+", 2) == 0 || std::memcmp(hfs_buf, "HX", 2) == 0) return "HFS+";
        }
    }

    return "Raw / Unknown";
}

std::vector<FilesystemCandidate> FileSystemFactory::ScanFilesystems(std::shared_ptr<IBlockDevice> device) {
    std::vector<FilesystemCandidate> candidates;
    if (!device || !device->IsValid()) {
        return candidates;
    }

    auto add_candidate = [&](uint64_t offset, uint64_t size, const std::string& source, uint32_t confidence) {
        if (offset > device->GetSize()) return;
        uint64_t bounded_size = std::min<uint64_t>(size, device->GetSize() - offset);
        if (bounded_size == 0) return;
        auto subdev = std::make_shared<OffsetBlockDevice>(device, offset, bounded_size, device->GetBlockSize());
        std::string fs_name = ProbeNameOnly(subdev);
        if (fs_name == "Unknown" || fs_name == "Raw / Unknown") return;
        for (const auto& existing : candidates) {
            if (existing.offset == offset && existing.fs_type == fs_name) return;
        }
        candidates.push_back(FilesystemCandidate{offset, bounded_size, fs_name, source, confidence});
    };

    add_candidate(0, device->GetSize(), "whole-device", 70);

    auto parts = PartitionTableParser::Parse(device);
    for (const auto& part : parts) {
        const uint64_t block_size = device->GetBlockSize();
        if (block_size == 0 || part.start_sector > std::numeric_limits<uint64_t>::max() / block_size) {
            continue;
        }
        uint64_t part_offset = part.start_sector * block_size;
        uint64_t part_size = part.size_bytes;
        if (part_offset >= device->GetSize()) continue;
        add_candidate(part_offset, part_size, "partition-" + std::to_string(part.index), 95);
    }

    std::sort(candidates.begin(), candidates.end(), [](const auto& a, const auto& b) {
        if (a.offset != b.offset) return a.offset < b.offset;
        return a.confidence > b.confidence;
    });
    return candidates;
}

FilesystemDiagnostic FileSystemFactory::DiagnoseFilesystem(std::shared_ptr<IBlockDevice> device) {
    FilesystemDiagnostic diag{};
    diag.fs_type = ProbeNameOnly(device);
    if (diag.fs_type != "Unknown" && diag.fs_type != "Raw / Unknown") {
        diag.is_valid_superblock = true;
        diag.is_clean_unmount = true;
        diag.has_corrupted_metadata = false;
        diag.block_size = device->GetBlockSize();
        diag.block_count = device->GetSize() / std::max<uint32_t>(1, diag.block_size);
    }
    return diag;
}

} // namespace disk_analyzer
