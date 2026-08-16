#include "filesystem.hpp"
#include "fat_filesystem.hpp"
#include "iso9660_filesystem.hpp"
#include "exfat_ntfs_filesystem.hpp"
#include "ext_filesystem.hpp"
#include <cstring>

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

    if (read_bytes >= 512 && std::memcmp(buf + 54, "FAT12", 5) == 0) return "FAT12";
    if (read_bytes >= 512 && std::memcmp(buf + 54, "FAT16", 5) == 0) return "FAT16";
    if (read_bytes >= 512 && std::memcmp(buf + 82, "FAT32", 5) == 0) return "FAT32";
    if (read_bytes >= 512 && std::memcmp(buf + 3, "EXFAT   ", 8) == 0) return "exFAT";
    if (read_bytes >= 512 && std::memcmp(buf + 3, "NTFS    ", 8) == 0) return "NTFS";

    // Ext2/3/4 magic 0xEF53 at offset 1024 + 56
    if (device->GetSize() >= 2048) {
        uint8_t ext_buf[1024];
        if (device->ReadAt(1024, ext_buf, 1024) >= 1024) {
            uint16_t magic = *reinterpret_cast<const uint16_t*>(ext_buf + 56);
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
    if (read_bytes >= 32 && std::memcmp(buf + 32, "NXSB", 4) == 0) return "APFS";

    // HFS+
    if (read_bytes >= 1024 + 2) {
        uint8_t hfs_buf[512];
        if (device->ReadAt(1024, hfs_buf, 512) >= 2) {
            if (std::memcmp(hfs_buf, "H+", 2) == 0 || std::memcmp(hfs_buf, "HX", 2) == 0) return "HFS+";
        }
    }

    return "Raw / Unknown";
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
