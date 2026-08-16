#include "exfat_ntfs_filesystem.hpp"
#include <cstring>

namespace disk_analyzer {

// --- exFAT ---

std::shared_ptr<ExFatFileSystem> ExFatFileSystem::Open(std::shared_ptr<IBlockDevice> device) {
    if (!device || !device->IsValid()) return nullptr;
    auto fs = std::make_shared<ExFatFileSystem>(device);
    if (!fs->IsValid()) return nullptr;
    return fs;
}

ExFatFileSystem::ExFatFileSystem(std::shared_ptr<IBlockDevice> device) : device_(std::move(device)) {
    if (Detect()) {
        is_valid_ = true;
    }
}

bool ExFatFileSystem::Detect() {
    uint8_t boot[512];
    if (device_->ReadAt(0, boot, 512) < 512) return false;

    // exFAT signature "EXFAT   " at byte offset 3
    if (std::memcmp(boot + 3, "EXFAT   ", 8) != 0) return false;

    volume_length_sectors_ = *reinterpret_cast<const uint64_t*>(boot + 72);
    uint8_t sec_shift = boot[108];
    uint8_t spc_shift = boot[109];

    if (sec_shift >= 9 && sec_shift <= 12) {
        bytes_per_sector_ = 1U << sec_shift;
    }
    if (spc_shift <= 25) {
        sectors_per_cluster_ = 1U << spc_shift;
    }

    return true;
}

uint64_t ExFatFileSystem::GetTotalSize() const {
    return volume_length_sectors_ * bytes_per_sector_;
}

bool ExFatFileSystem::ReadDirectory(const std::string& path, std::vector<FileEntry>& out_entries) {
    return is_valid_; // Stubs for discovery
}

size_t ExFatFileSystem::ReadFile(const FileEntry& entry, uint64_t offset, void* buffer, size_t size) {
    return 0;
}

// --- NTFS ---

std::shared_ptr<NtfsFileSystem> NtfsFileSystem::Open(std::shared_ptr<IBlockDevice> device) {
    if (!device || !device->IsValid()) return nullptr;
    auto fs = std::make_shared<NtfsFileSystem>(device);
    if (!fs->IsValid()) return nullptr;
    return fs;
}

NtfsFileSystem::NtfsFileSystem(std::shared_ptr<IBlockDevice> device) : device_(std::move(device)) {
    if (Detect()) {
        is_valid_ = true;
    }
}

bool NtfsFileSystem::Detect() {
    uint8_t boot[512];
    if (device_->ReadAt(0, boot, 512) < 512) return false;

    // NTFS OEM ID "NTFS    " at byte offset 3
    if (std::memcmp(boot + 3, "NTFS    ", 8) != 0) return false;

    bytes_per_sector_ = *reinterpret_cast<const uint16_t*>(boot + 11);
    sectors_per_cluster_ = boot[13];
    total_sectors_ = *reinterpret_cast<const uint64_t*>(boot + 40);

    return bytes_per_sector_ >= 512 && total_sectors_ > 0;
}

uint64_t NtfsFileSystem::GetTotalSize() const {
    return total_sectors_ * bytes_per_sector_;
}

bool NtfsFileSystem::ReadDirectory(const std::string& path, std::vector<FileEntry>& out_entries) {
    return is_valid_; // Stubs for discovery
}

size_t NtfsFileSystem::ReadFile(const FileEntry& entry, uint64_t offset, void* buffer, size_t size) {
    return 0;
}

} // namespace disk_analyzer
