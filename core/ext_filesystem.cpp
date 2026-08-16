#include "ext_filesystem.hpp"
#include <cstring>

namespace disk_analyzer {

std::shared_ptr<ExtFileSystem> ExtFileSystem::Open(std::shared_ptr<IBlockDevice> device) {
    if (!device || !device->IsValid()) return nullptr;
    auto fs = std::make_shared<ExtFileSystem>(device);
    if (!fs->IsValid()) return nullptr;
    return fs;
}

ExtFileSystem::ExtFileSystem(std::shared_ptr<IBlockDevice> device) : device_(std::move(device)) {
    if (ParseSuperblock()) {
        is_valid_ = true;
    }
}

bool ExtFileSystem::ParseSuperblock() {
    // Ext2/3/4 Superblock is always located at offset 1024
    if (device_->ReadAt(1024, &sb_, sizeof(Ext2Superblock)) < sizeof(Ext2Superblock)) {
        return false;
    }

    if (sb_.s_magic != 0xEF53) {
        return false;
    }

    block_size_ = 1024U << sb_.s_log_block_size;
    return block_size_ >= 1024 && block_size_ <= 65536;
}

std::string ExtFileSystem::GetFsName() const {
    if (sb_.s_rev_level >= 1) return "ext4";
    return "ext2/ext3";
}

uint64_t ExtFileSystem::GetTotalSize() const {
    return static_cast<uint64_t>(sb_.s_blocks_count) * block_size_;
}

uint64_t ExtFileSystem::GetFreeSpace() const {
    return static_cast<uint64_t>(sb_.s_free_blocks_count) * block_size_;
}

bool ExtFileSystem::ReadDirectory(const std::string& path, std::vector<FileEntry>& out_entries) {
    return is_valid_; // Stubs for discovery
}

size_t ExtFileSystem::ReadFile(const FileEntry& entry, uint64_t offset, void* buffer, size_t size) {
    return 0;
}

} // namespace disk_analyzer
