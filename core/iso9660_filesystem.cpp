#include "iso9660_filesystem.hpp"
#include <cstring>
#include <algorithm>

namespace disk_analyzer {

std::shared_ptr<Iso9660FileSystem> Iso9660FileSystem::Open(std::shared_ptr<IBlockDevice> device) {
    if (!device || !device->IsValid()) {
        return nullptr;
    }
    auto iso = std::make_shared<Iso9660FileSystem>(device);
    if (!iso->IsValid()) {
        return nullptr;
    }
    return iso;
}

Iso9660FileSystem::Iso9660FileSystem(std::shared_ptr<IBlockDevice> device) : device_(std::move(device)) {
    if (ParseVolumeDescriptors()) {
        is_valid_ = true;
    }
}

bool Iso9660FileSystem::ParseVolumeDescriptors() {
    uint8_t sector[2048];
    uint32_t current_sector = 16;

    while (current_sector < 32) {
        if (device_->ReadAt(static_cast<uint64_t>(current_sector) * 2048, sector, 2048) < 2048) {
            return false;
        }

        uint8_t type = sector[0];
        if (std::memcmp(sector + 1, "CD001", 5) != 0) {
            return false;
        }

        if (type == 1) { // Primary Volume Descriptor
            volume_space_size_ = *reinterpret_cast<const uint32_t*>(sector + 80);
            uint16_t blk_size = *reinterpret_cast<const uint16_t*>(sector + 128);

            // Guard against divide-by-zero or invalid logical block sizes on malformed metadata
            if (blk_size == 0 || (blk_size & (blk_size - 1)) != 0 || blk_size > 8192) {
                logical_block_size_ = 2048;
            } else {
                logical_block_size_ = blk_size;
            }

            // Root Directory Record at byte offset 156
            root_extent_lba_ = *reinterpret_cast<const uint32_t*>(sector + 156 + 2);
            uint32_t root_len = *reinterpret_cast<const uint32_t*>(sector + 156 + 10);

            // Cap root directory length to max 16MB to prevent uncontrolled RAM allocations
            if (root_len > 16 * 1024 * 1024) {
                return false;
            }
            root_data_length_ = root_len;

            return true;
        }

        if (type == 255) { // Volume Descriptor Set Terminator
            break;
        }

        current_sector++;
    }

    return false;
}

uint64_t Iso9660FileSystem::GetTotalSize() const {
    return static_cast<uint64_t>(volume_space_size_) * logical_block_size_;
}

bool Iso9660FileSystem::ReadDirectory(const std::string& path, std::vector<FileEntry>& out_entries) {
    if (!is_valid_ || logical_block_size_ == 0) return false;

    std::vector<uint8_t> dir_buf(root_data_length_);
    uint64_t root_offset = static_cast<uint64_t>(root_extent_lba_) * logical_block_size_;

    if (device_->ReadAt(root_offset, dir_buf.data(), root_data_length_) < root_data_length_) {
        return false;
    }

    size_t offset = 0;
    while (offset < root_data_length_) {
        uint8_t len = dir_buf[offset];
        if (len == 0) {
            offset = ((offset / logical_block_size_) + 1) * logical_block_size_;
            continue;
        }

        uint32_t extent_lba = *reinterpret_cast<const uint32_t*>(dir_buf.data() + offset + 2);
        uint32_t data_length = *reinterpret_cast<const uint32_t*>(dir_buf.data() + offset + 10);
        uint8_t flags = dir_buf[offset + 25];
        uint8_t name_len = dir_buf[offset + 32];

        if (name_len > 0 && offset + 33 + name_len <= root_data_length_) {
            std::string name(reinterpret_cast<const char*>(dir_buf.data() + offset + 33), name_len);
            if (name != "\x00" && name != "\x01") {
                // Strip ISO version suffix ";1"
                size_t semi = name.find(';');
                if (semi != std::string::npos) {
                    name = name.substr(0, semi);
                }

                FileEntry fe{};
                fe.name = name;
                fe.path = (path == "/" ? "" : path) + "/" + name;
                fe.type = (flags & 0x02) ? FileType::Directory : FileType::Regular;
                fe.size_bytes = data_length;
                fe.cluster_or_inode = extent_lba;

                out_entries.push_back(fe);
            }
        }

        offset += len;
    }

    return true;
}

size_t Iso9660FileSystem::ReadFile(const FileEntry& entry, uint64_t offset, void* buffer, size_t size) {
    if (!is_valid_ || !buffer || offset >= entry.size_bytes) return 0;

    size_t to_read = static_cast<size_t>(std::min<uint64_t>(size, entry.size_bytes - offset));
    uint64_t dev_offset = (static_cast<uint64_t>(entry.cluster_or_inode) * logical_block_size_) + offset;

    return device_->ReadAt(dev_offset, buffer, to_read);
}

} // namespace disk_analyzer
