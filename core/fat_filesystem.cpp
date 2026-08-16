#include "fat_filesystem.hpp"
#include <cstring>
#include <algorithm>
#include <sstream>

namespace disk_analyzer {

std::shared_ptr<FatFileSystem> FatFileSystem::Open(std::shared_ptr<IBlockDevice> device) {
    if (!device || !device->IsValid()) {
        return nullptr;
    }
    auto fat = std::make_shared<FatFileSystem>(device);
    if (!fat->IsValid()) {
        return nullptr;
    }
    return fat;
}

FatFileSystem::FatFileSystem(std::shared_ptr<IBlockDevice> device) : device_(std::move(device)) {
    if (ParseBpb()) {
        is_valid_ = true;
    }
}

bool FatFileSystem::ParseBpb() {
    if (device_->ReadAt(0, &bpb_, sizeof(FatBpb)) < sizeof(FatBpb)) {
        return false;
    }

    if (bpb_.bytes_per_sector != 512 && bpb_.bytes_per_sector != 1024 &&
        bpb_.bytes_per_sector != 2048 && bpb_.bytes_per_sector != 4096) {
        return false;
    }

    if (bpb_.sectors_per_cluster == 0 || (bpb_.sectors_per_cluster & (bpb_.sectors_per_cluster - 1)) != 0) {
        return false;
    }

    bytes_per_cluster_ = static_cast<uint32_t>(bpb_.bytes_per_sector) * bpb_.sectors_per_cluster;
    uint32_t fat_size = bpb_.fat_size_16 != 0 ? bpb_.fat_size_16 : bpb_.fat_size_32;
    uint32_t total_sectors = bpb_.total_sectors_16 != 0 ? bpb_.total_sectors_16 : bpb_.total_sectors_32;

    fat_start_sector_ = bpb_.reserved_sector_count;
    uint32_t root_dir_sectors = ((bpb_.root_entry_count * 32) + (bpb_.bytes_per_sector - 1)) / bpb_.bytes_per_sector;

    root_dir_start_sector_ = fat_start_sector_ + (bpb_.num_fats * fat_size);
    data_start_sector_ = root_dir_start_sector_ + root_dir_sectors;

    if (total_sectors <= (bpb_.reserved_sector_count + (bpb_.num_fats * fat_size) + root_dir_sectors)) {
        return false;
    }

    uint32_t data_sectors = total_sectors - (bpb_.reserved_sector_count + (bpb_.num_fats * fat_size) + root_dir_sectors);
    total_clusters_ = data_sectors / bpb_.sectors_per_cluster;

    if (total_clusters_ < 4085) {
        variant_ = FatVariant::Fat12;
    } else if (total_clusters_ < 65525) {
        variant_ = FatVariant::Fat16;
    } else {
        variant_ = FatVariant::Fat32;
    }

    return true;
}

std::string FatFileSystem::GetFsName() const {
    switch (variant_) {
        case FatVariant::Fat12: return "FAT12";
        case FatVariant::Fat16: return "FAT16";
        case FatVariant::Fat32: return "FAT32";
    }
    return "FAT";
}

uint64_t FatFileSystem::GetTotalSize() const {
    uint32_t total_sectors = bpb_.total_sectors_16 != 0 ? bpb_.total_sectors_16 : bpb_.total_sectors_32;
    return static_cast<uint64_t>(total_sectors) * bpb_.bytes_per_sector;
}

uint64_t FatFileSystem::GetFreeSpace() const {
    return 0; // Read-only discovery mode
}

uint64_t FatFileSystem::ClusterToSector(uint32_t cluster) const {
    if (cluster < 2) return 0;
    return data_start_sector_ + (static_cast<uint64_t>(cluster - 2) * bpb_.sectors_per_cluster);
}

uint32_t FatFileSystem::GetNextCluster(uint32_t cluster) {
    if (cluster < 2 || cluster >= total_clusters_ + 2) {
        return 0xFFFFFFFF;
    }

    std::lock_guard<std::mutex> lock(fat_mutex_);

    if (variant_ == FatVariant::Fat32) {
        uint64_t fat_offset = fat_start_sector_ * bpb_.bytes_per_sector + (cluster * 4);
        uint32_t next_cluster = 0;
        if (device_->ReadAt(fat_offset, &next_cluster, 4) == 4) {
            next_cluster &= 0x0FFFFFFF;
            return (next_cluster >= 0x0FFFFFF8 || next_cluster < 2) ? 0xFFFFFFFF : next_cluster;
        }
    } else if (variant_ == FatVariant::Fat16) {
        uint64_t fat_offset = fat_start_sector_ * bpb_.bytes_per_sector + (cluster * 2);
        uint16_t next_cluster = 0;
        if (device_->ReadAt(fat_offset, &next_cluster, 2) == 2) {
            return (next_cluster >= 0xFFF8 || next_cluster < 2) ? 0xFFFFFFFF : static_cast<uint32_t>(next_cluster);
        }
    } else if (variant_ == FatVariant::Fat12) {
        uint64_t fat_offset = fat_start_sector_ * bpb_.bytes_per_sector + (cluster + (cluster / 2));
        uint16_t entry = 0;
        if (device_->ReadAt(fat_offset, &entry, 2) == 2) {
            if (cluster & 1) {
                entry >>= 4;
            } else {
                entry &= 0x0FFF;
            }
            return (entry >= 0x0FF8 || entry < 2) ? 0xFFFFFFFF : static_cast<uint32_t>(entry);
        }
    }

    return 0xFFFFFFFF;
}

bool FatFileSystem::ReadDirectory(const std::string& path, std::vector<FileEntry>& out_entries) {
    if (!is_valid_) return false;

    // Traverse directory tree to find directory entries for requested path
    std::vector<std::string> components;
    std::stringstream ss(path);
    std::string comp;
    while (std::getline(ss, comp, '/')) {
        if (!comp.empty() && comp != ".") {
            components.push_back(comp);
        }
    }

    uint64_t current_offset = root_dir_start_sector_ * bpb_.bytes_per_sector;
    uint32_t current_size = bpb_.root_entry_count * 32;
    uint32_t current_cluster = (variant_ == FatVariant::Fat32) ? bpb_.root_cluster : 0;

    if (current_size == 0 && variant_ == FatVariant::Fat32) {
        current_offset = ClusterToSector(current_cluster) * bpb_.bytes_per_sector;
        current_size = bytes_per_cluster_;
    }

    for (size_t c = 0; c < components.size(); ++c) {
        std::vector<FileEntry> entries;
        std::vector<uint8_t> dir_buf(current_size);
        if (device_->ReadAt(current_offset, dir_buf.data(), current_size) < current_size) {
            return false;
        }

        bool found_subdir = false;
        for (size_t i = 0; i < dir_buf.size(); i += 32) {
            const uint8_t* entry = dir_buf.data() + i;
            if (entry[0] == 0x00) break;
            if (entry[0] == 0xE5 || entry[11] == 0x0F) continue;

            char name_buf[12]{};
            std::memcpy(name_buf, entry, 11);
            std::string filename;
            for (int k = 0; k < 8; ++k) {
                if (name_buf[k] != ' ') filename += name_buf[k];
            }
            if (name_buf[8] != ' ') {
                filename += ".";
                for (int k = 8; k < 11; ++k) {
                    if (name_buf[k] != ' ') filename += name_buf[k];
                }
            }

            if (filename == components[c] && (entry[11] & 0x10)) {
                uint16_t cluster_high = *reinterpret_cast<const uint16_t*>(entry + 20);
                uint16_t cluster_low = *reinterpret_cast<const uint16_t*>(entry + 26);
                current_cluster = (static_cast<uint32_t>(cluster_high) << 16) | cluster_low;
                current_offset = ClusterToSector(current_cluster) * bpb_.bytes_per_sector;
                current_size = bytes_per_cluster_;
                found_subdir = true;
                break;
            }
        }
        if (!found_subdir) return false;
    }

    // Read target directory
    std::vector<uint8_t> dir_buf(current_size);
    if (device_->ReadAt(current_offset, dir_buf.data(), current_size) < current_size) {
        return false;
    }

    for (size_t i = 0; i < dir_buf.size(); i += 32) {
        const uint8_t* entry = dir_buf.data() + i;
        if (entry[0] == 0x00) break; // No more entries
        if (entry[0] == 0xE5) continue; // Deleted entry
        if (entry[11] == 0x0F) continue; // LFN entry

        char name_buf[12]{};
        std::memcpy(name_buf, entry, 11);

        std::string filename;
        for (int k = 0; k < 8; ++k) {
            if (name_buf[k] != ' ') filename += name_buf[k];
        }
        if (name_buf[8] != ' ') {
            filename += ".";
            for (int k = 8; k < 11; ++k) {
                if (name_buf[k] != ' ') filename += name_buf[k];
            }
        }

        if (filename == "." || filename == "..") continue;

        uint8_t attr = entry[11];
        uint16_t cluster_high = *reinterpret_cast<const uint16_t*>(entry + 20);
        uint16_t cluster_low = *reinterpret_cast<const uint16_t*>(entry + 26);
        uint32_t first_cluster = (static_cast<uint32_t>(cluster_high) << 16) | cluster_low;
        uint32_t file_size = *reinterpret_cast<const uint32_t*>(entry + 28);

        FileEntry fe{};
        fe.name = filename;
        fe.path = (path == "/" ? "" : path) + "/" + filename;
        fe.type = (attr & 0x10) ? FileType::Directory : FileType::Regular;
        fe.size_bytes = file_size;
        fe.cluster_or_inode = first_cluster;
        fe.is_hidden = (attr & 0x02);
        fe.is_readonly = (attr & 0x01);
        fe.is_system = (attr & 0x04);

        out_entries.push_back(fe);
    }

    return true;
}

size_t FatFileSystem::ReadFile(const FileEntry& entry, uint64_t offset, void* buffer, size_t size) {
    if (!is_valid_ || !buffer || offset >= entry.size_bytes) return 0;

    size_t to_read = static_cast<size_t>(std::min<uint64_t>(size, entry.size_bytes - offset));
    uint32_t current_cluster = entry.cluster_or_inode;
    uint64_t cluster_skip = offset / bytes_per_cluster_;
    uint32_t cluster_offset = offset % bytes_per_cluster_;

    // Cycle detection counter
    uint32_t steps = 0;
    while (cluster_skip > 0 && current_cluster != 0xFFFFFFFF) {
        current_cluster = GetNextCluster(current_cluster);
        cluster_skip--;
        if (++steps > total_clusters_ + 10) return 0; // Loop protection
    }

    size_t bytes_read = 0;
    while (bytes_read < to_read && current_cluster != 0xFFFFFFFF) {
        uint64_t sector = ClusterToSector(current_cluster);
        if (sector == 0) break;

        uint64_t dev_offset = (sector * bpb_.bytes_per_sector) + cluster_offset;
        size_t chunk = std::min<size_t>(to_read - bytes_read, bytes_per_cluster_ - cluster_offset);

        if (device_->ReadAt(dev_offset, reinterpret_cast<uint8_t*>(buffer) + bytes_read, chunk) != chunk) {
            break;
        }

        bytes_read += chunk;
        cluster_offset = 0;

        if (bytes_read >= to_read) break;

        current_cluster = GetNextCluster(current_cluster);
        if (++steps > total_clusters_ + 10) break;
    }

    return bytes_read;
}

} // namespace disk_analyzer
