#ifndef FAT_FILESYSTEM_HPP
#define FAT_FILESYSTEM_HPP

#include "filesystem.hpp"
#include <vector>
#include <memory>
#include <mutex>
#include <unordered_map>

namespace disk_analyzer {

enum class FatVariant {
    Fat12,
    Fat16,
    Fat32
};

#pragma pack(push, 1)
struct FatBpb {
    uint8_t jmp_boot[3];
    char oem_name[8];
    uint16_t bytes_per_sector;
    uint8_t sectors_per_cluster;
    uint16_t reserved_sector_count;
    uint8_t num_fats;
    uint16_t root_entry_count;
    uint16_t total_sectors_16;
    uint8_t media_type;
    uint16_t fat_size_16;
    uint16_t sectors_per_track;
    uint16_t num_heads;
    uint32_t hidden_sectors;
    uint32_t total_sectors_32;

    // FAT32 Extended fields
    uint32_t fat_size_32;
    uint16_t ext_flags;
    uint16_t fs_version;
    uint32_t root_cluster;
    uint16_t fs_info;
    uint16_t bk_boot_sec;
    uint8_t reserved[12];
    uint8_t drive_num;
    uint8_t reserved1;
    uint8_t boot_sig;
    uint32_t vol_id;
    char vol_label[11];
    char fs_type[8];
};
#pragma pack(pop)

class FatFileSystem : public IFileSystem {
public:
    static std::shared_ptr<FatFileSystem> Open(std::shared_ptr<IBlockDevice> device);

    explicit FatFileSystem(std::shared_ptr<IBlockDevice> device);

    std::string GetFsName() const override;
    uint64_t GetTotalSize() const override;
    uint64_t GetFreeSpace() const override;

    bool ReadDirectory(const std::string& path, std::vector<FileEntry>& out_entries) override;
    size_t ReadFile(const FileEntry& entry, uint64_t offset, void* buffer, size_t size) override;

    bool IsValid() const { return is_valid_; }

private:
    bool ParseBpb();
    uint32_t GetNextCluster(uint32_t cluster);
    uint64_t ClusterToSector(uint32_t cluster) const;

    std::shared_ptr<IBlockDevice> device_;
    FatBpb bpb_{};
    FatVariant variant_{FatVariant::Fat16};
    bool is_valid_{false};

    uint32_t bytes_per_cluster_{0};
    uint64_t fat_start_sector_{0};
    uint64_t root_dir_start_sector_{0};
    uint64_t data_start_sector_{0};
    uint32_t total_clusters_{0};

    mutable std::mutex fat_mutex_;
};

} // namespace disk_analyzer

#endif // FAT_FILESYSTEM_HPP
