#ifndef EXT_FILESYSTEM_HPP
#define EXT_FILESYSTEM_HPP

#include "filesystem.hpp"
#include <vector>
#include <memory>

namespace disk_analyzer {

#pragma pack(push, 1)
struct Ext2Superblock {
    uint32_t s_inodes_count;
    uint32_t s_blocks_count;
    uint32_t s_r_blocks_count;
    uint32_t s_free_blocks_count;
    uint32_t s_free_inodes_count;
    uint32_t s_first_data_block;
    uint32_t s_log_block_size;
    uint32_t s_log_cluster_size;
    uint32_t s_blocks_per_group;
    uint32_t s_clusters_per_group;
    uint32_t s_inodes_per_group;
    uint32_t s_mtime;
    uint32_t s_wtime;
    uint16_t s_mnt_count;
    uint16_t s_max_mnt_count;
    uint16_t s_magic; // 0xEF53
    uint16_t s_state;
    uint16_t s_errors;
    uint16_t s_minor_rev_level;
    uint32_t s_lastcheck;
    uint32_t s_checkinterval;
    uint32_t s_creator_os;
    uint32_t s_rev_level;
};
#pragma pack(pop)

class ExtFileSystem : public IFileSystem {
public:
    static std::shared_ptr<ExtFileSystem> Open(std::shared_ptr<IBlockDevice> device);
    explicit ExtFileSystem(std::shared_ptr<IBlockDevice> device);

    std::string GetFsName() const override;
    uint64_t GetTotalSize() const override;
    uint64_t GetFreeSpace() const override;

    bool ReadDirectory(const std::string& path, std::vector<FileEntry>& out_entries) override;
    size_t ReadFile(const FileEntry& entry, uint64_t offset, void* buffer, size_t size) override;

    bool IsValid() const { return is_valid_; }

private:
    bool ParseSuperblock();

    std::shared_ptr<IBlockDevice> device_;
    Ext2Superblock sb_{};
    bool is_valid_{false};
    uint32_t block_size_{1024};
};

} // namespace disk_analyzer

#endif // EXT_FILESYSTEM_HPP
