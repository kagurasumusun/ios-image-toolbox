#ifndef EXFAT_NTFS_FILESYSTEM_HPP
#define EXFAT_NTFS_FILESYSTEM_HPP

#include "filesystem.hpp"

namespace disk_analyzer {

class ExFatFileSystem : public IFileSystem {
public:
    static std::shared_ptr<ExFatFileSystem> Open(std::shared_ptr<IBlockDevice> device);

    explicit ExFatFileSystem(std::shared_ptr<IBlockDevice> device);

    std::string GetFsName() const override { return "exFAT"; }
    uint64_t GetTotalSize() const override;
    uint64_t GetFreeSpace() const override { return 0; }

    bool ReadDirectory(const std::string& path, std::vector<FileEntry>& out_entries) override;
    size_t ReadFile(const FileEntry& entry, uint64_t offset, void* buffer, size_t size) override;

    bool IsValid() const { return is_valid_; }

private:
    bool Detect();

    std::shared_ptr<IBlockDevice> device_;
    bool is_valid_{false};
    uint64_t volume_length_sectors_{0};
    uint32_t bytes_per_sector_{512};
    uint32_t sectors_per_cluster_{0};
};

class NtfsFileSystem : public IFileSystem {
public:
    static std::shared_ptr<NtfsFileSystem> Open(std::shared_ptr<IBlockDevice> device);

    explicit NtfsFileSystem(std::shared_ptr<IBlockDevice> device);

    std::string GetFsName() const override { return "NTFS"; }
    uint64_t GetTotalSize() const override;
    uint64_t GetFreeSpace() const override { return 0; }

    bool ReadDirectory(const std::string& path, std::vector<FileEntry>& out_entries) override;
    size_t ReadFile(const FileEntry& entry, uint64_t offset, void* buffer, size_t size) override;

    bool IsValid() const { return is_valid_; }

private:
    bool Detect();

    std::shared_ptr<IBlockDevice> device_;
    bool is_valid_{false};
    uint64_t total_sectors_{0};
    uint16_t bytes_per_sector_{512};
    uint8_t sectors_per_cluster_{0};
};

} // namespace disk_analyzer

#endif // EXFAT_NTFS_FILESYSTEM_HPP
