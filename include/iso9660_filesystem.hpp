#ifndef ISO9660_FILESYSTEM_HPP
#define ISO9660_FILESYSTEM_HPP

#include "filesystem.hpp"
#include <vector>
#include <memory>

namespace disk_analyzer {

class Iso9660FileSystem : public IFileSystem {
public:
    static std::shared_ptr<Iso9660FileSystem> Open(std::shared_ptr<IBlockDevice> device);

    explicit Iso9660FileSystem(std::shared_ptr<IBlockDevice> device);

    std::string GetFsName() const override { return "ISO9660"; }
    uint64_t GetTotalSize() const override;
    uint64_t GetFreeSpace() const override { return 0; }

    bool ReadDirectory(const std::string& path, std::vector<FileEntry>& out_entries) override;
    size_t ReadFile(const FileEntry& entry, uint64_t offset, void* buffer, size_t size) override;

    bool IsValid() const { return is_valid_; }

private:
    bool ParseVolumeDescriptors();

    std::shared_ptr<IBlockDevice> device_;
    bool is_valid_{false};
    uint32_t logical_block_size_{2048};
    uint32_t volume_space_size_{0};
    uint32_t root_extent_lba_{0};
    uint32_t root_data_length_{0};
};

} // namespace disk_analyzer

#endif // ISO9660_FILESYSTEM_HPP
