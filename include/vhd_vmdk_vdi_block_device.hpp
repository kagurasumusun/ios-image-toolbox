#ifndef VHD_VMDK_VDI_BLOCK_DEVICE_HPP
#define VHD_VMDK_VDI_BLOCK_DEVICE_HPP

#include "block_device.hpp"
#include <vector>
#include <memory>
#include <unordered_map>
#include <mutex>

namespace disk_analyzer {

// --- VHD (Virtual Hard Disk) Block Device ---
class VhdBlockDevice : public IBlockDevice {
public:
    static std::shared_ptr<VhdBlockDevice> Open(std::shared_ptr<IBlockDevice> base_device);
    explicit VhdBlockDevice(std::shared_ptr<IBlockDevice> base_device);

    size_t ReadAt(uint64_t offset, void* buffer, size_t size) override;
    uint64_t GetSize() const override;
    uint32_t GetBlockSize() const override { return 512; }
    bool IsValid() const override { return is_valid_; }

private:
    bool ParseHeader();
    std::shared_ptr<IBlockDevice> base_dev_;
    bool is_valid_{false};
    uint64_t current_size_{0};
    uint32_t disk_type_{0}; // 2 = Fixed, 3 = Dynamic
    uint64_t bat_offset_{0};
    uint32_t max_bat_entries_{0};
    uint32_t block_size_{0};
    std::vector<uint32_t> bat_table_;
};

// --- VMDK (Virtual Machine Disk) Block Device ---
class VmdkBlockDevice : public IBlockDevice {
public:
    static std::shared_ptr<VmdkBlockDevice> Open(std::shared_ptr<IBlockDevice> base_device);
    explicit VmdkBlockDevice(std::shared_ptr<IBlockDevice> base_device);

    size_t ReadAt(uint64_t offset, void* buffer, size_t size) override;
    uint64_t GetSize() const override;
    uint32_t GetBlockSize() const override { return 512; }
    bool IsValid() const override { return is_valid_; }

private:
    bool ParseHeader();
    std::shared_ptr<IBlockDevice> base_dev_;
    bool is_valid_{false};
    uint64_t capacity_bytes_{0};
    uint64_t grain_size_bytes_{0};
    uint64_t gd_offset_{0};
    uint32_t num_gdes_{0};
    std::vector<uint32_t> gd_table_;
};

// --- VDI (VirtualBox Disk Image) Block Device ---
class VdiBlockDevice : public IBlockDevice {
public:
    static std::shared_ptr<VdiBlockDevice> Open(std::shared_ptr<IBlockDevice> base_device);
    explicit VdiBlockDevice(std::shared_ptr<IBlockDevice> base_device);

    size_t ReadAt(uint64_t offset, void* buffer, size_t size) override;
    uint64_t GetSize() const override;
    uint32_t GetBlockSize() const override { return 512; }
    bool IsValid() const override { return is_valid_; }

private:
    bool ParseHeader();
    std::shared_ptr<IBlockDevice> base_dev_;
    bool is_valid_{false};
    uint64_t disk_size_{0};
    uint32_t block_size_{0};
    uint32_t blocks_in_image_{0};
    uint32_t offset_blocks_{0};
    uint32_t offset_data_{0};
    std::vector<uint32_t> block_map_;
};

} // namespace disk_analyzer

#endif // VHD_VMDK_VDI_BLOCK_DEVICE_HPP
