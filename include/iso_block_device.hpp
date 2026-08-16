#ifndef ISO_BLOCK_DEVICE_HPP
#define ISO_BLOCK_DEVICE_HPP

#include "block_device.hpp"
#include <memory>

namespace disk_analyzer {

class IsoBlockDevice : public IBlockDevice {
public:
    static std::shared_ptr<IsoBlockDevice> Open(std::shared_ptr<IBlockDevice> base_device);

    explicit IsoBlockDevice(std::shared_ptr<IBlockDevice> base_device);
    ~IsoBlockDevice() override = default;

    size_t ReadAt(uint64_t offset, void* buffer, size_t size) override;
    uint64_t GetSize() const override;
    uint32_t GetBlockSize() const override;
    bool IsValid() const override;

private:
    bool DetectIso();

    std::shared_ptr<IBlockDevice> base_dev_;
    bool is_valid_{false};
    uint64_t size_{0};
    uint32_t sector_size_{2048};
};

} // namespace disk_analyzer

#endif // ISO_BLOCK_DEVICE_HPP
