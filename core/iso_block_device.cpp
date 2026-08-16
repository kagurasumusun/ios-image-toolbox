#include "iso_block_device.hpp"
#include <cstring>

namespace disk_analyzer {

std::shared_ptr<IsoBlockDevice> IsoBlockDevice::Open(std::shared_ptr<IBlockDevice> base_device) {
    if (!base_device || !base_device->IsValid()) {
        return nullptr;
    }
    auto iso = std::make_shared<IsoBlockDevice>(base_device);
    if (!iso->IsValid()) {
        return nullptr;
    }
    return iso;
}

IsoBlockDevice::IsoBlockDevice(std::shared_ptr<IBlockDevice> base_device)
    : base_dev_(std::move(base_device)) {
    if (DetectIso()) {
        is_valid_ = true;
        size_ = base_dev_->GetSize();
    }
}

bool IsoBlockDevice::DetectIso() {
    if (!base_dev_ || base_dev_->GetSize() < 16 * 2048 + 6) {
        return false;
    }

    uint8_t header[6];
    // Primary Volume Descriptor at sector 16 (0x8000)
    if (base_dev_->ReadAt(16 * 2048, header, sizeof(header)) < sizeof(header)) {
        return false;
    }

    // "CD001" magic at byte offset 1 in Volume Descriptor
    if (std::memcmp(header + 1, "CD001", 5) == 0) {
        sector_size_ = 2048;
        return true;
    }

    return false;
}

size_t IsoBlockDevice::ReadAt(uint64_t offset, void* buffer, size_t size) {
    if (!is_valid_ || !base_dev_) {
        return 0;
    }
    return base_dev_->ReadAt(offset, buffer, size);
}

uint64_t IsoBlockDevice::GetSize() const {
    return size_;
}

uint32_t IsoBlockDevice::GetBlockSize() const {
    return sector_size_;
}

bool IsoBlockDevice::IsValid() const {
    return is_valid_;
}

} // namespace disk_analyzer
