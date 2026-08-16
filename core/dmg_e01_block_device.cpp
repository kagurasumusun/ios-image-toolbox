#include "dmg_e01_block_device.hpp"
#include "qcow2_block_device.hpp"
#include "vhd_vmdk_vdi_block_device.hpp"
#include "iso_block_device.hpp"
#include <cstring>
#include <algorithm>

namespace disk_analyzer {

static uint32_t Swap32(uint32_t v) {
    return ((v >> 24) & 0xff) | ((v >> 8) & 0xff00) | ((v << 8) & 0xff0000) | ((v << 24) & 0xff000000);
}

static uint64_t Swap64(uint64_t v) {
    return ((v & 0x00000000000000ffULL) << 56) |
           ((v & 0x000000000000ff00ULL) << 40) |
           ((v & 0x0000000000ff0000ULL) << 24) |
           ((v & 0x00000000ff000000ULL) << 8)  |
           ((v & 0x000000ff00000000ULL) >> 8)  |
           ((v & 0x0000ff0000000000ULL) >> 24) |
           ((v & 0x00ff000000000000ULL) >> 40) |
           ((v & 0xff00000000000000ULL) >> 56);
}

// --- DMG (Apple UDIF) ---

std::shared_ptr<DmgBlockDevice> DmgBlockDevice::Open(std::shared_ptr<IBlockDevice> base_device) {
    if (!base_device || !base_device->IsValid()) return nullptr;
    auto dmg = std::make_shared<DmgBlockDevice>(base_device);
    if (!dmg->IsValid()) return nullptr;
    return dmg;
}

DmgBlockDevice::DmgBlockDevice(std::shared_ptr<IBlockDevice> base_device)
    : base_dev_(std::move(base_device)) {
    if (ParseTrailer()) {
        is_valid_ = true;
    }
}

bool DmgBlockDevice::ParseTrailer() {
    uint64_t base_size = base_dev_->GetSize();
    if (base_size < 512) return false;

    uint8_t koly[512];
    if (base_dev_->ReadAt(base_size - 512, koly, 512) < 512) return false;

    // Check "koly" magic (0x6B6F6C79) at start of UDIF trailer
    if (std::memcmp(koly, "koly", 4) != 0) {
        return false;
    }

    uint32_t version = Swap32(*reinterpret_cast<const uint32_t*>(koly + 4));
    if (version != 4) return false;

    uint64_t data_fork_offset = Swap64(*reinterpret_cast<const uint64_t*>(koly + 24));
    uint64_t data_fork_length = Swap64(*reinterpret_cast<const uint64_t*>(koly + 32));
    uint64_t sector_count = Swap64(*reinterpret_cast<const uint64_t*>(koly + 160));

    data_fork_offset_ = data_fork_offset;
    data_fork_length_ = data_fork_length;
    total_size_ = sector_count * 512;

    if (total_size_ == 0) {
        total_size_ = (data_fork_length_ > 0) ? data_fork_length_ : (base_size - 512);
    }

    return true;
}

size_t DmgBlockDevice::ReadAt(uint64_t offset, void* buffer, size_t size) {
    if (!is_valid_ || !buffer || offset >= total_size_) return 0;
    return base_dev_->ReadAt(data_fork_offset_ + offset, buffer, size);
}

uint64_t DmgBlockDevice::GetSize() const {
    return total_size_;
}

uint32_t DmgBlockDevice::GetBlockSize() const {
    return 512;
}

bool DmgBlockDevice::IsValid() const {
    return is_valid_;
}

// --- E01 (Expert Witness Forensic Format) ---

std::shared_ptr<E01BlockDevice> E01BlockDevice::Open(std::shared_ptr<IBlockDevice> base_device) {
    if (!base_device || !base_device->IsValid()) return nullptr;
    auto e01 = std::make_shared<E01BlockDevice>(base_device);
    if (!e01->IsValid()) return nullptr;
    return e01;
}

E01BlockDevice::E01BlockDevice(std::shared_ptr<IBlockDevice> base_device)
    : base_dev_(std::move(base_device)) {
    if (ParseHeader()) {
        is_valid_ = true;
    }
}

bool E01BlockDevice::ParseHeader() {
    uint64_t dev_size = base_dev_->GetSize();
    if (dev_size < 13) return false;

    uint8_t hdr[13];
    if (base_dev_->ReadAt(0, hdr, 13) < 13) return false;

    // Check EVF magic "EVF\x09\x0D\x0A\xFF\x00" or EnCase signature
    if (std::memcmp(hdr, "EVF", 3) != 0 && std::memcmp(hdr, "\x45\x56\x46", 3) != 0) {
        return false;
    }

    // Default sector parameters for E01 forensic image
    sectors_per_chunk_ = 64;
    bytes_per_sector_ = 512;
    total_size_ = dev_size - 13; // Virtual stream size
    case_number_ = "E01 Forensic Image";

    return true;
}

size_t E01BlockDevice::ReadAt(uint64_t offset, void* buffer, size_t size) {
    if (!is_valid_ || !buffer || offset >= total_size_) return 0;
    return base_dev_->ReadAt(13 + offset, buffer, size);
}

uint64_t E01BlockDevice::GetSize() const {
    return total_size_;
}

uint32_t E01BlockDevice::GetBlockSize() const {
    return bytes_per_sector_;
}

bool E01BlockDevice::IsValid() const {
    return is_valid_;
}

// --- Auto Probing Factory ---

std::shared_ptr<IBlockDevice> ImageContainerFactory::AutoDetectAndOpen(std::shared_ptr<IBlockDevice> base_device) {
    if (!base_device || !base_device->IsValid()) return nullptr;

    if (auto qcow2 = Qcow2BlockDevice::Open(base_device)) return qcow2;
    if (auto iso = IsoBlockDevice::Open(base_device)) return iso;
    if (auto vhd = VhdBlockDevice::Open(base_device)) return vhd;
    if (auto vmdk = VmdkBlockDevice::Open(base_device)) return vmdk;
    if (auto vdi = VdiBlockDevice::Open(base_device)) return vdi;
    if (auto dmg = DmgBlockDevice::Open(base_device)) return dmg;
    if (auto e01 = E01BlockDevice::Open(base_device)) return e01;

    // Fall back to raw block device
    return base_device;
}

} // namespace disk_analyzer
