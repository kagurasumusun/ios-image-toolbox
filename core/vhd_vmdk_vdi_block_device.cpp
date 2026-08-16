#include "vhd_vmdk_vdi_block_device.hpp"
#include <cstring>
#include <algorithm>

namespace disk_analyzer {

static uint32_t Be32(uint32_t v) {
    return ((v >> 24) & 0xff) | ((v >> 8) & 0xff00) | ((v << 8) & 0xff0000) | ((v << 24) & 0xff000000);
}
static uint64_t Be64(uint64_t v) {
    return ((v & 0x00000000000000ffULL) << 56) |
           ((v & 0x000000000000ff00ULL) << 40) |
           ((v & 0x0000000000ff0000ULL) << 24) |
           ((v & 0x00000000ff000000ULL) << 8)  |
           ((v & 0x000000ff00000000ULL) >> 8)  |
           ((v & 0x0000ff0000000000ULL) >> 24) |
           ((v & 0x00ff000000000000ULL) >> 40) |
           ((v & 0xff00000000000000ULL) >> 56);
}

// --- VHD ---

std::shared_ptr<VhdBlockDevice> VhdBlockDevice::Open(std::shared_ptr<IBlockDevice> base_device) {
    if (!base_device || !base_device->IsValid()) return nullptr;
    auto vhd = std::make_shared<VhdBlockDevice>(base_device);
    if (!vhd->IsValid()) return nullptr;
    return vhd;
}

VhdBlockDevice::VhdBlockDevice(std::shared_ptr<IBlockDevice> base_device)
    : base_dev_(std::move(base_device)) {
    if (ParseHeader()) {
        is_valid_ = true;
    }
}

bool VhdBlockDevice::ParseHeader() {
    uint64_t dev_size = base_dev_->GetSize();
    if (dev_size < 512) return false;

    // VHD Footer is at end of file (or beginning for dynamic)
    uint8_t footer[512];
    if (base_dev_->ReadAt(dev_size - 512, footer, 512) < 512) return false;

    // Cookie "conectix"
    if (std::memcmp(footer, "conectix", 8) != 0) {
        // Try reading at start
        if (base_dev_->ReadAt(0, footer, 512) < 512) return false;
        if (std::memcmp(footer, "conectix", 8) != 0) return false;
    }

    current_size_ = Be64(*reinterpret_cast<const uint64_t*>(footer + 40));
    disk_type_ = Be32(*reinterpret_cast<const uint32_t*>(footer + 60));

    if (disk_type_ == 2) { // Fixed VHD
        return true;
    }

    if (disk_type_ == 3) { // Dynamic VHD
        uint64_t dyn_hdr_offset = Be64(*reinterpret_cast<const uint64_t*>(footer + 16));
        uint8_t dyn_hdr[1024];
        if (base_dev_->ReadAt(dyn_hdr_offset, dyn_hdr, 1024) < 1024) return false;

        if (std::memcmp(dyn_hdr, "cxsparse", 8) != 0) return false;

        bat_offset_ = Be64(*reinterpret_cast<const uint64_t*>(dyn_hdr + 16));
        max_bat_entries_ = Be32(*reinterpret_cast<const uint32_t*>(dyn_hdr + 28));
        block_size_ = Be32(*reinterpret_cast<const uint32_t*>(dyn_hdr + 32));

        if (max_bat_entries_ > 1024 * 1024) return false;

        bat_table_.resize(max_bat_entries_);
        if (base_dev_->ReadAt(bat_offset_, bat_table_.data(), max_bat_entries_ * 4) < max_bat_entries_ * 4) {
            return false;
        }

        for (auto& entry : bat_table_) {
            entry = Be32(entry);
        }

        return true;
    }

    return false;
}

size_t VhdBlockDevice::ReadAt(uint64_t offset, void* buffer, size_t size) {
    if (!is_valid_ || !buffer || offset >= current_size_) return 0;

    if (disk_type_ == 2) { // Fixed VHD
        return base_dev_->ReadAt(offset, buffer, size);
    }

    // Dynamic VHD lookup
    size_t bytes_read = 0;
    uint64_t bytes_to_read = std::min<uint64_t>(size, current_size_ - offset);

    while (bytes_read < bytes_to_read) {
        uint64_t curr_pos = offset + bytes_read;
        uint32_t block_idx = static_cast<uint32_t>(curr_pos / block_size_);
        uint32_t block_off = static_cast<uint32_t>(curr_pos % block_size_);
        uint32_t chunk = std::min<uint32_t>(static_cast<uint32_t>(bytes_to_read - bytes_read), block_size_ - block_off);

        if (block_idx >= bat_table_.size() || bat_table_[block_idx] == 0xFFFFFFFF) {
            // Unallocated block -> zeroes
            std::memset(reinterpret_cast<uint8_t*>(buffer) + bytes_read, 0, chunk);
        } else {
            uint64_t sector_offset = static_cast<uint64_t>(bat_table_[block_idx]) * 512;
            // Bitmap occupies 1 or more sectors in VHD
            uint64_t data_offset = sector_offset + 512 + block_off;
            base_dev_->ReadAt(data_offset, reinterpret_cast<uint8_t*>(buffer) + bytes_read, chunk);
        }

        bytes_read += chunk;
    }

    return bytes_read;
}

uint64_t VhdBlockDevice::GetSize() const {
    return current_size_;
}

// --- VMDK ---

std::shared_ptr<VmdkBlockDevice> VmdkBlockDevice::Open(std::shared_ptr<IBlockDevice> base_device) {
    if (!base_device || !base_device->IsValid()) return nullptr;
    auto vmdk = std::make_shared<VmdkBlockDevice>(base_device);
    if (!vmdk->IsValid()) return nullptr;
    return vmdk;
}

VmdkBlockDevice::VmdkBlockDevice(std::shared_ptr<IBlockDevice> base_device)
    : base_dev_(std::move(base_device)) {
    if (ParseHeader()) {
        is_valid_ = true;
    }
}

bool VmdkBlockDevice::ParseHeader() {
    uint8_t header[512];
    if (base_dev_->ReadAt(0, header, 512) < 512) return false;

    // "KDMV" signature
    if (std::memcmp(header, "KDMV", 4) != 0) return false;

    uint32_t version = *reinterpret_cast<const uint32_t*>(header + 4);
    if (version > 3) return false;

    capacity_bytes_ = (*reinterpret_cast<const uint64_t*>(header + 12)) * 512;
    grain_size_bytes_ = (*reinterpret_cast<const uint64_t*>(header + 20)) * 512;

    gd_offset_ = (*reinterpret_cast<const uint64_t*>(header + 36)) * 512;
    num_gdes_ = *reinterpret_cast<const uint32_t*>(header + 44);

    return capacity_bytes_ > 0;
}

size_t VmdkBlockDevice::ReadAt(uint64_t offset, void* buffer, size_t size) {
    if (!is_valid_ || !buffer || offset >= capacity_bytes_) return 0;
    return base_dev_->ReadAt(offset, buffer, size);
}

uint64_t VmdkBlockDevice::GetSize() const {
    return capacity_bytes_;
}

// --- VDI ---

std::shared_ptr<VdiBlockDevice> VdiBlockDevice::Open(std::shared_ptr<IBlockDevice> base_device) {
    if (!base_device || !base_device->IsValid()) return nullptr;
    auto vdi = std::make_shared<VdiBlockDevice>(base_device);
    if (!vdi->IsValid()) return nullptr;
    return vdi;
}

VdiBlockDevice::VdiBlockDevice(std::shared_ptr<IBlockDevice> base_device)
    : base_dev_(std::move(base_device)) {
    if (ParseHeader()) {
        is_valid_ = true;
    }
}

bool VdiBlockDevice::ParseHeader() {
    uint8_t header[512];
    if (base_dev_->ReadAt(0, header, 512) < 512) return false;

    // VDI Pre-header signature <<< Oracle VM VirtualBox Disk Image >>> (offset 0x40 magic: 0x7F10DA2A)
    uint32_t magic = *reinterpret_cast<const uint32_t*>(header + 0x40);
    if (magic != 0x7F10DA2A) return false;

    offset_blocks_ = *reinterpret_cast<const uint32_t*>(header + 0x154);
    offset_data_ = *reinterpret_cast<const uint32_t*>(header + 0x158);
    block_size_ = *reinterpret_cast<const uint32_t*>(header + 0x168);
    disk_size_ = *reinterpret_cast<const uint64_t*>(header + 0x170);
    blocks_in_image_ = *reinterpret_cast<const uint32_t*>(header + 0x178);

    return disk_size_ > 0 && block_size_ > 0;
}

size_t VdiBlockDevice::ReadAt(uint64_t offset, void* buffer, size_t size) {
    if (!is_valid_ || !buffer || offset >= disk_size_) return 0;
    return base_dev_->ReadAt(offset, buffer, size);
}

uint64_t VdiBlockDevice::GetSize() const {
    return disk_size_;
}

} // namespace disk_analyzer
