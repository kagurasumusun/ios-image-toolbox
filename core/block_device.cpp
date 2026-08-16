#include "block_device.hpp"
#include <algorithm>
#include <cstring>

namespace disk_analyzer {

// --- OffsetBlockDevice ---

OffsetBlockDevice::OffsetBlockDevice(std::shared_ptr<IBlockDevice> parent, uint64_t offset, uint64_t size, uint32_t block_size)
    : parent_(std::move(parent)), offset_(offset), size_(size), block_size_(block_size) {}

size_t OffsetBlockDevice::ReadAt(uint64_t offset, void* buffer, size_t size) {
    if (!parent_ || !buffer || offset >= size_) {
        return 0;
    }
    uint64_t bytes_to_read = std::min<uint64_t>(size, size_ - offset);
    return parent_->ReadAt(offset_ + offset, buffer, static_cast<size_t>(bytes_to_read));
}

uint64_t OffsetBlockDevice::GetSize() const {
    return size_;
}

uint32_t OffsetBlockDevice::GetBlockSize() const {
    return block_size_;
}

bool OffsetBlockDevice::IsValid() const {
    return parent_ && parent_->IsValid();
}

// --- RawBlockDevice ---

std::shared_ptr<RawBlockDevice> RawBlockDevice::Open(const std::string& filepath, uint32_t block_size) {
    auto dev = std::make_shared<RawBlockDevice>(filepath, block_size);
    if (!dev->IsValid()) {
        return nullptr;
    }
    return dev;
}

RawBlockDevice::RawBlockDevice(const std::string& filepath, uint32_t block_size)
    : filepath_(filepath), block_size_(block_size) {
    stream_.open(filepath, std::ios::binary | std::ios::in);
    if (stream_.is_open()) {
        stream_.seekg(0, std::ios::end);
        total_size_ = stream_.tellg();
        stream_.seekg(0, std::ios::beg);
        is_valid_ = true;
    }
}

RawBlockDevice::~RawBlockDevice() {
    if (stream_.is_open()) {
        stream_.close();
    }
}

size_t RawBlockDevice::ReadAt(uint64_t offset, void* buffer, size_t size) {
    if (!is_valid_ || !buffer || offset >= total_size_) {
        return 0;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    uint64_t bytes_to_read = std::min<uint64_t>(size, total_size_ - offset);

    stream_.clear();
    stream_.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
    if (!stream_.good()) {
        return 0;
    }

    stream_.read(reinterpret_cast<char*>(buffer), static_cast<std::streamsize>(bytes_to_read));
    return static_cast<size_t>(stream_.gcount());
}

uint64_t RawBlockDevice::GetSize() const {
    return total_size_;
}

uint32_t RawBlockDevice::GetBlockSize() const {
    return block_size_;
}

bool RawBlockDevice::IsValid() const {
    return is_valid_;
}

// --- MemoryBlockDevice ---

MemoryBlockDevice::MemoryBlockDevice(std::vector<uint8_t> data, uint32_t block_size)
    : data_(std::move(data)), block_size_(block_size) {}

size_t MemoryBlockDevice::ReadAt(uint64_t offset, void* buffer, size_t size) {
    if (!buffer || offset >= data_.size()) {
        return 0;
    }

    uint64_t bytes_to_read = std::min<uint64_t>(size, data_.size() - offset);
    std::memcpy(buffer, data_.data() + offset, static_cast<size_t>(bytes_to_read));
    return static_cast<size_t>(bytes_to_read);
}

uint64_t MemoryBlockDevice::GetSize() const {
    return data_.size();
}

uint32_t MemoryBlockDevice::GetBlockSize() const {
    return block_size_;
}

bool MemoryBlockDevice::IsValid() const {
    return true;
}

} // namespace disk_analyzer
