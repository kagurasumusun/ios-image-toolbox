#ifndef BLOCK_DEVICE_HPP
#define BLOCK_DEVICE_HPP

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include <fstream>
#include <mutex>

namespace disk_analyzer {

class IBlockDevice {
public:
    virtual ~IBlockDevice() = default;

    // Reads exact bytes at offset into buffer. Returns number of bytes read.
    virtual size_t ReadAt(uint64_t offset, void* buffer, size_t size) = 0;

    // Returns total size in bytes of block device.
    virtual uint64_t GetSize() const = 0;

    // Returns natural block/sector size (e.g. 512, 2048, 4096).
    virtual uint32_t GetBlockSize() const = 0;

    // Returns if device is readable
    virtual bool IsValid() const = 0;
};

// Represents a sub-slice of another block device (e.g., a partition)
class OffsetBlockDevice : public IBlockDevice {
public:
    OffsetBlockDevice(std::shared_ptr<IBlockDevice> parent, uint64_t offset, uint64_t size, uint32_t block_size = 512);

    size_t ReadAt(uint64_t offset, void* buffer, size_t size) override;
    uint64_t GetSize() const override;
    uint32_t GetBlockSize() const override;
    bool IsValid() const override;

private:
    std::shared_ptr<IBlockDevice> parent_;
    uint64_t offset_;
    uint64_t size_;
    uint32_t block_size_;
};

// RAW / IMG file block device handler with random access & thread safety
class RawBlockDevice : public IBlockDevice {
public:
    static std::shared_ptr<RawBlockDevice> Open(const std::string& filepath, uint32_t block_size = 512);

    // Create from existing open stream / buffer for testing / memory images
    explicit RawBlockDevice(const std::string& filepath, uint32_t block_size = 512);
    ~RawBlockDevice() override;

    size_t ReadAt(uint64_t offset, void* buffer, size_t size) override;
    uint64_t GetSize() const override;
    uint32_t GetBlockSize() const override;
    bool IsValid() const override;

private:
    std::string filepath_;
    mutable std::ifstream stream_;
    mutable std::mutex mutex_;
    uint64_t total_size_{0};
    uint32_t block_size_{512};
    bool is_valid_{false};
};

// In-Memory Block Device for testing and synthetic image validation
class MemoryBlockDevice : public IBlockDevice {
public:
    explicit MemoryBlockDevice(std::vector<uint8_t> data, uint32_t block_size = 512);

    size_t ReadAt(uint64_t offset, void* buffer, size_t size) override;
    uint64_t GetSize() const override;
    uint32_t GetBlockSize() const override;
    bool IsValid() const override;

    std::vector<uint8_t>& GetData() { return data_; }

private:
    std::vector<uint8_t> data_;
    uint32_t block_size_;
};

} // namespace disk_analyzer

#endif // BLOCK_DEVICE_HPP
