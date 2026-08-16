#ifndef DMG_E01_BLOCK_DEVICE_HPP
#define DMG_E01_BLOCK_DEVICE_HPP

#include "block_device.hpp"
#include <memory>
#include <vector>
#include <string>

namespace disk_analyzer {

// Apple DMG (UDIF) Block Device Handler
class DmgBlockDevice : public IBlockDevice {
public:
    static std::shared_ptr<DmgBlockDevice> Open(std::shared_ptr<IBlockDevice> base_device);

    explicit DmgBlockDevice(std::shared_ptr<IBlockDevice> base_device);

    size_t ReadAt(uint64_t offset, void* buffer, size_t size) override;
    uint64_t GetSize() const override;
    uint32_t GetBlockSize() const override;
    bool IsValid() const override;

private:
    bool ParseTrailer();

    std::shared_ptr<IBlockDevice> base_dev_;
    uint64_t total_size_{0};
    uint64_t data_fork_offset_{0};
    uint64_t data_fork_length_{0};
    bool is_valid_{false};
};

// E01 (Expert Witness Forensic Format) Block Device Handler
class E01BlockDevice : public IBlockDevice {
public:
    static std::shared_ptr<E01BlockDevice> Open(std::shared_ptr<IBlockDevice> base_device);

    explicit E01BlockDevice(std::shared_ptr<IBlockDevice> base_device);

    size_t ReadAt(uint64_t offset, void* buffer, size_t size) override;
    uint64_t GetSize() const override;
    uint32_t GetBlockSize() const override;
    bool IsValid() const override;

    std::string GetCaseNumber() const { return case_number_; }
    std::string GetEvidenceNumber() const { return evidence_number_; }
    std::string GetExaminerName() const { return examiner_name_; }

private:
    bool ParseHeader();

    std::shared_ptr<IBlockDevice> base_dev_;
    uint64_t total_size_{0};
    uint64_t chunk_count_{0};
    uint32_t sectors_per_chunk_{64};
    uint32_t bytes_per_sector_{512};
    std::string case_number_;
    std::string evidence_number_;
    std::string examiner_name_;
    bool is_valid_{false};
};

// Auto-probing Image Container Factory
class ImageContainerFactory {
public:
    static std::shared_ptr<IBlockDevice> AutoDetectAndOpen(std::shared_ptr<IBlockDevice> base_device);
};

} // namespace disk_analyzer

#endif // DMG_E01_BLOCK_DEVICE_HPP
