#ifndef QCOW2_BLOCK_DEVICE_HPP
#define QCOW2_BLOCK_DEVICE_HPP

#include "block_device.hpp"
#include <vector>
#include <memory>
#include <mutex>
#include <unordered_map>

namespace disk_analyzer {

struct Qcow2Header {
    uint32_t magic;                 // "QFI\xfb" (0x514649fb)
    uint32_t version;               // 2 or 3
    uint64_t backing_file_offset;
    uint32_t backing_file_size;
    uint32_t cluster_bits;          // e.g., 16 -> 64KB cluster size
    uint64_t size;                  // Virtual disk size in bytes
    uint32_t crypt_method;
    uint32_t l1_size;               // Number of entries in L1 table
    uint64_t l1_table_offset;
    uint64_t refcount_table_offset;
    uint32_t refcount_table_clusters;
    uint32_t nb_snapshots;
    uint64_t snapshots_offset;
    // Version 3 extra fields
    uint64_t incompatible_features;
    uint64_t compatible_features;
    uint64_t autoclear_features;
    uint32_t refcount_order;
    uint32_t header_length;
};

class Qcow2BlockDevice : public IBlockDevice {
public:
    static std::shared_ptr<Qcow2BlockDevice> Open(std::shared_ptr<IBlockDevice> base_device);

    explicit Qcow2BlockDevice(std::shared_ptr<IBlockDevice> base_device);
    ~Qcow2BlockDevice() override = default;

    size_t ReadAt(uint64_t offset, void* buffer, size_t size) override;
    uint64_t GetSize() const override;
    uint32_t GetBlockSize() const override;
    bool IsValid() const override;

    const Qcow2Header& GetHeader() const { return header_; }

private:
    bool ParseHeader();
    bool LoadL1Table();
    bool ReadCluster(uint64_t cluster_index, std::vector<uint8_t>& out_cluster);

    std::shared_ptr<IBlockDevice> base_dev_;
    Qcow2Header header_{};
    bool is_valid_{false};
    uint32_t cluster_size_{0};
    uint32_t l2_entries_per_table_{0};

    std::vector<uint64_t> l1_table_;

    // Bounded L2 table cache to prevent unlimited RAM usage
    mutable std::mutex cache_mutex_;
    static constexpr size_t MAX_L2_CACHE_ENTRIES = 128;
    mutable std::unordered_map<uint64_t, std::vector<uint64_t>> l2_cache_;

    const std::vector<uint64_t>& GetL2Table(uint64_t l1_index);
};

} // namespace disk_analyzer

#endif // QCOW2_BLOCK_DEVICE_HPP
