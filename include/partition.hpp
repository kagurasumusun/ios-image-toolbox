#ifndef PARTITION_HPP
#define PARTITION_HPP

#include "block_device.hpp"
#include <string>
#include <vector>
#include <memory>
#include <cstdint>

namespace disk_analyzer {

enum class PartitionType {
    Unknown,
    Fat12,
    Fat16,
    Fat32,
    ExFat,
    Ntfs,
    Ext234,
    LinuxSwap,
    Iso9660,
    GptProtective,
    EfiSystem,
    AppleHfs,
    AppleApfs,
    AppleMap,
    BsdDisklabel
};

struct PartitionInfo {
    uint32_t index;
    uint64_t start_sector;
    uint64_t sector_count;
    uint64_t start_offset_bytes;
    uint64_t size_bytes;
    uint8_t mbr_type;
    std::string type_guid;
    std::string partition_guid;
    std::string name;
    bool bootable{false};
    PartitionType estimated_fs{PartitionType::Unknown};
};

struct UnallocatedRegion {
    uint64_t start_offset_bytes;
    uint64_t size_bytes;
    uint64_t start_sector;
    uint64_t sector_count;
};

struct DiskLayoutSummary {
    std::string table_type; // MBR, GPT, APM, BSD, Raw
    uint64_t total_disk_bytes{0};
    uint64_t allocated_bytes{0};
    uint64_t unallocated_bytes{0};
    uint32_t partition_count{0};
    bool is_gpt_corrupted{false};
    bool has_protective_mbr{false};
};

class PartitionTableParser {
public:
    static std::vector<PartitionInfo> Parse(std::shared_ptr<IBlockDevice> device);
    static bool ParseMbr(std::shared_ptr<IBlockDevice> device, std::vector<PartitionInfo>& out_partitions);
    static bool ParseGpt(std::shared_ptr<IBlockDevice> device, std::vector<PartitionInfo>& out_partitions);
    static bool ParseApm(std::shared_ptr<IBlockDevice> device, std::vector<PartitionInfo>& out_partitions);

    static std::vector<UnallocatedRegion> GetUnallocatedRegions(std::shared_ptr<IBlockDevice> device, const std::vector<PartitionInfo>& partitions);
    static DiskLayoutSummary SummarizeLayout(std::shared_ptr<IBlockDevice> device, const std::vector<PartitionInfo>& partitions);
};

} // namespace disk_analyzer

#endif // PARTITION_HPP
