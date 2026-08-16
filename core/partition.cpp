#include "partition.hpp"
#include <cstring>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <zlib.h>

namespace disk_analyzer {

static PartitionType EstimateFsType(uint8_t mbr_type) {
    switch (mbr_type) {
        case 0x01: return PartitionType::Fat12;
        case 0x04:
        case 0x06:
        case 0x0E: return PartitionType::Fat16;
        case 0x0B:
        case 0x0C: return PartitionType::Fat32;
        case 0x07: return PartitionType::Ntfs;
        case 0x83: return PartitionType::Ext234;
        case 0x82: return PartitionType::LinuxSwap;
        case 0xEF: return PartitionType::EfiSystem;
        case 0xEE: return PartitionType::GptProtective;
        case 0xAF: return PartitionType::AppleHfs;
        default: return PartitionType::Unknown;
    }
}

static std::string GuidToString(const uint8_t* g) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0')
        << std::setw(8) << (*reinterpret_cast<const uint32_t*>(g)) << "-"
        << std::setw(4) << (*reinterpret_cast<const uint16_t*>(g + 4)) << "-"
        << std::setw(4) << (*reinterpret_cast<const uint16_t*>(g + 6)) << "-"
        << std::setw(2) << static_cast<int>(g[8])
        << std::setw(2) << static_cast<int>(g[9]) << "-"
        << std::setw(2) << static_cast<int>(g[10])
        << std::setw(2) << static_cast<int>(g[11])
        << std::setw(2) << static_cast<int>(g[12])
        << std::setw(2) << static_cast<int>(g[13])
        << std::setw(2) << static_cast<int>(g[14])
        << std::setw(2) << static_cast<int>(g[15]);
    return oss.str();
}

static uint32_t Swap32(uint32_t v) {
    return ((v >> 24) & 0xff) | ((v >> 8) & 0xff00) | ((v << 8) & 0xff0000) | ((v << 24) & 0xff000000);
}

std::vector<PartitionInfo> PartitionTableParser::Parse(std::shared_ptr<IBlockDevice> device) {
    std::vector<PartitionInfo> partitions;
    if (!device || !device->IsValid()) {
        return partitions;
    }

    if (ParseGpt(device, partitions) && !partitions.empty()) {
        return partitions;
    }

    if (ParseApm(device, partitions) && !partitions.empty()) {
        return partitions;
    }

    ParseMbr(device, partitions);
    return partitions;
}

bool PartitionTableParser::ParseMbr(std::shared_ptr<IBlockDevice> device, std::vector<PartitionInfo>& out_partitions) {
    if (device->GetSize() < 512) {
        return false;
    }

    uint8_t sector[512];
    if (device->ReadAt(0, sector, 512) < 512) {
        return false;
    }

    if (sector[510] != 0x55 || sector[511] != 0xAA) {
        return false;
    }

    uint32_t block_size = device->GetBlockSize();
    bool found_valid = false;

    for (int i = 0; i < 4; ++i) {
        const uint8_t* entry = sector + 446 + (i * 16);
        uint8_t status = entry[0];
        uint8_t type = entry[4];

        uint32_t lba_start = *reinterpret_cast<const uint32_t*>(entry + 8);
        uint32_t sector_count = *reinterpret_cast<const uint32_t*>(entry + 12);

        if (type == 0x00 || sector_count == 0) {
            continue;
        }

        if (type == 0xEE && i == 0) {
            return false;
        }

        PartitionInfo info{};
        info.index = static_cast<uint32_t>(i + 1);
        info.start_sector = lba_start;
        info.sector_count = sector_count;
        info.start_offset_bytes = static_cast<uint64_t>(lba_start) * block_size;
        info.size_bytes = static_cast<uint64_t>(sector_count) * block_size;
        info.mbr_type = type;
        info.bootable = (status == 0x80);
        info.estimated_fs = EstimateFsType(type);
        info.name = "Primary Partition " + std::to_string(i + 1);

        out_partitions.push_back(info);
        found_valid = true;
    }

    return found_valid;
}

bool PartitionTableParser::ParseGpt(std::shared_ptr<IBlockDevice> device, std::vector<PartitionInfo>& out_partitions) {
    uint32_t block_size = device->GetBlockSize();
    if (device->GetSize() < block_size * 2) {
        return false;
    }

    uint8_t header[512];
    if (device->ReadAt(block_size, header, 512) < 512) {
        return false;
    }

    if (std::memcmp(header, "EFI PART", 8) != 0) {
        return false;
    }

    uint32_t header_size = *reinterpret_cast<const uint32_t*>(header + 12);
    if (header_size < 92 || header_size > 512) {
        return false;
    }

    uint32_t header_crc = *reinterpret_cast<const uint32_t*>(header + 16);

    std::vector<uint8_t> header_copy(header, header + header_size);
    std::memset(header_copy.data() + 16, 0, 4);
    uint32_t calc_crc = static_cast<uint32_t>(crc32(0L, header_copy.data(), header_size));
    if (calc_crc != header_crc) {
        return false;
    }

    uint64_t partition_entry_lba = *reinterpret_cast<const uint64_t*>(header + 72);
    uint32_t num_partition_entries = *reinterpret_cast<const uint32_t*>(header + 80);
    uint32_t size_partition_entry = *reinterpret_cast<const uint32_t*>(header + 84);

    if (num_partition_entries > 256 || size_partition_entry < 128 || size_partition_entry > 512) {
        return false;
    }

    size_t entries_bytes = static_cast<size_t>(num_partition_entries) * size_partition_entry;
    std::vector<uint8_t> entries(entries_bytes);

    if (device->ReadAt(partition_entry_lba * block_size, entries.data(), entries_bytes) < entries_bytes) {
        return false;
    }

    for (uint32_t i = 0; i < num_partition_entries; ++i) {
        const uint8_t* entry = entries.data() + (i * size_partition_entry);

        bool is_empty = true;
        for (int b = 0; b < 16; ++b) {
            if (entry[b] != 0) {
                is_empty = false;
                break;
            }
        }
        if (is_empty) {
            continue;
        }

        uint64_t first_lba = *reinterpret_cast<const uint64_t*>(entry + 32);
        uint64_t last_lba = *reinterpret_cast<const uint64_t*>(entry + 40);

        if (last_lba < first_lba) {
            continue;
        }

        uint64_t sector_count = (last_lba - first_lba) + 1;

        PartitionInfo info{};
        info.index = i + 1;
        info.start_sector = first_lba;
        info.sector_count = sector_count;
        info.start_offset_bytes = first_lba * block_size;
        info.size_bytes = sector_count * block_size;
        info.type_guid = GuidToString(entry);
        info.partition_guid = GuidToString(entry + 16);

        std::u16string u16name;
        for (int c = 0; c < 36; ++c) {
            uint16_t ch = *reinterpret_cast<const uint16_t*>(entry + 56 + c * 2);
            if (ch == 0) break;
            u16name.push_back(ch);
        }
        std::string utf8_name;
        for (char16_t ch : u16name) {
            utf8_name += (ch < 128) ? static_cast<char>(ch) : '?';
        }
        info.name = utf8_name.empty() ? ("Partition " + std::to_string(i + 1)) : utf8_name;

        out_partitions.push_back(info);
    }

    return true;
}

bool PartitionTableParser::ParseApm(std::shared_ptr<IBlockDevice> device, std::vector<PartitionInfo>& out_partitions) {
    if (device->GetSize() < 1024) return false;

    uint8_t pm_sector[512];
    if (device->ReadAt(512, pm_sector, 512) < 512) return false;

    // Check "PM" magic at offset 0 of sector 1 (0x504D)
    if (pm_sector[0] != 'P' || pm_sector[1] != 'M') {
        return false;
    }

    uint32_t map_entry_count = Swap32(*reinterpret_cast<const uint32_t*>(pm_sector + 4));
    if (map_entry_count > 64) return false;

    for (uint32_t i = 0; i < map_entry_count; ++i) {
        uint8_t entry_buf[512];
        if (device->ReadAt((1 + i) * 512, entry_buf, 512) < 512) break;

        if (entry_buf[0] != 'P' || entry_buf[1] != 'M') break;

        uint32_t p_start = Swap32(*reinterpret_cast<const uint32_t*>(entry_buf + 8));
        uint32_t p_size = Swap32(*reinterpret_cast<const uint32_t*>(entry_buf + 12));

        char name_buf[33] = {0};
        std::memcpy(name_buf, entry_buf + 16, 32);

        char type_buf[33] = {0};
        std::memcpy(type_buf, entry_buf + 48, 32);

        PartitionInfo info{};
        info.index = i + 1;
        info.start_sector = p_start;
        info.sector_count = p_size;
        info.start_offset_bytes = static_cast<uint64_t>(p_start) * 512;
        info.size_bytes = static_cast<uint64_t>(p_size) * 512;
        info.name = name_buf[0] ? name_buf : ("APM " + std::string(type_buf));
        info.estimated_fs = (std::string(type_buf) == "Apple_HFS") ? PartitionType::AppleHfs : PartitionType::Unknown;

        out_partitions.push_back(info);
    }

    return !out_partitions.empty();
}

std::vector<UnallocatedRegion> PartitionTableParser::GetUnallocatedRegions(std::shared_ptr<IBlockDevice> device, const std::vector<PartitionInfo>& partitions) {
    std::vector<UnallocatedRegion> unallocated;
    if (!device || !device->IsValid()) return unallocated;

    uint64_t disk_size = device->GetSize();
    uint32_t block_size = device->GetBlockSize();

    if (partitions.empty()) {
        unallocated.push_back({0, disk_size, 0, disk_size / block_size});
        return unallocated;
    }

    auto sorted_parts = partitions;
    std::sort(sorted_parts.begin(), sorted_parts.end(), [](const PartitionInfo& a, const PartitionInfo& b) {
        return a.start_offset_bytes < b.start_offset_bytes;
    });

    uint64_t current_pos = 0;
    for (const auto& p : sorted_parts) {
        if (p.start_offset_bytes > current_pos) {
            uint64_t gap_size = p.start_offset_bytes - current_pos;
            if (gap_size >= block_size) {
                unallocated.push_back({
                    current_pos,
                    gap_size,
                    current_pos / block_size,
                    gap_size / block_size
                });
            }
        }
        current_pos = std::max(current_pos, p.start_offset_bytes + p.size_bytes);
    }

    if (current_pos < disk_size) {
        uint64_t remaining = disk_size - current_pos;
        if (remaining >= block_size) {
            unallocated.push_back({
                current_pos,
                remaining,
                current_pos / block_size,
                remaining / block_size
            });
        }
    }

    return unallocated;
}

DiskLayoutSummary PartitionTableParser::SummarizeLayout(std::shared_ptr<IBlockDevice> device, const std::vector<PartitionInfo>& partitions) {
    DiskLayoutSummary summary{};
    if (!device || !device->IsValid()) return summary;

    summary.total_disk_bytes = device->GetSize();
    summary.partition_count = static_cast<uint32_t>(partitions.size());

    uint64_t allocated = 0;
    for (const auto& p : partitions) {
        allocated += p.size_bytes;
    }
    summary.allocated_bytes = std::min(allocated, summary.total_disk_bytes);
    summary.unallocated_bytes = (summary.total_disk_bytes > summary.allocated_bytes) ? (summary.total_disk_bytes - summary.allocated_bytes) : 0;

    if (!partitions.empty()) {
        if (!partitions[0].type_guid.empty()) {
            summary.table_type = "GPT";
        } else if (partitions[0].mbr_type != 0) {
            summary.table_type = "MBR";
        } else {
            summary.table_type = "Custom / Container";
        }
    } else {
        summary.table_type = "Unpartitioned / Raw";
    }

    return summary;
}

} // namespace disk_analyzer
