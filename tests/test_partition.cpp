#include <iostream>
#include <cassert>
#include <vector>
#include <cstring>
#include <zlib.h>
#include "test_suite.hpp"
#include "block_device.hpp"
#include "partition.hpp"

using namespace disk_analyzer;

void TestPartition() {
    std::cout << "Testing MBR & GPT Partition Table Parsers..." << std::endl;

    // Build synthetic MBR image
    std::vector<uint8_t> mbr_data(512 * 100, 0);
    // Boot signature
    mbr_data[510] = 0x55;
    mbr_data[511] = 0xAA;

    // Partition 1
    uint8_t* entry1 = mbr_data.data() + 446;
    entry1[0] = 0x80; // bootable
    entry1[4] = 0x0C; // FAT32 LBA
    *reinterpret_cast<uint32_t*>(entry1 + 8) = 2048; // start sector
    *reinterpret_cast<uint32_t*>(entry1 + 12) = 4096; // size in sectors

    auto dev = std::make_shared<MemoryBlockDevice>(mbr_data, 512);
    auto parts = PartitionTableParser::Parse(dev);

    assert(parts.size() == 1);
    assert(parts[0].index == 1);
    assert(parts[0].bootable == true);
    assert(parts[0].start_sector == 2048);
    assert(parts[0].sector_count == 4096);
    assert(parts[0].estimated_fs == PartitionType::Fat32);

    std::cout << "MBR Partition Test Passed!" << std::endl;
}
