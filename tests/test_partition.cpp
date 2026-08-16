#include <iostream>
#include <vector>
#include <cstring>
#include <zlib.h>
#include "test_suite.hpp"
#include "block_device.hpp"
#include "partition.hpp"

using namespace disk_analyzer;

void TestPartition() {
    std::cout << "Testing MBR & GPT Partition Table Parsers..." << std::endl;

    std::vector<uint8_t> mbr_data(512 * 100, 0);
    mbr_data[510] = 0x55;
    mbr_data[511] = 0xAA;

    uint8_t* entry1 = mbr_data.data() + 446;
    entry1[0] = 0x80;
    entry1[4] = 0x0C;
    *reinterpret_cast<uint32_t*>(entry1 + 8) = 2048;
    *reinterpret_cast<uint32_t*>(entry1 + 12) = 4096;

    auto dev = std::make_shared<MemoryBlockDevice>(mbr_data, 512);
    auto parts = PartitionTableParser::Parse(dev);

    REQUIRE(parts.size() == 1);
    REQUIRE(parts[0].index == 1);
    REQUIRE(parts[0].bootable == true);
    REQUIRE(parts[0].start_sector == 2048);
    REQUIRE(parts[0].sector_count == 4096);
    REQUIRE(parts[0].estimated_fs == PartitionType::Fat32);

    std::cout << "MBR Partition Test Passed!" << std::endl;
}
