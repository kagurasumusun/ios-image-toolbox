#include <iostream>
#include <vector>
#include <cstring>
#include "test_suite.hpp"
#include "block_device.hpp"
#include "vhd_vmdk_vdi_block_device.hpp"

using namespace disk_analyzer;

void TestMemoryBlockDevice() {
    std::cout << "Testing Memory & Offset Block Device..." << std::endl;
    std::vector<uint8_t> data(1024, 0xAA);
    MemoryBlockDevice dev(data, 512);

    REQUIRE(dev.IsValid());
    REQUIRE(dev.GetSize() == 1024);
    REQUIRE(dev.GetBlockSize() == 512);

    uint8_t buf[256];
    size_t read = dev.ReadAt(0, buf, sizeof(buf));
    REQUIRE(read == 256);
    REQUIRE(buf[0] == 0xAA);

    auto offset_dev = std::make_shared<OffsetBlockDevice>(
        std::make_shared<MemoryBlockDevice>(data, 512), 512, 512, 512);

    REQUIRE(offset_dev->GetSize() == 512);
    REQUIRE(offset_dev->ReadAt(0, buf, 256) == 256);

    // Test VHD Fixed Disk
    std::vector<uint8_t> vhd_data(1024, 0);
    std::memcpy(vhd_data.data() + 512, "conectix", 8); // VHD footer
    uint32_t type_be = 0x02000000; // Fixed
    std::memcpy(vhd_data.data() + 512 + 60, &type_be, 4);

    auto vhd_mem = std::make_shared<MemoryBlockDevice>(vhd_data, 512);
    auto vhd_dev = VhdBlockDevice::Open(vhd_mem);
    REQUIRE(vhd_dev != nullptr);
    REQUIRE(vhd_dev->IsValid());
}
