#include <iostream>
#include <cassert>
#include <vector>
#include "test_suite.hpp"
#include "block_device.hpp"

using namespace disk_analyzer;

void TestMemoryBlockDevice() {
    std::cout << "Testing Memory & Offset Block Device..." << std::endl;
    std::vector<uint8_t> data(1024, 0xAA);
    MemoryBlockDevice dev(data, 512);

    assert(dev.IsValid());
    assert(dev.GetSize() == 1024);
    assert(dev.GetBlockSize() == 512);

    uint8_t buf[256];
    size_t read = dev.ReadAt(0, buf, sizeof(buf));
    assert(read == 256);
    assert(buf[0] == 0xAA);

    auto offset_dev = std::make_shared<OffsetBlockDevice>(
        std::make_shared<MemoryBlockDevice>(data, 512), 512, 512, 512);

    assert(offset_dev->GetSize() == 512);
    assert(offset_dev->ReadAt(0, buf, 256) == 256);
}
