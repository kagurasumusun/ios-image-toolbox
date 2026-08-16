#include <iostream>
#include <vector>
#include <cstring>
#include "test_suite.hpp"
#include "block_device.hpp"
#include "qcow2_block_device.hpp"

using namespace disk_analyzer;

static uint32_t Swap32(uint32_t v) {
    return ((v >> 24) & 0xff) | ((v >> 8) & 0xff00) | ((v << 8) & 0xff0000) | ((v << 24) & 0xff000000);
}
static uint64_t Swap64(uint64_t v) {
    return ((v & 0x00000000000000ffULL) << 56) |
           ((v & 0x000000000000ff00ULL) << 40) |
           ((v & 0x0000000000ff0000ULL) << 24) |
           ((v & 0x00000000ff000000ULL) << 8)  |
           ((v & 0x000000ff00000000ULL) >> 8)  |
           ((v & 0x0000ff0000000000ULL) >> 24) |
           ((v & 0x00ff000000000000ULL) >> 40) |
           ((v & 0xff00000000000000ULL) >> 56);
}

void TestQcow2() {
    std::cout << "Testing QCOW2 Image Parser..." << std::endl;

    constexpr size_t cluster_size = 65536;
    std::vector<uint8_t> qcow2_data(cluster_size * 4, 0);

    // QCOW2 Header
    uint32_t magic = Swap32(0x514649fb);
    uint32_t version = Swap32(3);
    uint32_t cluster_bits = Swap32(16); // 2^16 = 65536
    uint64_t virtual_size = Swap64(1024 * 1024); // 1MB
    uint32_t l1_size = Swap32(1);
    uint64_t l1_offset = Swap64(cluster_size); // 65536
    uint64_t refcount_offset = Swap64(cluster_size * 2);
    uint32_t refcount_clusters = Swap32(1);

    std::memcpy(qcow2_data.data() + 0, &magic, 4);
    std::memcpy(qcow2_data.data() + 4, &version, 4);
    std::memcpy(qcow2_data.data() + 20, &cluster_bits, 4);
    std::memcpy(qcow2_data.data() + 24, &virtual_size, 8);
    std::memcpy(qcow2_data.data() + 36, &l1_size, 4);
    std::memcpy(qcow2_data.data() + 40, &l1_offset, 8);
    std::memcpy(qcow2_data.data() + 48, &refcount_offset, 8);
    std::memcpy(qcow2_data.data() + 56, &refcount_clusters, 4);

    // L1 Table entry
    uint64_t l2_offset_entry = Swap64(cluster_size * 2);
    std::memcpy(qcow2_data.data() + cluster_size, &l2_offset_entry, 8);

    // L2 Table entry
    uint64_t data_offset_entry = Swap64(cluster_size * 3);
    std::memcpy(qcow2_data.data() + cluster_size * 2, &data_offset_entry, 8);

    // Payload
    std::memcpy(qcow2_data.data() + cluster_size * 3, "QCOW2_DATA_TEST", 15);

    auto memory_dev = std::make_shared<MemoryBlockDevice>(qcow2_data, 512);
    auto qcow2_dev = Qcow2BlockDevice::Open(memory_dev);

    REQUIRE(qcow2_dev != nullptr);
    REQUIRE(qcow2_dev->IsValid());
    REQUIRE(qcow2_dev->GetSize() == 1024 * 1024);

    uint8_t read_buf[16]{};
    size_t read_bytes = qcow2_dev->ReadAt(0, read_buf, 15);
    REQUIRE(read_bytes == 15);
    REQUIRE(std::memcmp(read_buf, "QCOW2_DATA_TEST", 15) == 0);

    std::cout << "QCOW2 Test Passed!" << std::endl;
}
