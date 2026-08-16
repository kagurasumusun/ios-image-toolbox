#include <iostream>
#include <vector>
#include <cstring>
#include "test_suite.hpp"
#include "block_device.hpp"
#include "fat_filesystem.hpp"
#include "filesystem.hpp"

using namespace disk_analyzer;

void TestFilesystem() {
    std::cout << "Testing FAT Filesystem Parser & Streaming Extraction..." << std::endl;

    std::vector<uint8_t> fat_image(512 * 2880, 0);

    FatBpb* bpb = reinterpret_cast<FatBpb*>(fat_image.data());
    bpb->jmp_boot[0] = 0xEB; bpb->jmp_boot[1] = 0x3C; bpb->jmp_boot[2] = 0x90;
    std::memcpy(bpb->oem_name, "MSDOS5.0", 8);
    bpb->bytes_per_sector = 512;
    bpb->sectors_per_cluster = 1;
    bpb->reserved_sector_count = 1;
    bpb->num_fats = 2;
    bpb->root_entry_count = 224;
    bpb->total_sectors_16 = 2880;
    bpb->media_type = 0xF0;
    bpb->fat_size_16 = 9;

    uint8_t* root_dir = fat_image.data() + (19 * 512);
    std::memcpy(root_dir, "TESTFILETXT", 11);
    root_dir[11] = 0x20;
    *reinterpret_cast<uint16_t*>(root_dir + 26) = 2;
    *reinterpret_cast<uint32_t*>(root_dir + 28) = 13;

    uint8_t* file_data = fat_image.data() + (33 * 512);
    std::memcpy(file_data, "Hello World!\n", 13);

    auto dev = std::make_shared<MemoryBlockDevice>(fat_image, 512);
    auto fs = FileSystemFactory::ProbeAndOpen(dev);

    REQUIRE(fs != nullptr);
    REQUIRE(fs->GetFsName() == "FAT12" || fs->GetFsName() == "FAT16");

    std::vector<FileEntry> entries;
    REQUIRE(fs->ReadDirectory("/", entries));
    REQUIRE(!entries.empty());
    REQUIRE(entries[0].name == "TESTFILE.TXT");
    REQUIRE(entries[0].size_bytes == 13);

    std::vector<uint8_t> extracted_bytes;
    bool extract_ok = fs->ExtractFile(entries[0], [&](const void* chunk, size_t len) {
        extracted_bytes.insert(extracted_bytes.end(),
                               reinterpret_cast<const uint8_t*>(chunk),
                               reinterpret_cast<const uint8_t*>(chunk) + len);
        return true;
    });

    REQUIRE(extract_ok);
    REQUIRE(extracted_bytes.size() == 13);
    REQUIRE(std::memcmp(extracted_bytes.data(), "Hello World!\n", 13) == 0);

    std::cout << "Filesystem Parser & Extraction Test Passed!" << std::endl;
}
