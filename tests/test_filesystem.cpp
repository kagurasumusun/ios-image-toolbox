#include <iostream>
#include <cassert>
#include <vector>
#include <cstring>
#include "test_suite.hpp"
#include "block_device.hpp"
#include "fat_filesystem.hpp"
#include "filesystem.hpp"

using namespace disk_analyzer;

void TestFilesystem() {
    std::cout << "Testing FAT Filesystem Parser & Streaming Extraction..." << std::endl;

    // Create synthetic FAT16 image
    std::vector<uint8_t> fat_image(512 * 2880, 0); // 1.44MB floppy-like size

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

    // Root directory starts at sector 1 + (2 * 9) = 19
    uint8_t* root_dir = fat_image.data() + (19 * 512);
    std::memcpy(root_dir, "TESTFILETXT", 11);
    root_dir[11] = 0x20; // Archive file
    *reinterpret_cast<uint16_t*>(root_dir + 26) = 2; // cluster 2
    *reinterpret_cast<uint32_t*>(root_dir + 28) = 13; // 13 bytes file size

    // Cluster 2 offset = data_start (19 + 14 = 33) * 512 = 33 * 512
    uint8_t* file_data = fat_image.data() + (33 * 512);
    std::memcpy(file_data, "Hello World!\n", 13);

    auto dev = std::make_shared<MemoryBlockDevice>(fat_image, 512);
    auto fs = FileSystemFactory::ProbeAndOpen(dev);

    assert(fs != nullptr);
    assert(fs->GetFsName() == "FAT12" || fs->GetFsName() == "FAT16");

    std::vector<FileEntry> entries;
    assert(fs->ReadDirectory("/", entries));
    assert(!entries.empty());
    assert(entries[0].name == "TESTFILE.TXT");
    assert(entries[0].size_bytes == 13);

    // Test streaming extraction
    std::vector<uint8_t> extracted_bytes;
    bool extract_ok = fs->ExtractFile(entries[0], [&](const void* chunk, size_t len) {
        extracted_bytes.insert(extracted_bytes.end(),
                               reinterpret_cast<const uint8_t*>(chunk),
                               reinterpret_cast<const uint8_t*>(chunk) + len);
        return true;
    });

    assert(extract_ok);
    assert(extracted_bytes.size() == 13);
    assert(std::memcmp(extracted_bytes.data(), "Hello World!\n", 13) == 0);

    std::cout << "Filesystem Parser & Extraction Test Passed!" << std::endl;
}
