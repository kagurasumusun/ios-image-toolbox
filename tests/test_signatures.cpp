#include <cstring>
#include <iostream>
#include <vector>
#include "test_suite.hpp"
#include "block_device.hpp"
#include "signature_scanner.hpp"

using namespace disk_analyzer;

void TestSignatureScanner() {
    std::cout << "Testing bounded embedded signature scanner..." << std::endl;

    std::vector<uint8_t> image(1024 * 1024 + 4096, 0);
    std::memcpy(image.data() + 4096, "ANDROID!", 8);
    std::memcpy(image.data() + 65536, "\x89PNG\x0D\x0A\x1A\x0A", 8);
    std::memcpy(image.data() + 131072 + 257, "ustar", 5);
    std::memcpy(image.data() + 900000, "SQLite format 3\0", 16);

    auto dev = std::make_shared<MemoryBlockDevice>(image, 512);
    auto hits = SignatureScanner::Scan(*dev, 0, image.size(), 32);

    bool found_android = false;
    bool found_png = false;
    bool found_tar = false;
    bool found_sqlite = false;
    for (const auto& hit : hits) {
        if (hit.offset == 4096 && hit.format == "Android Boot") found_android = true;
        if (hit.offset == 65536 && hit.format == "PNG") found_png = true;
        if (hit.offset == 131072 && hit.format == "TAR") found_tar = true;
        if (hit.offset == 900000 && hit.format == "SQLite3") found_sqlite = true;
    }

    REQUIRE(found_android);
    REQUIRE(found_png);
    REQUIRE(found_tar);
    REQUIRE(found_sqlite);

    auto bounded_hits = SignatureScanner::Scan(*dev, 0, 128 * 1024, 32);
    for (const auto& hit : bounded_hits) {
        REQUIRE(hit.offset < 128 * 1024);
    }

    std::cout << "Signature Scanner Test Passed!" << std::endl;
}
