#include <iostream>
#include <vector>
#include <cstring>
#include "test_suite.hpp"
#include "block_device.hpp"
#include "analysis.hpp"
#include "carving.hpp"
#include "diff_engine.hpp"

using namespace disk_analyzer;

void TestAnalysis() {
    std::cout << "Testing Hex Analysis, Search Engine & Binary Analysis..." << std::endl;

    std::vector<uint8_t> data = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!', 0x7F, 'E', 'L', 'F',
                                 0xFF, 0xD8, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xD9};
    MemoryBlockDevice dev(data, 512);

    auto rows = HexAnalyzer::GetHexView(dev, 0, 16, 8);
    REQUIRE(rows.size() == 2);
    REQUIRE(rows[0].ascii_dump == "Hello Wo");

    auto search_res = SearchEngine::SearchText(dev, "World");
    REQUIRE(search_res.size() == 1);
    REQUIRE(search_res[0].offset == 6);

    std::string magic = BinaryAnalyzer::DetectMagicSignature(data.data() + 12, 4);
    REQUIRE(magic == "ELF Executable");

    double entropy = BinaryAnalyzer::CalculateEntropy(data.data(), data.size());
    REQUIRE(entropy > 3.0);

    auto checksums = BinaryAnalyzer::CalculateChecksums(dev, 0, data.size());
    REQUIRE(!checksums.md5_hex.empty());
    REQUIRE(!checksums.sha256_hex.empty());

    // Test File Carving
    auto carved = FileCarver::CarveFiles(dev, 0, data.size());
    REQUIRE(carved.size() >= 2);
    REQUIRE(carved[0].suggested_extension == "elf");
    REQUIRE(carved[1].suggested_extension == "jpg");

    // Test Diff Engine
    MemoryBlockDevice dev2(data, 512);
    auto diffs = DiffEngine::CompareDevices(dev, dev2, 0, data.size());
    REQUIRE(diffs.empty()); // Identical devices produce 0 diffs

    std::cout << "Analysis Engine Tests Passed!" << std::endl;
}
