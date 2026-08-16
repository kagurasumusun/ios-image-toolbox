#include <iostream>
#include <vector>
#include <cstring>
#include "test_suite.hpp"
#include "block_device.hpp"
#include "analysis.hpp"

using namespace disk_analyzer;

void TestAnalysis() {
    std::cout << "Testing Hex Analysis, Search Engine & Binary Analysis..." << std::endl;

    std::vector<uint8_t> data = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!', '\x7F', 'E', 'L', 'F'};
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

    std::cout << "Analysis Engine Tests Passed!" << std::endl;
}
