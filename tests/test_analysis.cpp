#include <iostream>
#include <cassert>
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

    // 1. Hex Analysis
    auto rows = HexAnalyzer::GetHexView(dev, 0, 16, 8);
    assert(rows.size() == 2);
    assert(rows[0].ascii_dump == "Hello Wo");

    // 2. Search Engine
    auto search_res = SearchEngine::SearchText(dev, "World");
    assert(search_res.size() == 1);
    assert(search_res[0].offset == 6);

    // 3. Binary Magic & Entropy
    std::string magic = BinaryAnalyzer::DetectMagicSignature(data.data() + 12, 4);
    assert(magic == "ELF Executable");

    double entropy = BinaryAnalyzer::CalculateEntropy(data.data(), data.size());
    assert(entropy > 3.0);

    // 4. Checksums
    auto checksums = BinaryAnalyzer::CalculateChecksums(dev, 0, data.size());
    assert(!checksums.md5_hex.empty());
    assert(!checksums.sha256_hex.empty());

    std::cout << "Analysis Engine Tests Passed!" << std::endl;
}
