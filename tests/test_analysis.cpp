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

    // Search must find patterns spanning chunk boundaries without reporting matches
    // that start outside a caller-bounded scan range.
    std::vector<uint8_t> boundary_data((1024 * 1024) + 8, 'x');
    boundary_data[1024 * 1024 - 1] = 'A';
    boundary_data[1024 * 1024] = 'B';
    boundary_data[1024 * 1024 + 1] = 'C';
    MemoryBlockDevice boundary_dev(boundary_data, 512);
    auto bounded_miss = SearchEngine::SearchBytes(boundary_dev, {'A', 'B', 'C'}, 0, 1024 * 1024);
    REQUIRE(bounded_miss.empty());
    auto boundary_hit = SearchEngine::SearchBytes(boundary_dev, {'A', 'B', 'C'}, 0, 1024 * 1024 + 2);
    REQUIRE(boundary_hit.size() == 1);
    REQUIRE(boundary_hit[0].offset == 1024 * 1024 - 1);

    // String extraction is streaming and bounded: it preserves strings across
    // internal chunk edges but caps adversarially long strings and result counts.
    std::vector<uint8_t> string_data((1024 * 1024) + 16, 0);
    string_data[1024 * 1024 - 2] = 'T';
    string_data[1024 * 1024 - 1] = 'E';
    string_data[1024 * 1024] = 'S';
    string_data[1024 * 1024 + 1] = 'T';
    MemoryBlockDevice string_dev(string_data, 512);
    auto strings = BinaryAnalyzer::ExtractStrings(string_dev, 0, string_data.size(), 4, 1);
    REQUIRE(strings.size() == 1);
    REQUIRE(strings[0] == "TEST");

    std::vector<uint8_t> long_string_data(5000, 'A');
    MemoryBlockDevice long_string_dev(long_string_data, 512);
    auto long_strings = BinaryAnalyzer::ExtractStrings(long_string_dev, 0, long_string_data.size(), 4, 1);
    REQUIRE(long_strings.size() == 1);
    REQUIRE(long_strings[0].size() == 4096);

    std::vector<uint8_t> region_data(4096 * 4, 0x00);
    std::fill(region_data.begin() + 4096, region_data.begin() + 8192, 0xFF);
    const std::string text_region = "This is a printable forensic note repeated for text classification.\n";
    for (size_t i = 8192; i < 12288; ++i) {
        region_data[i] = static_cast<uint8_t>(text_region[(i - 8192) % text_region.size()]);
    }
    for (size_t i = 12288; i < region_data.size(); ++i) {
        region_data[i] = static_cast<uint8_t>((i * 37 + 11) & 0xFF);
    }
    MemoryBlockDevice region_dev(region_data, 512);
    auto regions = RegionInspector::ClassifyRegions(region_dev, 0, region_data.size(), 4096, 8);
    REQUIRE(regions.size() == 4);
    REQUIRE(regions[0].kind == RegionKind::ZeroFilled);
    REQUIRE(regions[1].kind == RegionKind::FFilled);
    REQUIRE(regions[2].kind == RegionKind::MostlyText);
    REQUIRE(regions[3].entropy > 7.0);

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
