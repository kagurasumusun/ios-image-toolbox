#ifndef ANALYSIS_HPP
#define ANALYSIS_HPP

#include "block_device.hpp"
#include <string>
#include <vector>
#include <memory>
#include <cstdint>
#include <functional>

namespace disk_analyzer {

// --- Hex Analysis ---

enum class Endianness {
    LittleEndian,
    BigEndian
};

struct HexViewRow {
    uint64_t offset;
    std::vector<uint8_t> bytes;
    std::string ascii_dump;
};

class HexAnalyzer {
public:
    static std::vector<HexViewRow> GetHexView(IBlockDevice& device, uint64_t offset, size_t size, size_t bytes_per_row = 16);
    static uint16_t ReadUint16(const uint8_t* data, Endianness endian);
    static uint32_t ReadUint32(const uint8_t* data, Endianness endian);
    static uint64_t ReadUint64(const uint8_t* data, Endianness endian);
};

// --- Search Engine ---

struct SearchResult {
    uint64_t offset;
    size_t match_length;
    std::string context_snippet;
};

class SearchEngine {
public:
    using ProgressCallback = std::function<bool(uint64_t bytes_searched, uint64_t total_bytes)>;

    static std::vector<SearchResult> SearchBytes(IBlockDevice& device,
                                                  const std::vector<uint8_t>& pattern,
                                                  uint64_t start_offset = 0,
                                                  uint64_t max_bytes = 0,
                                                  ProgressCallback progress_fn = nullptr);

    static std::vector<SearchResult> SearchText(IBlockDevice& device,
                                                 const std::string& query,
                                                 bool case_sensitive = false,
                                                 uint64_t start_offset = 0,
                                                 uint64_t max_bytes = 0,
                                                 ProgressCallback progress_fn = nullptr);
};


// --- Region Diagnostics ---

enum class RegionKind {
    ZeroFilled,
    FFilled,
    MostlyText,
    HighEntropy,
    Mixed
};

struct RegionSummary {
    uint64_t offset;
    uint64_t length;
    double entropy;
    RegionKind kind;
    double printable_ratio;
    uint8_t dominant_byte;
    double dominant_ratio;
};

class RegionInspector {
public:
    static std::vector<RegionSummary> ClassifyRegions(IBlockDevice& device,
                                                       uint64_t offset = 0,
                                                       uint64_t length = 0,
                                                       size_t region_size = 1024 * 1024,
                                                       size_t max_regions = 256);
    static const char* RegionKindName(RegionKind kind);
};

// --- Binary Analysis ---

struct ChecksumResult {
    uint32_t crc32;
    std::string md5_hex;
    std::string sha256_hex;
};

class BinaryAnalyzer {
public:
    static std::string DetectMagicSignature(const uint8_t* header, size_t len);
    static double CalculateEntropy(const uint8_t* data, size_t len);
    static std::vector<std::string> ExtractStrings(IBlockDevice& device, uint64_t offset, size_t length, size_t min_len = 4, size_t max_results = 1000);
    static ChecksumResult CalculateChecksums(IBlockDevice& device, uint64_t offset, size_t length);
};

} // namespace disk_analyzer

#endif // ANALYSIS_HPP
