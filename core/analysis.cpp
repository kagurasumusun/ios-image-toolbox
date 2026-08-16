#include "analysis.hpp"
#include "sha256.hpp"
#include <algorithm>
#include <cmath>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <cctype>
#include <zlib.h>

namespace disk_analyzer {

// --- HexAnalyzer ---

std::vector<HexViewRow> HexAnalyzer::GetHexView(IBlockDevice& device, uint64_t offset, size_t size, size_t bytes_per_row) {
    std::vector<HexViewRow> rows;
    if (bytes_per_row == 0) bytes_per_row = 16;
    if (!device.IsValid() || offset >= device.GetSize()) return rows;

    const uint64_t available = device.GetSize() - offset;
    const size_t bounded_size = static_cast<size_t>(std::min<uint64_t>(size, available));
    std::vector<uint8_t> buffer(bounded_size);
    size_t read_bytes = device.ReadAt(offset, buffer.data(), bounded_size);

    for (size_t i = 0; i < read_bytes; i += bytes_per_row) {
        HexViewRow row;
        row.offset = offset + i;
        size_t row_len = std::min<size_t>(bytes_per_row, read_bytes - i);

        row.bytes.assign(buffer.data() + i, buffer.data() + i + row_len);

        std::string ascii;
        for (size_t b = 0; b < row_len; ++b) {
            uint8_t ch = buffer[i + b];
            ascii += (ch >= 32 && ch <= 126) ? static_cast<char>(ch) : '.';
        }
        row.ascii_dump = ascii;

        rows.push_back(row);
    }

    return rows;
}

uint16_t HexAnalyzer::ReadUint16(const uint8_t* data, Endianness endian) {
    if (endian == Endianness::LittleEndian) {
        return static_cast<uint16_t>(data[0]) | (static_cast<uint16_t>(data[1]) << 8);
    } else {
        return (static_cast<uint16_t>(data[0]) << 8) | static_cast<uint16_t>(data[1]);
    }
}

uint32_t HexAnalyzer::ReadUint32(const uint8_t* data, Endianness endian) {
    if (endian == Endianness::LittleEndian) {
        return static_cast<uint32_t>(data[0]) |
              (static_cast<uint32_t>(data[1]) << 8) |
              (static_cast<uint32_t>(data[2]) << 16) |
              (static_cast<uint32_t>(data[3]) << 24);
    } else {
        return (static_cast<uint32_t>(data[0]) << 24) |
               (static_cast<uint32_t>(data[1]) << 16) |
               (static_cast<uint32_t>(data[2]) << 8) |
               static_cast<uint32_t>(data[3]);
    }
}

uint64_t HexAnalyzer::ReadUint64(const uint8_t* data, Endianness endian) {
    uint64_t low = ReadUint32(data, endian);
    uint64_t high = ReadUint32(data + 4, endian);
    if (endian == Endianness::LittleEndian) {
        return low | (high << 32);
    } else {
        return (low << 32) | high;
    }
}

// --- SearchEngine ---

std::vector<SearchResult> SearchEngine::SearchBytes(IBlockDevice& device,
                                              const std::vector<uint8_t>& pattern,
                                              uint64_t start_offset,
                                              uint64_t max_bytes,
                                              ProgressCallback progress_fn) {
    std::vector<SearchResult> results;
    if (pattern.empty() || !device.IsValid()) return results;

    uint64_t dev_size = device.GetSize();
    if (start_offset >= dev_size) return results;

    uint64_t search_len = (max_bytes > 0) ? std::min<uint64_t>(max_bytes, dev_size - start_offset) : (dev_size - start_offset);

    constexpr size_t CHUNK_SIZE = 1024 * 1024;
    std::vector<uint8_t> chunk(CHUNK_SIZE + pattern.size());

    uint64_t processed = 0;
    while (processed < search_len && results.size() < 1000) {
        uint64_t curr_offset = start_offset + processed;
        size_t to_read = static_cast<size_t>(std::min<uint64_t>(std::min<uint64_t>(CHUNK_SIZE, search_len - processed) + pattern.size() - 1, dev_size - curr_offset));

        size_t read_bytes = device.ReadAt(curr_offset, chunk.data(), to_read);
        if (read_bytes < pattern.size()) break;

        const size_t searchable_bytes = static_cast<size_t>(std::min<uint64_t>(read_bytes, search_len - processed));
        const size_t last_start = (searchable_bytes >= pattern.size()) ? (searchable_bytes - pattern.size() + 1) : 0;
        for (size_t i = 0; i < last_start; ++i) {
            if (std::memcmp(chunk.data() + i, pattern.data(), pattern.size()) == 0) {
                SearchResult res{};
                res.offset = curr_offset + i;
                res.match_length = pattern.size();

                size_t snip_len = std::min<size_t>(16, read_bytes - i);
                std::string snip;
                for (size_t s = 0; s < snip_len; ++s) {
                    uint8_t c = chunk[i + s];
                    snip += (c >= 32 && c <= 126) ? static_cast<char>(c) : '.';
                }
                res.context_snippet = snip;
                results.push_back(res);

                if (results.size() >= 1000) break;
            }
        }

        processed += std::min<uint64_t>(CHUNK_SIZE, search_len - processed);

        if (progress_fn) {
            if (!progress_fn(processed, search_len)) break;
        }
    }

    return results;
}

std::vector<SearchResult> SearchEngine::SearchText(IBlockDevice& device,
                                             const std::string& query,
                                             bool case_sensitive,
                                             uint64_t start_offset,
                                             uint64_t max_bytes,
                                             ProgressCallback progress_fn) {
    if (case_sensitive) {
        std::vector<uint8_t> pattern(query.begin(), query.end());
        return SearchBytes(device, pattern, start_offset, max_bytes, progress_fn);
    }

    std::vector<SearchResult> results;
    if (query.empty() || !device.IsValid()) return results;

    uint64_t dev_size = device.GetSize();
    if (start_offset >= dev_size) return results;

    uint64_t search_len = (max_bytes > 0) ? std::min<uint64_t>(max_bytes, dev_size - start_offset) : (dev_size - start_offset);

    std::string lower_query = query;
    for (auto& c : lower_query) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    constexpr size_t CHUNK_SIZE = 1024 * 1024;
    std::vector<uint8_t> chunk(CHUNK_SIZE + lower_query.size());

    uint64_t processed = 0;
    while (processed < search_len && results.size() < 1000) {
        uint64_t curr_offset = start_offset + processed;
        size_t to_read = static_cast<size_t>(std::min<uint64_t>(std::min<uint64_t>(CHUNK_SIZE, search_len - processed) + lower_query.size() - 1, dev_size - curr_offset));

        size_t read_bytes = device.ReadAt(curr_offset, chunk.data(), to_read);
        if (read_bytes < lower_query.size()) break;

        const size_t searchable_bytes = static_cast<size_t>(std::min<uint64_t>(read_bytes, search_len - processed));
        const size_t last_start = (searchable_bytes >= lower_query.size()) ? (searchable_bytes - lower_query.size() + 1) : 0;
        for (size_t i = 0; i < last_start; ++i) {
            bool match = true;
            for (size_t p = 0; p < lower_query.size(); ++p) {
                if (std::tolower(static_cast<unsigned char>(chunk[i + p])) != static_cast<unsigned char>(lower_query[p])) {
                    match = false;
                    break;
                }
            }

            if (match) {
                SearchResult res{};
                res.offset = curr_offset + i;
                res.match_length = lower_query.size();

                size_t snip_len = std::min<size_t>(16, read_bytes - i);
                std::string snip;
                for (size_t s = 0; s < snip_len; ++s) {
                    uint8_t c = chunk[i + s];
                    snip += (c >= 32 && c <= 126) ? static_cast<char>(c) : '.';
                }
                res.context_snippet = snip;
                results.push_back(res);

                if (results.size() >= 1000) break;
            }
        }

        processed += std::min<uint64_t>(CHUNK_SIZE, search_len - processed);

        if (progress_fn) {
            if (!progress_fn(processed, search_len)) break;
        }
    }

    return results;
}


// --- RegionInspector ---

const char* RegionInspector::RegionKindName(RegionKind kind) {
    switch (kind) {
        case RegionKind::ZeroFilled: return "Zero-filled";
        case RegionKind::FFilled: return "0xFF-filled";
        case RegionKind::MostlyText: return "Mostly text";
        case RegionKind::HighEntropy: return "High entropy";
        case RegionKind::Mixed: return "Mixed data";
    }
    return "Unknown";
}

std::vector<RegionSummary> RegionInspector::ClassifyRegions(IBlockDevice& device,
                                                            uint64_t offset,
                                                            uint64_t length,
                                                            size_t region_size,
                                                            size_t max_regions) {
    std::vector<RegionSummary> regions;
    if (!device.IsValid() || offset >= device.GetSize() || max_regions == 0) return regions;

    constexpr size_t MIN_REGION_SIZE = 4096;
    constexpr size_t MAX_REGION_SIZE = 16 * 1024 * 1024;
    region_size = std::clamp(region_size == 0 ? static_cast<size_t>(1024 * 1024) : region_size,
                             MIN_REGION_SIZE,
                             MAX_REGION_SIZE);

    const uint64_t scan_len = (length > 0)
        ? std::min<uint64_t>(length, device.GetSize() - offset)
        : (device.GetSize() - offset);

    std::vector<uint8_t> buffer(region_size);
    uint64_t processed = 0;
    while (processed < scan_len && regions.size() < max_regions) {
        const uint64_t current_offset = offset + processed;
        const size_t to_read = static_cast<size_t>(std::min<uint64_t>(region_size, scan_len - processed));
        const size_t read_bytes = device.ReadAt(current_offset, buffer.data(), to_read);
        if (read_bytes == 0) break;

        uint64_t counts[256] = {0};
        uint64_t printable = 0;
        for (size_t i = 0; i < read_bytes; ++i) {
            const uint8_t byte = buffer[i];
            counts[byte]++;
            if ((byte >= 32 && byte <= 126) || byte == '\n' || byte == '\r' || byte == '\t') {
                printable++;
            }
        }

        uint8_t dominant_byte = 0;
        uint64_t dominant_count = counts[0];
        for (int i = 1; i < 256; ++i) {
            if (counts[i] > dominant_count) {
                dominant_count = counts[i];
                dominant_byte = static_cast<uint8_t>(i);
            }
        }

        RegionSummary region{};
        region.offset = current_offset;
        region.length = read_bytes;
        region.entropy = BinaryAnalyzer::CalculateEntropy(buffer.data(), read_bytes);
        region.printable_ratio = static_cast<double>(printable) / static_cast<double>(read_bytes);
        region.dominant_byte = dominant_byte;
        region.dominant_ratio = static_cast<double>(dominant_count) / static_cast<double>(read_bytes);

        if (region.dominant_byte == 0x00 && region.dominant_ratio >= 0.995) {
            region.kind = RegionKind::ZeroFilled;
        } else if (region.dominant_byte == 0xFF && region.dominant_ratio >= 0.995) {
            region.kind = RegionKind::FFilled;
        } else if (region.printable_ratio >= 0.85 && region.entropy < 7.2) {
            region.kind = RegionKind::MostlyText;
        } else if (region.entropy >= 7.5 && region.dominant_ratio < 0.05) {
            region.kind = RegionKind::HighEntropy;
        } else {
            region.kind = RegionKind::Mixed;
        }

        regions.push_back(region);
        processed += read_bytes;
    }

    return regions;
}

// --- BinaryAnalyzer ---

std::string BinaryAnalyzer::DetectMagicSignature(const uint8_t* header, size_t len) {
    if (len >= 4 && std::memcmp(header, "\x7F\x45\x4C\x46", 4) == 0) return "ELF Executable";
    if (len >= 2 && std::memcmp(header, "MZ", 2) == 0) return "PE Executable (MZ)";
    if (len >= 4 && (std::memcmp(header, "\xCF\xFA\xED\xFE", 4) == 0 || std::memcmp(header, "\xCE\xFA\xED\xFE", 4) == 0)) return "Mach-O Executable";
    if (len >= 4 && std::memcmp(header, "PK\x03\x04", 4) == 0) return "ZIP Archive";
    if (len >= 4 && std::memcmp(header, "QFI\xFB", 4) == 0) return "QCOW2 Disk Image";
    if (len >= 5 && std::memcmp(header + 1, "CD001", 5) == 0) return "ISO9660 Image";
    if (len >= 3 && std::memcmp(header, "\xFF\xD8\xFF", 3) == 0) return "JPEG Image";
    if (len >= 8 && std::memcmp(header, "\x89PNG\x0D\x0A\x1A\x0A", 8) == 0) return "PNG Image";

    return "Unknown / Raw Data";
}

double BinaryAnalyzer::CalculateEntropy(const uint8_t* data, size_t len) {
    if (len == 0) return 0.0;

    uint64_t counts[256] = {0};
    for (size_t i = 0; i < len; ++i) {
        counts[data[i]]++;
    }

    double entropy = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (counts[i] > 0) {
            double p = static_cast<double>(counts[i]) / len;
            entropy -= p * (std::log2(p));
        }
    }

    return entropy;
}

std::vector<std::string> BinaryAnalyzer::ExtractStrings(IBlockDevice& device, uint64_t offset, size_t length, size_t min_len, size_t max_results) {
    std::vector<std::string> strings;
    if (!device.IsValid() || offset >= device.GetSize() || max_results == 0) return strings;

    const uint64_t scan_len = std::min<uint64_t>(length, device.GetSize() - offset);
    constexpr size_t CHUNK_SIZE = 1024 * 1024;
    constexpr size_t MAX_STRING_LEN = 4096;
    std::vector<uint8_t> buffer(CHUNK_SIZE);

    std::string current;
    uint64_t processed = 0;
    while (processed < scan_len && strings.size() < max_results) {
        const size_t to_read = static_cast<size_t>(std::min<uint64_t>(CHUNK_SIZE, scan_len - processed));
        const size_t read_bytes = device.ReadAt(offset + processed, buffer.data(), to_read);
        if (read_bytes == 0) break;

        for (size_t i = 0; i < read_bytes && strings.size() < max_results; ++i) {
            uint8_t ch = buffer[i];
            if (ch >= 32 && ch <= 126) {
                if (current.size() < MAX_STRING_LEN) {
                    current += static_cast<char>(ch);
                }
            } else {
                if (current.length() >= min_len) {
                    strings.push_back(current);
                }
                current.clear();
            }
        }
        processed += read_bytes;
    }

    if (current.length() >= min_len && strings.size() < max_results) {
        strings.push_back(current);
    }

    return strings;
}

ChecksumResult BinaryAnalyzer::CalculateChecksums(IBlockDevice& device, uint64_t offset, size_t length) {
    ChecksumResult res{};
    std::vector<uint8_t> buffer(length);
    size_t read_bytes = device.ReadAt(offset, buffer.data(), length);

    // CRC32
    res.crc32 = static_cast<uint32_t>(crc32(0L, buffer.data(), static_cast<uInt>(read_bytes)));

    // Standalone SHA256 & MD5 (portable without external libcrypto dependency)
    res.sha256_hex = Sha256::HexHash(buffer.data(), read_bytes);
    res.md5_hex = Md5::HexHash(buffer.data(), read_bytes);

    return res;
}

} // namespace disk_analyzer
