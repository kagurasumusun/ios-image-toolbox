#include "analysis.hpp"
#include <algorithm>
#include <cmath>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <cctype>
#include <zlib.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

namespace disk_analyzer {

// --- HexAnalyzer ---

std::vector<HexViewRow> HexAnalyzer::GetHexView(IBlockDevice& device, uint64_t offset, size_t size, size_t bytes_per_row) {
    std::vector<HexViewRow> rows;
    if (bytes_per_row == 0) bytes_per_row = 16;

    std::vector<uint8_t> buffer(size);
    size_t read_bytes = device.ReadAt(offset, buffer.data(), size);

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

    constexpr size_t CHUNK_SIZE = 1024 * 1024; // 1MB chunked streaming
    std::vector<uint8_t> chunk(CHUNK_SIZE + pattern.size());

    uint64_t processed = 0;
    while (processed < search_len) {
        uint64_t curr_offset = start_offset + processed;
        size_t to_read = static_cast<size_t>(std::min<uint64_t>(CHUNK_SIZE + pattern.size() - 1, dev_size - curr_offset));

        size_t read_bytes = device.ReadAt(curr_offset, chunk.data(), to_read);
        if (read_bytes < pattern.size()) break;

        for (size_t i = 0; i <= read_bytes - pattern.size(); ++i) {
            if (std::memcmp(chunk.data() + i, pattern.data(), pattern.size()) == 0) {
                SearchResult res{};
                res.offset = curr_offset + i;
                res.match_length = pattern.size();

                // Snippet
                size_t snip_len = std::min<size_t>(16, read_bytes - i);
                std::string snip;
                for (size_t s = 0; s < snip_len; ++s) {
                    uint8_t c = chunk[i + s];
                    snip += (c >= 32 && c <= 126) ? static_cast<char>(c) : '.';
                }
                res.context_snippet = snip;
                results.push_back(res);

                if (results.size() >= 1000) break; // Bounded result limit
            }
        }

        processed += std::min<uint64_t>(CHUNK_SIZE, search_len - processed);

        if (progress_fn) {
            if (!progress_fn(processed, search_len)) break; // Cancelled
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
    while (processed < search_len) {
        uint64_t curr_offset = start_offset + processed;
        size_t to_read = static_cast<size_t>(std::min<uint64_t>(CHUNK_SIZE + lower_query.size() - 1, dev_size - curr_offset));

        size_t read_bytes = device.ReadAt(curr_offset, chunk.data(), to_read);
        if (read_bytes < lower_query.size()) break;

        for (size_t i = 0; i <= read_bytes - lower_query.size(); ++i) {
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

std::vector<std::string> BinaryAnalyzer::ExtractStrings(IBlockDevice& device, uint64_t offset, size_t length, size_t min_len) {
    std::vector<std::string> strings;
    std::vector<uint8_t> buffer(length);
    size_t read_bytes = device.ReadAt(offset, buffer.data(), length);

    std::string current;
    for (size_t i = 0; i < read_bytes; ++i) {
        uint8_t ch = buffer[i];
        if (ch >= 32 && ch <= 126) {
            current += static_cast<char>(ch);
        } else {
            if (current.length() >= min_len) {
                strings.push_back(current);
            }
            current.clear();
        }
    }
    if (current.length() >= min_len) {
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

    // MD5
    unsigned char md5_digest[MD5_DIGEST_LENGTH];
    MD5(buffer.data(), read_bytes, md5_digest);
    std::ostringstream md5_ss;
    for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        md5_ss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(md5_digest[i]);
    }
    res.md5_hex = md5_ss.str();

    // SHA256
    unsigned char sha_digest[SHA256_DIGEST_LENGTH];
    SHA256(buffer.data(), read_bytes, sha_digest);
    std::ostringstream sha_ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        sha_ss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(sha_digest[i]);
    }
    res.sha256_hex = sha_ss.str();

    return res;
}

} // namespace disk_analyzer
