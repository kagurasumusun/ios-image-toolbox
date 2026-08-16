#include "signature_scanner.hpp"
#include <algorithm>
#include <array>
#include <cstring>
#include <limits>

namespace disk_analyzer {
namespace {

struct SignatureRule {
    const char* magic;
    size_t magic_len;
    uint64_t relative_offset;
    const char* format;
    const char* category;
    const char* description;
    const char* extension;
    uint32_t confidence;
};

constexpr SignatureRule kRules[] = {
    {"\xFF\xD8\xFF", 3, 0, "JPEG", "media", "JPEG image stream", "jpg", 80},
    {"\x89PNG\x0D\x0A\x1A\x0A", 8, 0, "PNG", "media", "PNG image stream", "png", 95},
    {"%PDF-", 5, 0, "PDF", "document", "PDF document", "pdf", 95},
    {"PK\x03\x04", 4, 0, "ZIP", "archive", "ZIP-compatible archive or document container", "zip", 85},
    {"7z\xBC\xAF\x27\x1C", 6, 0, "7-Zip", "archive", "7-Zip archive", "7z", 95},
    {"Rar!\x1A\x07\x00", 7, 0, "RAR4", "archive", "RAR v4 archive", "rar", 95},
    {"Rar!\x1A\x07\x01\x00", 8, 0, "RAR5", "archive", "RAR v5 archive", "rar", 95},
    {"\x1F\x8B", 2, 0, "GZIP", "archive", "GZIP compressed stream", "gz", 80},
    {"BZh", 3, 0, "BZip2", "archive", "BZip2 compressed stream", "bz2", 85},
    {"\xFD" "7zXZ\x00", 6, 0, "XZ", "archive", "XZ compressed stream", "xz", 95},
    {"ustar", 5, 257, "TAR", "archive", "POSIX tar archive", "tar", 95},
    {"070701", 6, 0, "CPIO newc", "archive", "CPIO new ASCII archive", "cpio", 95},
    {"hsqs", 4, 0, "SquashFS LE", "filesystem", "SquashFS little-endian filesystem", "sqsh", 95},
    {"sqsh", 4, 0, "SquashFS BE", "filesystem", "SquashFS big-endian filesystem", "sqsh", 95},
    {"Cr24", 4, 0, "Chrome CRX", "browser", "Chrome extension package", "crx", 90},
    {"SQLite format 3\0", 16, 0, "SQLite3", "database", "SQLite 3 database", "sqlite", 95},
    {"\x7F" "ELF", 4, 0, "ELF", "executable", "ELF executable/shared object", "elf", 95},
    {"MZ", 2, 0, "MZ/PE", "executable", "DOS/Windows executable candidate", "exe", 70},
    {"\xCF\xFA\xED\xFE", 4, 0, "Mach-O 64 LE", "executable", "Mach-O 64-bit little-endian binary", "macho", 95},
    {"\xFE\xED\xFA\xCF", 4, 0, "Mach-O 64 BE", "executable", "Mach-O 64-bit big-endian binary", "macho", 95},
    {"ANDROID!", 8, 0, "Android Boot", "firmware", "Android boot image", "img", 95},
    {"VNDRBOOT", 8, 0, "Android Vendor Boot", "firmware", "Android vendor boot image", "img", 95},
    {"AVB0", 4, 0, "Android VBMeta", "firmware", "Android verified boot metadata", "vbmeta", 95},
    {"\x27\x05\x19\x56", 4, 0, "U-Boot uImage", "firmware", "U-Boot legacy image", "uimage", 95},
    {"DTB\0", 4, 0, "Android DTB", "firmware", "Android device tree blob candidate", "dtb", 80},
    {"\xD0\x0D\xFE\xED", 4, 0, "Flattened Device Tree", "firmware", "Flattened device tree blob", "dtb", 95},
    {"EFI PART", 8, 512, "GPT Header", "partition", "GUID partition table header", "gpt", 95},
    {"CD001", 5, 0x8001, "ISO9660", "filesystem", "ISO9660 volume descriptor", "iso", 95},
};

bool MatchesAt(const std::vector<uint8_t>& window, uint64_t candidate_offset, uint64_t chunk_base, const SignatureRule& rule) {
    if (candidate_offset > std::numeric_limits<uint64_t>::max() - rule.relative_offset) return false;
    const uint64_t magic_start_offset = candidate_offset + rule.relative_offset;
    if (magic_start_offset < chunk_base) return false;
    const uint64_t in_chunk_u64 = magic_start_offset - chunk_base;
    if (in_chunk_u64 > std::numeric_limits<size_t>::max()) return false;
    const size_t in_chunk = static_cast<size_t>(in_chunk_u64);
    return in_chunk + rule.magic_len <= window.size() &&
           std::memcmp(window.data() + in_chunk, rule.magic, rule.magic_len) == 0;
}

} // namespace

std::vector<SignatureHit> SignatureScanner::Scan(IBlockDevice& device,
                                                 uint64_t start_offset,
                                                 uint64_t length,
                                                 size_t max_hits,
                                                 ProgressCallback progress_fn) {
    std::vector<SignatureHit> hits;
    if (!device.IsValid() || max_hits == 0 || start_offset >= device.GetSize()) return hits;

    const uint64_t available = device.GetSize() - start_offset;
    const uint64_t total = length > 0 ? std::min<uint64_t>(length, available) : available;
    if (total == 0) return hits;

    constexpr size_t kChunkSize = 1024 * 1024;
    constexpr size_t kOverlap = 4096;
    std::vector<uint8_t> chunk(kChunkSize + kOverlap);

    uint64_t scanned = 0;
    while (scanned < total && hits.size() < max_hits) {
        const uint64_t chunk_start = start_offset + scanned;
        const size_t to_read = static_cast<size_t>(std::min<uint64_t>(kChunkSize + kOverlap, device.GetSize() - chunk_start));
        const size_t read_bytes = device.ReadAt(chunk_start, chunk.data(), to_read);
        if (read_bytes == 0) break;

        const size_t searchable = static_cast<size_t>(std::min<uint64_t>(read_bytes, total - scanned));
        for (size_t i = 0; i < searchable && hits.size() < max_hits; ++i) {
            const uint64_t absolute = chunk_start + i;
            for (const auto& rule : kRules) {
                if (MatchesAt(chunk, absolute, chunk_start, rule)) {
                    const uint64_t hit_offset = absolute;
                    bool duplicate = false;
                    for (const auto& hit : hits) {
                        if (hit.offset == hit_offset && hit.format == rule.format) {
                            duplicate = true;
                            break;
                        }
                    }
                    if (!duplicate) {
                        hits.push_back(SignatureHit{hit_offset, rule.format, rule.category, rule.description, rule.extension, rule.confidence});
                    }
                }
            }
        }

        const uint64_t step = std::min<uint64_t>(kChunkSize, total - scanned);
        scanned += step;
        if (progress_fn && !progress_fn(scanned, total)) break;
    }

    std::sort(hits.begin(), hits.end(), [](const auto& a, const auto& b) {
        if (a.offset != b.offset) return a.offset < b.offset;
        return a.confidence > b.confidence;
    });
    return hits;
}

} // namespace disk_analyzer
