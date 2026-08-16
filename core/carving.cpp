#include "carving.hpp"
#include <cstring>
#include <algorithm>

namespace disk_analyzer {

struct FileSignature {
    const char* magic;
    size_t magic_len;
    const char* footer;
    size_t footer_len;
    const char* type_name;
    const char* ext;
    uint64_t max_carve_size;
};

static const FileSignature SIGNATURES[] = {
    {"\xFF\xD8\xFF", 3, "\xFF\xD9", 2, "JPEG Image", "jpg", 10 * 1024 * 1024},
    {"\x89PNG\x0D\x0A\x1A\x0A", 8, "\x49\x45\x4E\x44\xAE\x42\x60\x82", 8, "PNG Image", "png", 10 * 1024 * 1024},
    {"%PDF-", 5, "%%EOF", 5, "PDF Document", "pdf", 50 * 1024 * 1024},
    {"PK\x03\x04", 4, "PK\x05\x06", 4, "ZIP Archive", "zip", 100 * 1024 * 1024},
    {"\x7F\x45\x4C\x46", 4, nullptr, 0, "ELF Executable", "elf", 20 * 1024 * 1024},
    {"SQLite format 3\0", 16, nullptr, 0, "SQLite3 Database", "sqlite", 50 * 1024 * 1024},
    {"\x1F\x8B", 2, nullptr, 0, "GZIP Compressed Archive", "gz", 50 * 1024 * 1024},
    {"\xCF\xFA\xED\xFE", 4, nullptr, 0, "Mach-O 64-bit Executable", "macho", 20 * 1024 * 1024}
};

std::vector<CarvedFile> FileCarver::CarveFiles(IBlockDevice& device,
                                               uint64_t start_offset,
                                               uint64_t length,
                                               ProgressCallback progress_fn) {
    std::vector<CarvedFile> carved;
    if (!device.IsValid()) return carved;

    uint64_t total = (length > 0) ? std::min<uint64_t>(length, device.GetSize() - start_offset) : (device.GetSize() - start_offset);

    constexpr size_t CHUNK_SIZE = 1024 * 1024;
    std::vector<uint8_t> chunk(CHUNK_SIZE);

    uint64_t scanned = 0;
    while (scanned < total) {
        uint64_t curr_pos = start_offset + scanned;
        size_t to_read = static_cast<size_t>(std::min<uint64_t>(CHUNK_SIZE, total - scanned));

        size_t read_bytes = device.ReadAt(curr_pos, chunk.data(), to_read);
        if (read_bytes < 4) break;

        for (size_t i = 0; i <= read_bytes - 2; ++i) {
            for (const auto& sig : SIGNATURES) {
                if (i + sig.magic_len <= read_bytes && std::memcmp(chunk.data() + i, sig.magic, sig.magic_len) == 0) {
                    CarvedFile file{};
                    file.offset = curr_pos + i;
                    file.file_type = sig.type_name;
                    file.suggested_extension = sig.ext;
                    file.size_bytes = sig.max_carve_size;

                    carved.push_back(file);
                    if (carved.size() >= 200) break;
                }
            }
        }

        scanned += std::min<uint64_t>(CHUNK_SIZE, total - scanned);
        if (progress_fn) {
            if (!progress_fn(scanned, total)) break;
        }
    }

    return carved;
}

} // namespace disk_analyzer
