#include "diff_engine.hpp"
#include <cstring>
#include <algorithm>

namespace disk_analyzer {

std::vector<DiffBlock> DiffEngine::CompareDevices(IBlockDevice& dev1,
                                                   IBlockDevice& dev2,
                                                   uint64_t start_offset,
                                                   uint64_t length,
                                                   ProgressCallback progress_fn) {
    std::vector<DiffBlock> diffs;
    if (!dev1.IsValid() || !dev2.IsValid()) return diffs;

    uint64_t max_len = std::min(dev1.GetSize(), dev2.GetSize());
    if (start_offset >= max_len) return diffs;

    uint64_t compare_len = (length > 0) ? std::min<uint64_t>(length, max_len - start_offset) : (max_len - start_offset);

    constexpr size_t BLOCK_SIZE = 4096;
    std::vector<uint8_t> buf1(BLOCK_SIZE);
    std::vector<uint8_t> buf2(BLOCK_SIZE);

    uint64_t compared = 0;
    while (compared < compare_len) {
        uint64_t curr_pos = start_offset + compared;
        size_t chunk = static_cast<size_t>(std::min<uint64_t>(BLOCK_SIZE, compare_len - compared));

        size_t read1 = dev1.ReadAt(curr_pos, buf1.data(), chunk);
        size_t read2 = dev2.ReadAt(curr_pos, buf2.data(), chunk);

        bool match = (read1 == read2 && std::memcmp(buf1.data(), buf2.data(), read1) == 0);

        if (!match) {
            DiffBlock block{};
            block.offset = curr_pos;
            block.length = chunk;
            block.is_different = true;
            diffs.push_back(block);

            if (diffs.size() >= 1000) break; // Bounded limit
        }

        compared += chunk;
        if (progress_fn) {
            if (!progress_fn(compared, compare_len)) break;
        }
    }

    return diffs;
}

} // namespace disk_analyzer
