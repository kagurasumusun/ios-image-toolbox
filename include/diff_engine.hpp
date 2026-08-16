#ifndef DIFF_ENGINE_HPP
#define DIFF_ENGINE_HPP

#include "block_device.hpp"
#include <vector>
#include <memory>
#include <cstdint>
#include <functional>

namespace disk_analyzer {

struct DiffBlock {
    uint64_t offset;
    size_t length;
    bool is_different;
};

class DiffEngine {
public:
    using ProgressCallback = std::function<bool(uint64_t bytes_compared, uint64_t total_bytes)>;

    static std::vector<DiffBlock> CompareDevices(IBlockDevice& dev1,
                                                 IBlockDevice& dev2,
                                                 uint64_t start_offset = 0,
                                                 uint64_t length = 0,
                                                 ProgressCallback progress_fn = nullptr);
};

} // namespace disk_analyzer

#endif // DIFF_ENGINE_HPP
