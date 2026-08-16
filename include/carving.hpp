#ifndef CARVING_HPP
#define CARVING_HPP

#include "block_device.hpp"
#include <string>
#include <vector>
#include <memory>
#include <functional>

namespace disk_analyzer {

struct CarvedFile {
    uint64_t offset;
    uint64_t size_bytes;
    std::string file_type;
    std::string suggested_extension;
};

class FileCarver {
public:
    using ProgressCallback = std::function<bool(uint64_t bytes_scanned, uint64_t total_bytes)>;

    static std::vector<CarvedFile> CarveFiles(IBlockDevice& device,
                                              uint64_t start_offset = 0,
                                              uint64_t length = 0,
                                              ProgressCallback progress_fn = nullptr);
};

} // namespace disk_analyzer

#endif // CARVING_HPP
