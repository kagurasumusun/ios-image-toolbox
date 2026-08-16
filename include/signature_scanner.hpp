#ifndef SIGNATURE_SCANNER_HPP
#define SIGNATURE_SCANNER_HPP

#include "block_device.hpp"
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace disk_analyzer {

struct SignatureHit {
    uint64_t offset{0};
    std::string format;
    std::string category;
    std::string description;
    std::string extension;
    uint32_t confidence{0};
};

class SignatureScanner {
public:
    using ProgressCallback = std::function<bool(uint64_t bytes_scanned, uint64_t total_bytes)>;

    static std::vector<SignatureHit> Scan(IBlockDevice& device,
                                          uint64_t start_offset = 0,
                                          uint64_t length = 0,
                                          size_t max_hits = 512,
                                          ProgressCallback progress_fn = nullptr);
};

} // namespace disk_analyzer

#endif // SIGNATURE_SCANNER_HPP
