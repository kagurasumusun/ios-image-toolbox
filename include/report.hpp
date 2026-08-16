#ifndef REPORT_HPP
#define REPORT_HPP

#include "block_device.hpp"
#include <cstdint>
#include <memory>
#include <string>

namespace disk_analyzer {

struct ReportOptions {
    uint64_t signature_scan_bytes{256ULL * 1024ULL * 1024ULL};
    uint64_t region_scan_bytes{64ULL * 1024ULL * 1024ULL};
    uint64_t checksum_bytes{64ULL * 1024ULL * 1024ULL};
    size_t max_signature_hits{256};
    size_t max_regions{128};
};

class AnalysisReportBuilder {
public:
    static std::string BuildJson(std::shared_ptr<IBlockDevice> device,
                                 const std::string& image_name,
                                 const ReportOptions& options = ReportOptions{});
};

} // namespace disk_analyzer

#endif // REPORT_HPP
