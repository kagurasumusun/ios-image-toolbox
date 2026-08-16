#include "report.hpp"
#include "analysis.hpp"
#include "filesystem.hpp"
#include "partition.hpp"
#include "signature_scanner.hpp"
#include <algorithm>
#include <iomanip>
#include <sstream>

namespace disk_analyzer {
namespace {

std::string JsonEscape(const std::string& value) {
    std::ostringstream out;
    for (unsigned char c : value) {
        switch (c) {
            case '"': out << "\\\""; break;
            case '\\': out << "\\\\"; break;
            case '\b': out << "\\b"; break;
            case '\f': out << "\\f"; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default:
                if (c < 0x20) {
                    out << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c) << std::dec << std::setfill(' ');
                } else {
                    out << static_cast<char>(c);
                }
        }
    }
    return out.str();
}

void AppendJsonString(std::ostringstream& out, const std::string& value) {
    out << '"' << JsonEscape(value) << '"';
}

uint64_t BoundedLength(uint64_t device_size, uint64_t requested) {
    return requested == 0 ? device_size : std::min<uint64_t>(requested, device_size);
}

} // namespace

std::string AnalysisReportBuilder::BuildJson(std::shared_ptr<IBlockDevice> device,
                                             const std::string& image_name,
                                             const ReportOptions& options) {
    std::ostringstream out;
    out << std::boolalpha;
    out << "{\n";
    out << "  \"report_schema\": \"disk-analyzer.analysis.v1\",\n";
    out << "  \"image_name\": ";
    AppendJsonString(out, image_name);
    out << ",\n";

    if (!device || !device->IsValid()) {
        out << "  \"valid\": false,\n";
        out << "  \"error\": \"invalid or unreadable block device\"\n";
        out << "}\n";
        return out.str();
    }

    const uint64_t device_size = device->GetSize();
    out << "  \"valid\": true,\n";
    out << "  \"device\": {\n";
    out << "    \"size_bytes\": " << device_size << ",\n";
    out << "    \"block_size\": " << device->GetBlockSize() << ",\n";
    uint8_t header[16]{};
    const size_t header_read = device->ReadAt(0, header, sizeof(header));
    out << "    \"magic\": ";
    AppendJsonString(out, BinaryAnalyzer::DetectMagicSignature(header, header_read));
    out << "\n  },\n";

    const auto partitions = PartitionTableParser::Parse(device);
    out << "  \"partitions\": [\n";
    for (size_t i = 0; i < partitions.size(); ++i) {
        const auto& p = partitions[i];
        out << "    {\"index\": " << p.index
            << ", \"start_sector\": " << p.start_sector
            << ", \"sector_count\": " << p.sector_count
            << ", \"size_bytes\": " << p.size_bytes
            << ", \"bootable\": " << (p.bootable ? "true" : "false")
            << ", \"name\": ";
        AppendJsonString(out, p.name);
        out << ", \"type_guid\": ";
        AppendJsonString(out, p.type_guid);
        out << "}" << (i + 1 == partitions.size() ? "" : ",") << "\n";
    }
    out << "  ],\n";

    const auto filesystems = FileSystemFactory::ScanFilesystems(device);
    out << "  \"filesystem_candidates\": [\n";
    for (size_t i = 0; i < filesystems.size(); ++i) {
        const auto& fs = filesystems[i];
        out << "    {\"offset\": " << fs.offset
            << ", \"size_bytes\": " << fs.size_bytes
            << ", \"confidence\": " << fs.confidence
            << ", \"fs_type\": ";
        AppendJsonString(out, fs.fs_type);
        out << ", \"source\": ";
        AppendJsonString(out, fs.source);
        out << "}" << (i + 1 == filesystems.size() ? "" : ",") << "\n";
    }
    out << "  ],\n";

    const uint64_t signature_len = BoundedLength(device_size, options.signature_scan_bytes);
    const auto signatures = SignatureScanner::Scan(*device, 0, signature_len, options.max_signature_hits);
    out << "  \"signature_scan\": {\n";
    out << "    \"scanned_bytes\": " << signature_len << ",\n";
    out << "    \"hits\": [\n";
    for (size_t i = 0; i < signatures.size(); ++i) {
        const auto& hit = signatures[i];
        out << "      {\"offset\": " << hit.offset << ", \"confidence\": " << hit.confidence << ", \"format\": ";
        AppendJsonString(out, hit.format);
        out << ", \"category\": ";
        AppendJsonString(out, hit.category);
        out << ", \"description\": ";
        AppendJsonString(out, hit.description);
        out << ", \"extension\": ";
        AppendJsonString(out, hit.extension);
        out << "}" << (i + 1 == signatures.size() ? "" : ",") << "\n";
    }
    out << "    ]\n  },\n";

    const uint64_t region_len = BoundedLength(device_size, options.region_scan_bytes);
    const auto regions = RegionInspector::ClassifyRegions(*device, 0, region_len, 1024 * 1024, options.max_regions);
    out << "  \"region_scan\": {\n";
    out << "    \"scanned_bytes\": " << region_len << ",\n";
    out << "    \"regions\": [\n";
    for (size_t i = 0; i < regions.size(); ++i) {
        const auto& r = regions[i];
        out << "      {\"offset\": " << r.offset
            << ", \"length\": " << r.length
            << ", \"entropy\": " << std::fixed << std::setprecision(6) << r.entropy
            << ", \"printable_ratio\": " << r.printable_ratio
            << ", \"dominant_byte\": " << static_cast<unsigned>(r.dominant_byte)
            << ", \"dominant_ratio\": " << r.dominant_ratio
            << ", \"kind\": ";
        AppendJsonString(out, RegionInspector::RegionKindName(r.kind));
        out << "}" << (i + 1 == regions.size() ? "" : ",") << "\n";
    }
    out << "    ]\n  },\n";

    const uint64_t checksum_len = BoundedLength(device_size, options.checksum_bytes);
    const auto checksums = BinaryAnalyzer::CalculateChecksums(*device, 0, static_cast<size_t>(checksum_len));
    out << "  \"checksums\": {\n";
    out << "    \"scanned_bytes\": " << checksum_len << ",\n";
    out << "    \"crc32\": " << checksums.crc32 << ",\n";
    out << "    \"md5\": ";
    AppendJsonString(out, checksums.md5_hex);
    out << ",\n";
    out << "    \"sha256\": ";
    AppendJsonString(out, checksums.sha256_hex);
    out << "\n  }\n";

    out << "}\n";
    return out.str();
}

} // namespace disk_analyzer
