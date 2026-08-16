#include <iostream>
#include <string>
#include <vector>
#include <iomanip>

#include "disk_analyzer.h"
#include "block_device.hpp"
#include "dmg_e01_block_device.hpp"
#include "partition.hpp"
#include "filesystem.hpp"
#include "analysis.hpp"
#include "signature_scanner.hpp"
#include "report.hpp"

using namespace disk_analyzer;

void PrintUsage() {
    std::cout << "Usage: disk-analyzer <command> [options] <image_file>\n\n"
              << "Commands:\n"
              << "  info <image>              Show image details & partitions\n"
              << "  ls <image> [path]         List files in image filesystem\n"
              << "  search <image> <text>     Search text pattern in image\n"
              << "  hex <image> <offset>      Show hex dump at offset\n"
              << "  checksum <image>          Calculate CRC32, MD5, SHA256\n"
              << "  regions <image>           Classify image regions by entropy/content\n"
              << "  signatures <image>        Scan embedded file, firmware, archive signatures\n"
              << "  report <image>            Emit consolidated JSON analysis report\n";
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        PrintUsage();
        return 1;
    }

    std::string cmd = argv[1];
    std::string image_path = argv[argc - 1];

    std::shared_ptr<IBlockDevice> dev;
    auto base = RawBlockDevice::Open(image_path);
    if (base) {
        dev = ImageContainerFactory::AutoDetectAndOpen(base);
    }

    if (!dev || !dev->IsValid()) {
        std::cerr << "Error: Failed to open disk image " << image_path << std::endl;
        return 1;
    }

    if (cmd == "info") {
        std::cout << "=== Disk Image Information ===" << std::endl;
        std::cout << "File: " << image_path << std::endl;
        std::cout << "Size: " << dev->GetSize() << " bytes (" << (dev->GetSize() / (1024 * 1024)) << " MB)" << std::endl;
        std::cout << "Block Size: " << dev->GetBlockSize() << " bytes" << std::endl;

        auto fs_candidates = FileSystemFactory::ScanFilesystems(dev);
        std::cout << "\n=== Filesystems Detected (" << fs_candidates.size() << ") ===" << std::endl;
        for (const auto& fs : fs_candidates) {
            std::cout << " " << fs.fs_type
                      << " | Offset: 0x" << std::hex << fs.offset << std::dec
                      << " | Size: " << (fs.size_bytes / (1024 * 1024)) << " MB"
                      << " | Source: " << fs.source
                      << " | Confidence: " << fs.confidence << "%" << std::endl;
        }

        auto parts = PartitionTableParser::Parse(dev);
        std::cout << "\n=== Partitions Detected (" << parts.size() << ") ===" << std::endl;
        for (const auto& p : parts) {
            std::cout << " Partition " << p.index << ": " << p.name
                      << " | Start LBA: " << p.start_sector
                      << " | Count: " << p.sector_count
                      << " | Size: " << (p.size_bytes / (1024 * 1024)) << " MB"
                      << (p.bootable ? " [Bootable]" : "") << std::endl;
        }
    } else if (cmd == "ls") {
        std::string path = (argc >= 4 && argv[2] != image_path) ? argv[2] : "/";
        auto fs = FileSystemFactory::ProbeAndOpen(dev);
        if (!fs) {
            std::cerr << "Error: No supported filesystem detected." << std::endl;
            return 1;
        }

        std::cout << "=== Directory Listing for " << path << " (" << fs->GetFsName() << ") ===" << std::endl;
        std::vector<FileEntry> entries;
        if (fs->ReadDirectory(path, entries)) {
            for (const auto& e : entries) {
                std::cout << (e.type == FileType::Directory ? "[DIR]  " : "[FILE] ")
                          << std::setw(30) << std::left << e.name
                          << " " << e.size_bytes << " B" << std::endl;
            }
        }
    } else if (cmd == "search") {
        std::string text = argv[2];
        std::cout << "=== Searching for text: '" << text << "' ===" << std::endl;
        auto results = SearchEngine::SearchText(*dev, text);
        std::cout << "Found " << results.size() << " match(es):" << std::endl;
        for (const auto& r : results) {
            std::cout << " Offset 0x" << std::hex << r.offset << std::dec
                      << ": " << r.context_snippet << std::endl;
        }
    } else if (cmd == "report") {
        std::cout << AnalysisReportBuilder::BuildJson(dev, image_path);
    } else if (cmd == "signatures") {
        std::cout << "=== Signature Scan ===" << std::endl;
        auto hits = SignatureScanner::Scan(*dev, 0, std::min<uint64_t>(dev->GetSize(), 256 * 1024 * 1024), 256);
        std::cout << "Found " << hits.size() << " signature hit(s):" << std::endl;
        for (const auto& hit : hits) {
            std::cout << " Offset 0x" << std::hex << hit.offset << std::dec
                      << " | " << hit.format
                      << " | " << hit.category
                      << " | confidence=" << hit.confidence << "%"
                      << " | " << hit.description << std::endl;
        }
    } else if (cmd == "checksum") {
        std::cout << "=== Calculating Checksums ===" << std::endl;
        auto cs = BinaryAnalyzer::CalculateChecksums(*dev, 0, std::min<uint64_t>(dev->GetSize(), 10 * 1024 * 1024));
        std::cout << "CRC32:  0x" << std::hex << cs.crc32 << std::dec << std::endl;
        std::cout << "MD5:    " << cs.md5_hex << std::endl;
        std::cout << "SHA256: " << cs.sha256_hex << std::endl;
    } else if (cmd == "regions") {
        std::cout << "=== Region Classification ===" << std::endl;
        auto regions = RegionInspector::ClassifyRegions(*dev, 0, dev->GetSize(), 1024 * 1024, 128);
        for (const auto& region : regions) {
            std::cout << " Offset 0x" << std::hex << region.offset << std::dec
                      << " | " << region.length << " B"
                      << " | " << RegionInspector::RegionKindName(region.kind)
                      << " | entropy=" << std::fixed << std::setprecision(3) << region.entropy
                      << " | printable=" << std::setprecision(1) << (region.printable_ratio * 100.0) << "%"
                      << " | dominant=0x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(region.dominant_byte)
                      << std::dec << std::setfill(' ') << " (" << std::setprecision(1) << (region.dominant_ratio * 100.0) << "%)"
                      << std::endl;
        }
    } else {
        PrintUsage();
        return 1;
    }

    return 0;
}
