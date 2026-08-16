#include <cstring>
#include <iostream>
#include <memory>
#include <vector>
#include "test_suite.hpp"
#include "block_device.hpp"
#include "report.hpp"

using namespace disk_analyzer;

void TestAnalysisReport() {
    std::cout << "Testing consolidated JSON analysis report..." << std::endl;

    std::vector<uint8_t> image(512 * 4096, 0);
    image[510] = 0x55;
    image[511] = 0xAA;
    uint8_t* entry = image.data() + 446;
    entry[4] = 0x0C;
    *reinterpret_cast<uint32_t*>(entry + 8) = 64;
    *reinterpret_cast<uint32_t*>(entry + 12) = 1024;
    std::memcpy(image.data() + 4096, "ANDROID!", 8);

    auto dev = std::make_shared<MemoryBlockDevice>(image, 512);
    ReportOptions options{};
    options.signature_scan_bytes = 128 * 1024;
    options.region_scan_bytes = 2 * 1024 * 1024;
    options.checksum_bytes = 1024 * 1024;
    auto report = AnalysisReportBuilder::BuildJson(dev, "synthetic.img", options);

    REQUIRE(report.find("\"report_schema\": \"disk-analyzer.analysis.v1\"") != std::string::npos);
    REQUIRE(report.find("\"image_name\": \"synthetic.img\"") != std::string::npos);
    REQUIRE(report.find("\"partitions\"") != std::string::npos);
    REQUIRE(report.find("\"signature_scan\"") != std::string::npos);
    REQUIRE(report.find("Android Boot") != std::string::npos);
    REQUIRE(report.find("\"region_scan\"") != std::string::npos);
    REQUIRE(report.find("\"checksums\"") != std::string::npos);

    std::cout << "Analysis Report Test Passed!" << std::endl;
}
