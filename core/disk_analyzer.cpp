#include "disk_analyzer.h"
#include "block_device.hpp"
#include "qcow2_block_device.hpp"
#include "vhd_vmdk_vdi_block_device.hpp"
#include "partition.hpp"
#include "filesystem.hpp"
#include "analysis.hpp"
#include "carving.hpp"
#include "diff_engine.hpp"

#include <cstring>
#include <fstream>
#include <memory>
#include <vector>

using namespace disk_analyzer;

struct DiskDeviceHandle {
    std::shared_ptr<IBlockDevice> dev;
};

struct DiskFsHandle {
    std::shared_ptr<IFileSystem> fs;
    std::string fs_name_cache;
};

const char* disk_analyzer_version(void) {
    return "0.1.0";
}

DiskDeviceHandle* disk_analyzer_open_raw(const char* filepath) {
    if (!filepath) return nullptr;
    try {
        auto dev = RawBlockDevice::Open(filepath);
        if (!dev) return nullptr;
        return new DiskDeviceHandle{dev};
    } catch (...) {
        return nullptr;
    }
}

DiskDeviceHandle* disk_analyzer_open_qcow2(const char* filepath) {
    if (!filepath) return nullptr;
    try {
        auto base = RawBlockDevice::Open(filepath);
        if (!base) return nullptr;
        auto qcow2 = Qcow2BlockDevice::Open(base);
        if (!qcow2) return nullptr;
        return new DiskDeviceHandle{qcow2};
    } catch (...) {
        return nullptr;
    }
}

DiskDeviceHandle* disk_analyzer_open_vhd(const char* filepath) {
    if (!filepath) return nullptr;
    try {
        auto base = RawBlockDevice::Open(filepath);
        if (!base) return nullptr;
        auto vhd = VhdBlockDevice::Open(base);
        if (!vhd) return nullptr;
        return new DiskDeviceHandle{vhd};
    } catch (...) {
        return nullptr;
    }
}

DiskDeviceHandle* disk_analyzer_open_vmdk(const char* filepath) {
    if (!filepath) return nullptr;
    try {
        auto base = RawBlockDevice::Open(filepath);
        if (!base) return nullptr;
        auto vmdk = VmdkBlockDevice::Open(base);
        if (!vmdk) return nullptr;
        return new DiskDeviceHandle{vmdk};
    } catch (...) {
        return nullptr;
    }
}

DiskDeviceHandle* disk_analyzer_open_vdi(const char* filepath) {
    if (!filepath) return nullptr;
    try {
        auto base = RawBlockDevice::Open(filepath);
        if (!base) return nullptr;
        auto vdi = VdiBlockDevice::Open(base);
        if (!vdi) return nullptr;
        return new DiskDeviceHandle{vdi};
    } catch (...) {
        return nullptr;
    }
}

void disk_analyzer_close_device(DiskDeviceHandle* handle) {
    if (handle) {
        delete handle;
    }
}

uint64_t disk_analyzer_device_get_size(DiskDeviceHandle* handle) {
    if (!handle || !handle->dev) return 0;
    return handle->dev->GetSize();
}

uint32_t disk_analyzer_device_get_block_size(DiskDeviceHandle* handle) {
    if (!handle || !handle->dev) return 512;
    return handle->dev->GetBlockSize();
}

size_t disk_analyzer_device_read_at(DiskDeviceHandle* handle, uint64_t offset, void* buffer, size_t size) {
    if (!handle || !handle->dev || !buffer) return 0;
    return handle->dev->ReadAt(offset, buffer, size);
}

size_t disk_analyzer_get_partitions(DiskDeviceHandle* handle, CPartitionInfo* out_partitions, size_t max_count) {
    if (!handle || !handle->dev || !out_partitions || max_count == 0) return 0;

    auto parts = PartitionTableParser::Parse(handle->dev);
    size_t count = std::min(max_count, parts.size());

    for (size_t i = 0; i < count; ++i) {
        const auto& src = parts[i];
        CPartitionInfo& dst = out_partitions[i];
        dst.index = src.index;
        dst.start_sector = src.start_sector;
        dst.sector_count = src.sector_count;
        dst.size_bytes = src.size_bytes;
        dst.mbr_type = src.mbr_type;
        dst.bootable = src.bootable;

        std::strncpy(dst.name, src.name.c_str(), sizeof(dst.name) - 1);
        dst.name[sizeof(dst.name) - 1] = '\0';

        std::strncpy(dst.type_guid, src.type_guid.c_str(), sizeof(dst.type_guid) - 1);
        dst.type_guid[sizeof(dst.type_guid) - 1] = '\0';
    }

    return count;
}

DiskFsHandle* disk_analyzer_open_filesystem(DiskDeviceHandle* handle, uint64_t partition_offset, uint64_t partition_size) {
    if (!handle || !handle->dev) return nullptr;

    try {
        std::shared_ptr<IBlockDevice> target_dev = handle->dev;
        if (partition_size > 0) {
            target_dev = std::make_shared<OffsetBlockDevice>(handle->dev, partition_offset, partition_size);
        }

        auto fs = FileSystemFactory::ProbeAndOpen(target_dev);
        if (!fs) return nullptr;

        return new DiskFsHandle{fs, fs->GetFsName()};
    } catch (...) {
        return nullptr;
    }
}

void disk_analyzer_close_filesystem(DiskFsHandle* fs_handle) {
    if (fs_handle) {
        delete fs_handle;
    }
}

const char* disk_analyzer_fs_get_name(DiskFsHandle* fs_handle) {
    if (!fs_handle || !fs_handle->fs) return "Unknown";
    return fs_handle->fs_name_cache.c_str();
}

size_t disk_analyzer_fs_list_directory(DiskFsHandle* fs_handle, const char* path, CFileEntry* out_entries, size_t max_count) {
    if (!fs_handle || !fs_handle->fs || !out_entries || max_count == 0) return 0;

    std::vector<FileEntry> entries;
    if (!fs_handle->fs->ReadDirectory(path ? path : "/", entries)) {
        return 0;
    }

    size_t count = std::min(max_count, entries.size());
    for (size_t i = 0; i < count; ++i) {
        const auto& src = entries[i];
        CFileEntry& dst = out_entries[i];

        std::strncpy(dst.name, src.name.c_str(), sizeof(dst.name) - 1);
        dst.name[sizeof(dst.name) - 1] = '\0';

        std::strncpy(dst.path, src.path.c_str(), sizeof(dst.path) - 1);
        dst.path[sizeof(dst.path) - 1] = '\0';

        dst.is_directory = (src.type == FileType::Directory);
        dst.size_bytes = src.size_bytes;
        dst.cluster_or_inode = src.cluster_or_inode;
    }

    return count;
}

bool disk_analyzer_fs_extract_file(DiskFsHandle* fs_handle, const char* file_path, const char* dest_path) {
    if (!fs_handle || !fs_handle->fs || !file_path || !dest_path) return false;

    std::string path_str(file_path);
    size_t last_slash = path_str.find_last_of('/');
    std::string dir_path = (last_slash == std::string::npos) ? "/" : path_str.substr(0, last_slash);
    std::string target_name = (last_slash == std::string::npos) ? path_str : path_str.substr(last_slash + 1);

    std::vector<FileEntry> entries;
    if (!fs_handle->fs->ReadDirectory(dir_path.empty() ? "/" : dir_path, entries)) {
        return false;
    }

    const FileEntry* target_entry = nullptr;
    for (const auto& entry : entries) {
        if (entry.name == target_name) {
            target_entry = &entry;
            break;
        }
    }

    if (!target_entry) return false;

    std::ofstream out_file(dest_path, std::ios::binary);
    if (!out_file.is_open()) return false;

    return fs_handle->fs->ExtractFile(*target_entry, [&](const void* chunk, size_t len) {
        out_file.write(reinterpret_cast<const char*>(chunk), len);
        return out_file.good();
    });
}

size_t disk_analyzer_get_hex_view(DiskDeviceHandle* handle, uint64_t offset, size_t size, CHexRow* out_rows, size_t max_rows) {
    if (!handle || !handle->dev || !out_rows || max_rows == 0) return 0;

    auto rows = HexAnalyzer::GetHexView(*handle->dev, offset, size, 16);
    size_t count = std::min(max_rows, rows.size());

    for (size_t i = 0; i < count; ++i) {
        out_rows[i].offset = rows[i].offset;
        out_rows[i].byte_count = rows[i].bytes.size();
        std::memcpy(out_rows[i].bytes, rows[i].bytes.data(), rows[i].bytes.size());

        std::strncpy(out_rows[i].ascii_dump, rows[i].ascii_dump.c_str(), sizeof(out_rows[i].ascii_dump) - 1);
        out_rows[i].ascii_dump[sizeof(out_rows[i].ascii_dump) - 1] = '\0';
    }

    return count;
}

size_t disk_analyzer_search_text(DiskDeviceHandle* handle, const char* query, bool case_sensitive, CSearchResult* out_results, size_t max_results) {
    if (!handle || !handle->dev || !query || !out_results || max_results == 0) return 0;

    auto results = SearchEngine::SearchText(*handle->dev, query, case_sensitive);
    size_t count = std::min(max_results, results.size());

    for (size_t i = 0; i < count; ++i) {
        out_results[i].offset = results[i].offset;
        out_results[i].match_length = results[i].match_length;
        std::strncpy(out_results[i].snippet, results[i].context_snippet.c_str(), sizeof(out_results[i].snippet) - 1);
        out_results[i].snippet[sizeof(out_results[i].snippet) - 1] = '\0';
    }

    return count;
}

double disk_analyzer_calculate_entropy(DiskDeviceHandle* handle, uint64_t offset, size_t size) {
    if (!handle || !handle->dev) return 0.0;
    std::vector<uint8_t> buffer(size);
    size_t read_bytes = handle->dev->ReadAt(offset, buffer.data(), size);
    return BinaryAnalyzer::CalculateEntropy(buffer.data(), read_bytes);
}

bool disk_analyzer_calculate_checksums(DiskDeviceHandle* handle, uint64_t offset, size_t size, CChecksumResult* out_checksums) {
    if (!handle || !handle->dev || !out_checksums) return false;

    auto res = BinaryAnalyzer::CalculateChecksums(*handle->dev, offset, size);
    out_checksums->crc32 = res.crc32;

    std::strncpy(out_checksums->md5_hex, res.md5_hex.c_str(), sizeof(out_checksums->md5_hex) - 1);
    out_checksums->md5_hex[sizeof(out_checksums->md5_hex) - 1] = '\0';

    std::strncpy(out_checksums->sha256_hex, res.sha256_hex.c_str(), sizeof(out_checksums->sha256_hex) - 1);
    out_checksums->sha256_hex[sizeof(out_checksums->sha256_hex) - 1] = '\0';

    return true;
}

const char* disk_analyzer_detect_magic(DiskDeviceHandle* handle, uint64_t offset) {
    if (!handle || !handle->dev) return "Unknown";
    uint8_t header[16];
    size_t read_bytes = handle->dev->ReadAt(offset, header, sizeof(header));
    static std::string magic;
    magic = BinaryAnalyzer::DetectMagicSignature(header, read_bytes);
    return magic.c_str();
}

size_t disk_analyzer_carve_files(DiskDeviceHandle* handle, uint64_t offset, uint64_t length, CCarvedFile* out_carved, size_t max_count) {
    if (!handle || !handle->dev || !out_carved || max_count == 0) return 0;

    auto carved = FileCarver::CarveFiles(*handle->dev, offset, length);
    size_t count = std::min(max_count, carved.size());

    for (size_t i = 0; i < count; ++i) {
        out_carved[i].offset = carved[i].offset;
        out_carved[i].size_bytes = carved[i].size_bytes;

        std::strncpy(out_carved[i].file_type, carved[i].file_type.c_str(), sizeof(out_carved[i].file_type) - 1);
        out_carved[i].file_type[sizeof(out_carved[i].file_type) - 1] = '\0';

        std::strncpy(out_carved[i].extension, carved[i].suggested_extension.c_str(), sizeof(out_carved[i].extension) - 1);
        out_carved[i].extension[sizeof(out_carved[i].extension) - 1] = '\0';
    }

    return count;
}

size_t disk_analyzer_diff_devices(DiskDeviceHandle* handle1, DiskDeviceHandle* handle2, uint64_t offset, uint64_t length, CDiffBlock* out_diffs, size_t max_count) {
    if (!handle1 || !handle1->dev || !handle2 || !handle2->dev || !out_diffs || max_count == 0) return 0;

    auto diffs = DiffEngine::CompareDevices(*handle1->dev, *handle2->dev, offset, length);
    size_t count = std::min(max_count, diffs.size());

    for (size_t i = 0; i < count; ++i) {
        out_diffs[i].offset = diffs[i].offset;
        out_diffs[i].length = diffs[i].length;
        out_diffs[i].is_different = diffs[i].is_different;
    }

    return count;
}
