#ifndef DISK_ANALYZER_H
#define DISK_ANALYZER_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum DiskAnalyzerStatus {
    DISK_ANALYZER_SUCCESS = 0,
    DISK_ANALYZER_ERROR_INVALID_ARGUMENT = 1,
    DISK_ANALYZER_ERROR_IO_ERROR = 2,
    DISK_ANALYZER_ERROR_OUT_OF_BOUNDS = 3,
    DISK_ANALYZER_ERROR_UNSUPPORTED_FORMAT = 4,
    DISK_ANALYZER_ERROR_CORRUPT_METADATA = 5,
    DISK_ANALYZER_ERROR_ALLOCATION_FAILED = 6,
    DISK_ANALYZER_ERROR_UNKNOWN = 99
} DiskAnalyzerStatus;

typedef struct DiskDeviceHandle DiskDeviceHandle;
typedef struct DiskFsHandle DiskFsHandle;

typedef struct CPartitionInfo {
    uint32_t index;
    uint64_t start_sector;
    uint64_t sector_count;
    uint64_t size_bytes;
    uint8_t mbr_type;
    bool bootable;
    char name[64];
    char type_guid[40];
} CPartitionInfo;

typedef struct CFileEntry {
    char name[256];
    char path[1024];
    bool is_directory;
    uint64_t size_bytes;
    uint64_t cluster_or_inode;
} CFileEntry;

typedef struct CHexRow {
    uint64_t offset;
    uint8_t bytes[16];
    size_t byte_count;
    char ascii_dump[17];
} CHexRow;

typedef struct CSearchResult {
    uint64_t offset;
    size_t match_length;
    char snippet[32];
} CSearchResult;

typedef struct CChecksumResult {
    uint32_t crc32;
    char md5_hex[33];
    char sha256_hex[65];
} CChecksumResult;

typedef struct CCarvedFile {
    uint64_t offset;
    uint64_t size_bytes;
    char file_type[32];
    char extension[8];
} CCarvedFile;

typedef struct CDiffBlock {
    uint64_t offset;
    size_t length;
    bool is_different;
} CDiffBlock;

// API functions
const char* disk_analyzer_version(void);

DiskDeviceHandle* disk_analyzer_open_raw(const char* filepath);
DiskDeviceHandle* disk_analyzer_open_qcow2(const char* filepath);
DiskDeviceHandle* disk_analyzer_open_vhd(const char* filepath);
DiskDeviceHandle* disk_analyzer_open_vmdk(const char* filepath);
DiskDeviceHandle* disk_analyzer_open_vdi(const char* filepath);
void disk_analyzer_close_device(DiskDeviceHandle* handle);

uint64_t disk_analyzer_device_get_size(DiskDeviceHandle* handle);
uint32_t disk_analyzer_device_get_block_size(DiskDeviceHandle* handle);
size_t disk_analyzer_device_read_at(DiskDeviceHandle* handle, uint64_t offset, void* buffer, size_t size);

size_t disk_analyzer_get_partitions(DiskDeviceHandle* handle, CPartitionInfo* out_partitions, size_t max_count);

DiskFsHandle* disk_analyzer_open_filesystem(DiskDeviceHandle* handle, uint64_t partition_offset, uint64_t partition_size);
void disk_analyzer_close_filesystem(DiskFsHandle* fs_handle);

const char* disk_analyzer_fs_get_name(DiskFsHandle* fs_handle);
size_t disk_analyzer_fs_list_directory(DiskFsHandle* fs_handle, const char* path, CFileEntry* out_entries, size_t max_count);

bool disk_analyzer_fs_extract_file(DiskFsHandle* fs_handle, const char* file_path, const char* dest_path);

size_t disk_analyzer_get_hex_view(DiskDeviceHandle* handle, uint64_t offset, size_t size, CHexRow* out_rows, size_t max_rows);
size_t disk_analyzer_search_text(DiskDeviceHandle* handle, const char* query, bool case_sensitive, CSearchResult* out_results, size_t max_results);
double disk_analyzer_calculate_entropy(DiskDeviceHandle* handle, uint64_t offset, size_t size);
bool disk_analyzer_calculate_checksums(DiskDeviceHandle* handle, uint64_t offset, size_t size, CChecksumResult* out_checksums);
const char* disk_analyzer_detect_magic(DiskDeviceHandle* handle, uint64_t offset);

size_t disk_analyzer_carve_files(DiskDeviceHandle* handle, uint64_t offset, uint64_t length, CCarvedFile* out_carved, size_t max_count);
size_t disk_analyzer_diff_devices(DiskDeviceHandle* handle1, DiskDeviceHandle* handle2, uint64_t offset, uint64_t length, CDiffBlock* out_diffs, size_t max_count);

#ifdef __cplusplus
}
#endif

#endif // DISK_ANALYZER_H
