#ifndef FILESYSTEM_HPP
#define FILESYSTEM_HPP

#include "block_device.hpp"
#include <string>
#include <vector>
#include <memory>
#include <cstdint>
#include <functional>

namespace disk_analyzer {

enum class FileType {
    Regular,
    Directory,
    Symlink,
    Special
};

struct FileEntry {
    std::string name;
    std::string path;
    FileType type{FileType::Regular};
    uint64_t size_bytes{0};
    uint64_t created_time{0};
    uint64_t modified_time{0};
    uint32_t cluster_or_inode{0};
    bool is_hidden{false};
    bool is_readonly{false};
    bool is_system{false};
};

class IFileSystem {
public:
    virtual ~IFileSystem() = default;

    virtual std::string GetFsName() const = 0;
    virtual uint64_t GetTotalSize() const = 0;
    virtual uint64_t GetFreeSpace() const = 0;

    virtual bool ReadDirectory(const std::string& path, std::vector<FileEntry>& out_entries) = 0;
    virtual size_t ReadFile(const FileEntry& entry, uint64_t offset, void* buffer, size_t size) = 0;

    // Streaming extraction callback: returns false if user cancelled or write failed
    using StreamProgressCallback = std::function<bool(uint64_t bytes_written, uint64_t total_bytes)>;

    virtual bool ExtractFile(const FileEntry& entry,
                             const std::function<bool(const void* data, size_t len)>& write_fn,
                             StreamProgressCallback progress_fn = nullptr) {
        constexpr size_t CHUNK_SIZE = 64 * 1024;
        std::vector<uint8_t> buffer(CHUNK_SIZE);
        uint64_t offset = 0;
        uint64_t total = entry.size_bytes;

        while (offset < total) {
            size_t to_read = static_cast<size_t>(std::min<uint64_t>(CHUNK_SIZE, total - offset));
            size_t read_bytes = ReadFile(entry, offset, buffer.data(), to_read);
            if (read_bytes == 0) {
                return false;
            }

            if (!write_fn(buffer.data(), read_bytes)) {
                return false;
            }

            offset += read_bytes;
            if (progress_fn) {
                if (!progress_fn(offset, total)) {
                    return false; // Cancelled
                }
            }
        }
        return true;
    }
};

class FileSystemFactory {
public:
    static std::shared_ptr<IFileSystem> ProbeAndOpen(std::shared_ptr<IBlockDevice> device);
};

} // namespace disk_analyzer

#endif // FILESYSTEM_HPP
