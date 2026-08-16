#include "filesystem.hpp"
#include "fat_filesystem.hpp"
#include "iso9660_filesystem.hpp"

namespace disk_analyzer {

std::shared_ptr<IFileSystem> FileSystemFactory::ProbeAndOpen(std::shared_ptr<IBlockDevice> device) {
    if (!device || !device->IsValid()) {
        return nullptr;
    }

    auto fat = FatFileSystem::Open(device);
    if (fat) return fat;

    auto iso = Iso9660FileSystem::Open(device);
    if (iso) return iso;

    return nullptr;
}

} // namespace disk_analyzer
