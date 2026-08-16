#include "qcow2_block_device.hpp"
#include <algorithm>
#include <cstring>
#include <zlib.h>

namespace disk_analyzer {

static uint32_t Swap32(uint32_t v) {
    return ((v >> 24) & 0xff) | ((v >> 8) & 0xff00) | ((v << 8) & 0xff0000) | ((v << 24) & 0xff000000);
}

static uint64_t Swap64(uint64_t v) {
    return ((v & 0x00000000000000ffULL) << 56) |
           ((v & 0x000000000000ff00ULL) << 40) |
           ((v & 0x0000000000ff0000ULL) << 24) |
           ((v & 0x00000000ff000000ULL) << 8)  |
           ((v & 0x000000ff00000000ULL) >> 8)  |
           ((v & 0x0000ff0000000000ULL) >> 24) |
           ((v & 0x00ff000000000000ULL) >> 40) |
           ((v & 0xff00000000000000ULL) >> 56);
}

static uint32_t Be32(uint32_t v) { return Swap32(v); }
static uint64_t Be64(uint64_t v) { return Swap64(v); }

std::shared_ptr<Qcow2BlockDevice> Qcow2BlockDevice::Open(std::shared_ptr<IBlockDevice> base_device) {
    if (!base_device || !base_device->IsValid()) {
        return nullptr;
    }
    auto qcow2 = std::make_shared<Qcow2BlockDevice>(base_device);
    if (!qcow2->IsValid()) {
        return nullptr;
    }
    return qcow2;
}

Qcow2BlockDevice::Qcow2BlockDevice(std::shared_ptr<IBlockDevice> base_device)
    : base_dev_(std::move(base_device)) {
    if (ParseHeader() && LoadL1Table()) {
        is_valid_ = true;
    }
}

bool Qcow2BlockDevice::ParseHeader() {
    if (!base_dev_ || base_dev_->GetSize() < 72) {
        return false;
    }

    uint8_t buf[104];
    size_t read_bytes = base_dev_->ReadAt(0, buf, sizeof(buf));
    if (read_bytes < 72) {
        return false;
    }

    std::memcpy(&header_.magic, buf, 4);
    header_.magic = Be32(header_.magic);
    if (header_.magic != 0x514649fb) { // "QFI\xfb"
        return false;
    }

    std::memcpy(&header_.version, buf + 4, 4);
    header_.version = Be32(header_.version);
    if (header_.version != 2 && header_.version != 3) {
        return false;
    }

    std::memcpy(&header_.backing_file_offset, buf + 8, 8);
    header_.backing_file_offset = Be64(header_.backing_file_offset);

    std::memcpy(&header_.backing_file_size, buf + 16, 4);
    header_.backing_file_size = Be32(header_.backing_file_size);

    std::memcpy(&header_.cluster_bits, buf + 20, 4);
    header_.cluster_bits = Be32(header_.cluster_bits);
    if (header_.cluster_bits < 9 || header_.cluster_bits > 21) { // 512B to 2MB clusters
        return false;
    }

    cluster_size_ = 1U << header_.cluster_bits;
    l2_entries_per_table_ = cluster_size_ / 8;

    std::memcpy(&header_.size, buf + 24, 8);
    header_.size = Be64(header_.size);

    std::memcpy(&header_.crypt_method, buf + 32, 4);
    header_.crypt_method = Be32(header_.crypt_method);

    std::memcpy(&header_.l1_size, buf + 36, 4);
    header_.l1_size = Be32(header_.l1_size);

    std::memcpy(&header_.l1_table_offset, buf + 40, 8);
    header_.l1_table_offset = Be64(header_.l1_table_offset);

    std::memcpy(&header_.refcount_table_offset, buf + 48, 8);
    header_.refcount_table_offset = Be64(header_.refcount_table_offset);

    std::memcpy(&header_.refcount_table_clusters, buf + 56, 4);
    header_.refcount_table_clusters = Be32(header_.refcount_table_clusters);

    std::memcpy(&header_.nb_snapshots, buf + 60, 4);
    header_.nb_snapshots = Be32(header_.nb_snapshots);

    std::memcpy(&header_.snapshots_offset, buf + 64, 8);
    header_.snapshots_offset = Be64(header_.snapshots_offset);

    if (header_.l1_size > 1024 * 1024) {
        return false;
    }

    return true;
}

bool Qcow2BlockDevice::LoadL1Table() {
    l1_table_.resize(header_.l1_size);
    if (header_.l1_size == 0) {
        return true;
    }

    size_t bytes_to_read = header_.l1_size * 8;
    std::vector<uint8_t> raw_l1(bytes_to_read);
    if (base_dev_->ReadAt(header_.l1_table_offset, raw_l1.data(), bytes_to_read) != bytes_to_read) {
        return false;
    }

    for (size_t i = 0; i < header_.l1_size; ++i) {
        uint64_t val;
        std::memcpy(&val, raw_l1.data() + i * 8, 8);
        l1_table_[i] = Be64(val);
    }

    return true;
}

const std::vector<uint64_t>& Qcow2BlockDevice::GetL2Table(uint64_t l1_index) {
    static const std::vector<uint64_t> empty_l2;

    if (l1_index >= l1_table_.size()) {
        return empty_l2;
    }

    uint64_t l1_entry = l1_table_[l1_index];
    uint64_t l2_offset = l1_entry & ~0x3fe00000000001ffULL;
    if (l2_offset == 0) {
        return empty_l2;
    }

    std::lock_guard<std::mutex> lock(cache_mutex_);
    auto it = l2_cache_.find(l1_index);
    if (it != l2_cache_.end()) {
        return it->second;
    }

    if (l2_cache_.size() >= MAX_L2_CACHE_ENTRIES) {
        l2_cache_.clear();
    }

    std::vector<uint64_t> l2_table(l2_entries_per_table_);
    size_t bytes_to_read = l2_entries_per_table_ * 8;
    std::vector<uint8_t> raw_l2(bytes_to_read);

    if (base_dev_->ReadAt(l2_offset, raw_l2.data(), bytes_to_read) == bytes_to_read) {
        for (size_t i = 0; i < l2_entries_per_table_; ++i) {
            uint64_t val;
            std::memcpy(&val, raw_l2.data() + i * 8, 8);
            l2_table[i] = Be64(val);
        }
    }

    auto inserted = l2_cache_.emplace(l1_index, std::move(l2_table));
    return inserted.first->second;
}

bool Qcow2BlockDevice::ReadCluster(uint64_t cluster_index, std::vector<uint8_t>& out_cluster) {
    out_cluster.assign(cluster_size_, 0);

    uint64_t l2_index = cluster_index % l2_entries_per_table_;
    uint64_t l1_index = cluster_index / l2_entries_per_table_;

    const auto& l2_table = GetL2Table(l1_index);
    if (l2_index >= l2_table.size()) {
        return true;
    }

    uint64_t l2_entry = l2_table[l2_index];

    if (l2_entry & (1ULL << 62)) {
        uint64_t csize_shift = 62 - (header_.cluster_bits - 8);
        uint64_t compressed_sector_offset = l2_entry & ((1ULL << csize_shift) - 1);
        uint64_t nb_sectors = ((l2_entry >> csize_shift) & ((1ULL << (header_.cluster_bits - 8)) - 1)) + 1;
        uint64_t comp_bytes = nb_sectors * 512;

        std::vector<uint8_t> comp_buf(comp_bytes);
        if (base_dev_->ReadAt(compressed_sector_offset * 512, comp_buf.data(), comp_bytes) == 0) {
            return false;
        }

        z_stream strm{};
        strm.next_in = comp_buf.data();
        strm.avail_in = static_cast<uInt>(comp_bytes);
        strm.next_out = out_cluster.data();
        strm.avail_out = static_cast<uInt>(cluster_size_);

        if (inflateInit2(&strm, -12) != Z_OK) {
            return false;
        }
        int ret = inflate(&strm, Z_FINISH);
        inflateEnd(&strm);

        return (ret == Z_STREAM_END || ret == Z_OK);
    }

    uint64_t cluster_offset = l2_entry & ~0xc0000000000001ffULL;
    if (cluster_offset == 0) {
        return true;
    }

    return base_dev_->ReadAt(cluster_offset, out_cluster.data(), cluster_size_) == cluster_size_;
}

size_t Qcow2BlockDevice::ReadAt(uint64_t offset, void* buffer, size_t size) {
    if (!is_valid_ || !buffer || offset >= header_.size) {
        return 0;
    }

    uint64_t bytes_to_read = std::min<uint64_t>(size, header_.size - offset);
    size_t total_read = 0;

    std::vector<uint8_t> cluster_buf;

    while (total_read < bytes_to_read) {
        uint64_t curr_pos = offset + total_read;
        uint64_t cluster_idx = curr_pos / cluster_size_;
        uint32_t cluster_off = curr_pos % cluster_size_;
        uint32_t chunk = std::min<uint32_t>(static_cast<uint32_t>(bytes_to_read - total_read), cluster_size_ - cluster_off);

        if (!ReadCluster(cluster_idx, cluster_buf)) {
            break;
        }

        std::memcpy(reinterpret_cast<uint8_t*>(buffer) + total_read, cluster_buf.data() + cluster_off, chunk);
        total_read += chunk;
    }

    return total_read;
}

uint64_t Qcow2BlockDevice::GetSize() const {
    return header_.size;
}

uint32_t Qcow2BlockDevice::GetBlockSize() const {
    return 512;
}

bool Qcow2BlockDevice::IsValid() const {
    return is_valid_;
}

} // namespace disk_analyzer
