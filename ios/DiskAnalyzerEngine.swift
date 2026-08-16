import Foundation

public struct PartitionModel: Identifiable {
    public let id: UInt32
    public let index: UInt32
    public let startSector: UInt64
    public let sectorCount: UInt64
    public let sizeBytes: UInt64
    public let name: String
    public let typeGuid: String
    public let bootable: Bool
}

public struct FileEntryModel: Identifiable {
    public var id: String { path }
    public let name: String
    public let path: String
    public let isDirectory: Bool
    public let sizeBytes: UInt64
}

public struct SearchResultModel: Identifiable {
    public var id: UInt64 { offset }
    public let offset: UInt64
    public let length: Int
    public let snippet: String
}

public class DiskAnalyzerEngine: ObservableObject {
    private var deviceHandle: OpaquePointer?
    private var fsHandle: OpaquePointer?

    @Published public var isLoaded: Bool = false
    @Published public var totalSize: UInt64 = 0
    @Published public var partitions: [PartitionModel] = []
    @Published public var currentPathFiles: [FileEntryModel] = []
    @Published public var searchResults: [SearchResultModel] = []

    public init() {}

    deinit {
        close()
    }

    public func openRawImage(path: String) -> Bool {
        close()
        guard let handle = disk_analyzer_open_raw(path) else { return false }
        self.deviceHandle = handle
        self.totalSize = disk_analyzer_device_get_size(handle)
        self.isLoaded = true
        loadPartitions()
        return true
    }

    public func openQcow2Image(path: String) -> Bool {
        close()
        guard let handle = disk_analyzer_open_qcow2(path) else { return false }
        self.deviceHandle = handle
        self.totalSize = disk_analyzer_device_get_size(handle)
        self.isLoaded = true
        loadPartitions()
        return true
    }

    public func close() {
        if let fs = fsHandle {
            disk_analyzer_close_filesystem(fs)
            fsHandle = nil
        }
        if let dev = deviceHandle {
            disk_analyzer_close_device(dev)
            deviceHandle = nil
        }
        isLoaded = false
        partitions.removeAll()
        currentPathFiles.removeAll()
    }

    public func loadPartitions() {
        guard let dev = deviceHandle else { return }
        var cPartitions = [CPartitionInfo](repeating: CPartitionInfo(), count: 16)
        let count = disk_analyzer_get_partitions(dev, &cPartitions, 16)

        partitions = (0..<count).map { i in
            let p = cPartitions[i]
            let name = withUnsafeBytes(of: p.name) { String(cString: $0.baseAddress!.assumingMemoryBound(to: CChar.self)) }
            let guid = withUnsafeBytes(of: p.type_guid) { String(cString: $0.baseAddress!.assumingMemoryBound(to: CChar.self)) }
            return PartitionModel(
                id: p.index,
                index: p.index,
                startSector: p.start_sector,
                sectorCount: p.sector_count,
                sizeBytes: p.size_bytes,
                name: name,
                typeGuid: guid,
                bootable: p.bootable
            )
        }
    }

    public func mountFilesystem(partitionOffset: UInt64, partitionSize: UInt64) -> Bool {
        guard let dev = deviceHandle else { return false }
        if let fs = fsHandle {
            disk_analyzer_close_filesystem(fs)
            fsHandle = nil
        }
        guard let fs = disk_analyzer_open_filesystem(dev, partitionOffset, partitionSize) else { return false }
        self.fsHandle = fs
        return true
    }

    public func listDirectory(path: String) {
        guard let fs = fsHandle else { return }
        var cEntries = [CFileEntry](repeating: CFileEntry(), count: 256)
        let count = disk_analyzer_fs_list_directory(fs, path, &cEntries, 256)

        currentPathFiles = (0..<count).map { i in
            let e = cEntries[i]
            let name = withUnsafeBytes(of: e.name) { String(cString: $0.baseAddress!.assumingMemoryBound(to: CChar.self)) }
            let path = withUnsafeBytes(of: e.path) { String(cString: $0.baseAddress!.assumingMemoryBound(to: CChar.self)) }
            return FileEntryModel(
                name: name,
                path: path,
                isDirectory: e.is_directory,
                sizeBytes: e.size_bytes
            )
        }
    }

    public func search(query: String, caseSensitive: Bool) {
        guard let dev = deviceHandle else { return }
        var cResults = [CSearchResult](repeating: CSearchResult(), count: 100)
        let count = disk_analyzer_search_text(dev, query, caseSensitive, &cResults, 100)

        searchResults = (0..<count).map { i in
            let r = cResults[i]
            let snip = withUnsafeBytes(of: r.snippet) { String(cString: $0.baseAddress!.assumingMemoryBound(to: CChar.self)) }
            return SearchResultModel(offset: r.offset, length: r.match_length, snippet: snip)
        }
    }
}
