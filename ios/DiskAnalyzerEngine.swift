import Foundation

public struct PartitionModel: Identifiable, Hashable {
    public let id: UInt32
    public let index: UInt32
    public let startSector: UInt64
    public let sectorCount: UInt64
    public let sizeBytes: UInt64
    public let name: String
    public let typeGuid: String
    public let bootable: Bool
}

public struct FileEntryModel: Identifiable, Hashable {
    public var id: String { path }
    public let name: String
    public let path: String
    public let isDirectory: Bool
    public let sizeBytes: UInt64
}

public struct HexRowModel: Identifiable {
    public var id: UInt64 { offset }
    public let offset: UInt64
    public let hexDump: String
    public let asciiDump: String
}

public struct SearchResultModel: Identifiable {
    public var id: UInt64 { offset }
    public let offset: UInt64
    public let length: Int
    public let snippet: String
}

public struct SignatureHitModel: Identifiable, Hashable {
    public var id: String { "\(offset)-\(format)-\(description)" }
    public let offset: UInt64
    public let format: String
    public let category: String
    public let description: String
    public let extensionName: String
    public let confidence: UInt32
}

public struct CarvedFileModel: Identifiable {
    public var id: UInt64 { offset }
    public let offset: UInt64
    public let sizeBytes: UInt64
    public let fileType: String
    public let extensionName: String
}

public struct FilesystemCandidateModel: Identifiable, Hashable {
    public var id: String { "\(offset)-\(fsType)-\(source)" }
    public let offset: UInt64
    public let sizeBytes: UInt64
    public let fsType: String
    public let source: String
    public let confidence: UInt32
}

public struct ChecksumModel {
    public let crc32: UInt32
    public let md5: String
    public let sha256: String
}

public struct RegionSummaryModel: Identifiable {
    public var id: UInt64 { offset }
    public let offset: UInt64
    public let length: UInt64
    public let entropy: Double
    public let printableRatio: Double
    public let dominantByte: UInt8
    public let dominantRatio: Double
    public let kind: String
}

public class DiskAnalyzerEngine: ObservableObject {
    private var deviceHandle: OpaquePointer?
    private var fsHandle: OpaquePointer?

    @Published public var isLoaded: Bool = false
    @Published public var imagePath: String = ""
    @Published public var totalSize: UInt64 = 0
    @Published public var blockSize: UInt32 = 512
    @Published public var detectedMagic: String = "Unknown"
    @Published public var partitions: [PartitionModel] = []
    @Published public var mountedFsName: String = "None"
    @Published public var filesystemCandidates: [FilesystemCandidateModel] = []
    @Published public var currentPathFiles: [FileEntryModel] = []
    @Published public var hexRows: [HexRowModel] = []
    @Published public var searchResults: [SearchResultModel] = []
    @Published public var signatureHits: [SignatureHitModel] = []
    @Published public var carvedFiles: [CarvedFileModel] = []
    @Published public var lastChecksums: ChecksumModel?
    @Published public var currentEntropy: Double = 0.0
    @Published public var regionSummaries: [RegionSummaryModel] = []
    @Published public var statusMessage: String = "Open an image to begin analysis."
    @Published public var jsonReport: String = ""

    public init() {}

    deinit {
        close()
    }

    public func openImage(url: URL) -> Bool {
        close()
        guard url.startAccessingSecurityScopedResource() else {
            return openImageByPath(path: url.path)
        }
        defer { url.stopAccessingSecurityScopedResource() }
        return openImageByPath(path: url.path)
    }

    public func openImageByPath(path: String) -> Bool {
        close()
        self.imagePath = path

        if let handle = disk_analyzer_open_auto(path) {
            self.deviceHandle = handle
        } else {
            return false
        }

        guard let handle = deviceHandle else { return false }

        self.totalSize = disk_analyzer_device_get_size(handle)
        self.blockSize = disk_analyzer_device_get_block_size(handle)
        if let magicPtr = disk_analyzer_detect_magic(handle, 0) {
            self.detectedMagic = String(cString: magicPtr)
        }
        self.isLoaded = true

        loadPartitions()
        scanFilesystems()
        loadHexView(offset: 0, size: 512)
        calculateEntropy(offset: 0, size: min(totalSize, 1024 * 1024))
        classifyRegions(offset: 0, length: min(totalSize, 64 * 1024 * 1024), regionSize: 1024 * 1024)
        scanSignatures(offset: 0, length: min(totalSize, 256 * 1024 * 1024))
        jsonReport = ""
        statusMessage = "Loaded and profiled \(URL(fileURLWithPath: path).lastPathComponent)"
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
        imagePath = ""
        totalSize = 0
        blockSize = 512
        detectedMagic = "Unknown"
        partitions.removeAll()
        currentPathFiles.removeAll()
        filesystemCandidates.removeAll()
        hexRows.removeAll()
        searchResults.removeAll()
        signatureHits.removeAll()
        carvedFiles.removeAll()
        lastChecksums = nil
        mountedFsName = "None"
        regionSummaries.removeAll()
        jsonReport = ""
        statusMessage = "Open an image to begin analysis."
    }

    public func loadPartitions() {
        guard let dev = deviceHandle else { return }
        var cPartitions = [CPartitionInfo](repeating: CPartitionInfo(), count: 32)
        let count = disk_analyzer_get_partitions(dev, &cPartitions, 32)

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

    public func scanFilesystems() {
        guard let dev = deviceHandle else { return }
        var cCandidates = [CFilesystemCandidate](repeating: CFilesystemCandidate(), count: 64)
        let count = disk_analyzer_scan_filesystems(dev, &cCandidates, 64)

        filesystemCandidates = (0..<count).map { i in
            let c = cCandidates[i]
            let fsType = withUnsafeBytes(of: c.fs_type) { String(cString: $0.baseAddress!.assumingMemoryBound(to: CChar.self)) }
            let source = withUnsafeBytes(of: c.source) { String(cString: $0.baseAddress!.assumingMemoryBound(to: CChar.self)) }
            return FilesystemCandidateModel(offset: c.offset, sizeBytes: c.size_bytes, fsType: fsType, source: source, confidence: c.confidence)
        }
    }

    public func mountFilesystem(partitionOffset: UInt64, partitionSize: UInt64) -> Bool {
        guard let dev = deviceHandle else { return false }
        if let fs = fsHandle {
            disk_analyzer_close_filesystem(fs)
            fsHandle = nil
        }
        guard let fs = disk_analyzer_open_filesystem(dev, partitionOffset, partitionSize) else {
            statusMessage = "No supported filesystem detected at selected range."
            return false
        }
        self.fsHandle = fs
        if let namePtr = disk_analyzer_fs_get_name(fs) {
            self.mountedFsName = String(cString: namePtr)
        }
        statusMessage = "Mounted \(mountedFsName) filesystem."
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

    public func extractFile(filePath: String, destPath: String) -> Bool {
        guard let fs = fsHandle else { return false }
        return disk_analyzer_fs_extract_file(fs, filePath, destPath)
    }

    public func loadHexView(offset: UInt64, size: Int = 512) {
        guard let dev = deviceHandle else { return }
        var cRows = [CHexRow](repeating: CHexRow(), count: 32)
        let count = disk_analyzer_get_hex_view(dev, offset, size, &cRows, 32)

        hexRows = (0..<count).map { i in
            let r = cRows[i]
            let ascii = withUnsafeBytes(of: r.ascii_dump) { String(cString: $0.baseAddress!.assumingMemoryBound(to: CChar.self)) }

            var hexDumpStr = ""
            withUnsafeBytes(of: r.bytes) { ptr in
                for b in 0..<r.byte_count {
                    hexDumpStr += String(format: "%02X ", ptr[b])
                }
            }

            return HexRowModel(offset: r.offset, hexDump: hexDumpStr, asciiDump: ascii)
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

    public func scanSignatures(offset: UInt64, length: UInt64) {
        guard let dev = deviceHandle else { return }
        var cHits = [CSignatureHit](repeating: CSignatureHit(), count: 256)
        let count = disk_analyzer_scan_signatures(dev, offset, length, &cHits, 256)

        signatureHits = (0..<count).map { i in
            let h = cHits[i]
            let format = withUnsafeBytes(of: h.format) { String(cString: $0.baseAddress!.assumingMemoryBound(to: CChar.self)) }
            let category = withUnsafeBytes(of: h.category) { String(cString: $0.baseAddress!.assumingMemoryBound(to: CChar.self)) }
            let description = withUnsafeBytes(of: h.description) { String(cString: $0.baseAddress!.assumingMemoryBound(to: CChar.self)) }
            let ext = withUnsafeBytes(of: h.extension) { String(cString: $0.baseAddress!.assumingMemoryBound(to: CChar.self)) }
            return SignatureHitModel(offset: h.offset, format: format, category: category, description: description, extensionName: ext, confidence: h.confidence)
        }
    }

    public func carveFiles(offset: UInt64, length: UInt64) {
        guard let dev = deviceHandle else { return }
        var cCarved = [CCarvedFile](repeating: CCarvedFile(), count: 100)
        let count = disk_analyzer_carve_files(dev, offset, length, &cCarved, 100)

        carvedFiles = (0..<count).map { i in
            let c = cCarved[i]
            let fileType = withUnsafeBytes(of: c.file_type) { String(cString: $0.baseAddress!.assumingMemoryBound(to: CChar.self)) }
            let ext = withUnsafeBytes(of: c.extension) { String(cString: $0.baseAddress!.assumingMemoryBound(to: CChar.self)) }
            return CarvedFileModel(offset: c.offset, sizeBytes: c.size_bytes, fileType: fileType, extensionName: ext)
        }
    }

    public func calculateEntropy(offset: UInt64, size: UInt64) {
        guard let dev = deviceHandle else { return }
        self.currentEntropy = disk_analyzer_calculate_entropy(dev, offset, Int(size))
    }

    public func classifyRegions(offset: UInt64, length: UInt64, regionSize: Int) {
        guard let dev = deviceHandle else { return }
        var cRegions = [CRegionSummary](repeating: CRegionSummary(), count: 128)
        let count = disk_analyzer_classify_regions(dev, offset, length, regionSize, &cRegions, 128)

        regionSummaries = (0..<count).map { i in
            let r = cRegions[i]
            let kind = withUnsafeBytes(of: r.kind) { String(cString: $0.baseAddress!.assumingMemoryBound(to: CChar.self)) }
            return RegionSummaryModel(
                offset: r.offset,
                length: r.length,
                entropy: r.entropy,
                printableRatio: r.printable_ratio,
                dominantByte: r.dominant_byte,
                dominantRatio: r.dominant_ratio,
                kind: kind
            )
        }
    }

    public func generateJsonReport() -> Bool {
        guard let dev = deviceHandle else { return false }
        guard let reportPtr = disk_analyzer_generate_json_report(dev, URL(fileURLWithPath: imagePath).lastPathComponent) else {
            statusMessage = "Failed to generate analysis report."
            return false
        }
        defer { disk_analyzer_free_string(reportPtr) }
        jsonReport = String(cString: reportPtr)
        statusMessage = "Generated JSON analysis report."
        return true
    }

    public func calculateChecksums(offset: UInt64, size: UInt64) {
        guard let dev = deviceHandle else { return }
        var cChecksums = CChecksumResult()
        if disk_analyzer_calculate_checksums(dev, offset, Int(size), &cChecksums) {
            let md5Str = withUnsafeBytes(of: cChecksums.md5_hex) { String(cString: $0.baseAddress!.assumingMemoryBound(to: CChar.self)) }
            let shaStr = withUnsafeBytes(of: cChecksums.sha256_hex) { String(cString: $0.baseAddress!.assumingMemoryBound(to: CChar.self)) }
            self.lastChecksums = ChecksumModel(crc32: cChecksums.crc32, md5: md5Str, sha256: shaStr)
        }
    }
}
