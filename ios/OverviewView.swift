import SwiftUI

struct OverviewView: View {
    @ObservedObject var engine: DiskAnalyzerEngine

    private var highEntropyRegions: Int {
        engine.regionSummaries.filter { $0.kind == "High entropy" }.count
    }

    private var sparseRegions: Int {
        engine.regionSummaries.filter { $0.kind == "Zero-filled" || $0.kind == "0xFF-filled" }.count
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                heroCard
                readinessStrip
                metricsGrid
                filesystemCandidatesCard
                regionMap
                partitionQuickActions
            }
            .padding()
        }
        .background(Color(UIColor.systemGroupedBackground))
    }

    private var heroCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Disk Image Analyzer")
                        .font(.caption)
                        .fontWeight(.semibold)
                        .foregroundColor(.secondary)
                        .textCase(.uppercase)
                    Text(engine.imagePath.isEmpty ? "No Image Loaded" : (engine.imagePath as NSString).lastPathComponent)
                        .font(.largeTitle)
                        .fontWeight(.bold)
                        .lineLimit(2)
                    Text(engine.statusMessage)
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }
                Spacer()
                Image(systemName: engine.isLoaded ? "checkmark.seal.fill" : "externaldrive.badge.questionmark")
                    .font(.system(size: 42))
                    .foregroundStyle(engine.isLoaded ? .green : .secondary)
            }

            HStack(spacing: 10) {
                CapsuleLabel(text: engine.detectedMagic, icon: "doc.viewfinder", tint: .blue)
                CapsuleLabel(text: engine.mountedFsName == "None" ? "No FS mounted" : engine.mountedFsName, icon: "folder.badge.gearshape", tint: .purple)
            }
        }
        .padding(20)
        .background(
            LinearGradient(colors: [Color.blue.opacity(0.18), Color.purple.opacity(0.10), Color(UIColor.secondarySystemGroupedBackground)], startPoint: .topLeading, endPoint: .bottomTrailing)
        )
        .clipShape(RoundedRectangle(cornerRadius: 24, style: .continuous))
    }

    private var readinessStrip: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Operational Readiness")
                .font(.headline)
            HStack(spacing: 10) {
                ReadinessPill(title: "Container", isReady: engine.isLoaded, detail: engine.detectedMagic)
                ReadinessPill(title: "Partitions", isReady: !engine.partitions.isEmpty, detail: "\(engine.partitions.count) found")
                ReadinessPill(title: "Filesystems", isReady: !engine.filesystemCandidates.isEmpty, detail: "\(engine.filesystemCandidates.count) candidates")
                ReadinessPill(title: "Regions", isReady: !engine.regionSummaries.isEmpty, detail: "\(engine.regionSummaries.count) sampled")
            }
        }
    }

    private var metricsGrid: some View {
        LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 12) {
            MetricCard(title: "Total Size", value: ByteCountFormatter.diskString(engine.totalSize), subtitle: "\(engine.totalSize) bytes", icon: "internaldrive")
            MetricCard(title: "Block Size", value: "\(engine.blockSize) B", subtitle: "Natural sector", icon: "square.grid.2x2")
            MetricCard(title: "High Entropy", value: "\(highEntropyRegions)", subtitle: "compressed/encrypted candidates", icon: "waveform.path.ecg")
            MetricCard(title: "Sparse / Blank", value: "\(sparseRegions)", subtitle: "zero/0xFF regions", icon: "circle.dashed")
        }
    }

    private var filesystemCandidatesCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Filesystem Candidates")
                    .font(.headline)
                Spacer()
                Button("Rescan") { engine.scanFilesystems() }
                    .font(.caption)
                    .buttonStyle(.bordered)
                    .disabled(!engine.isLoaded)
            }

            if engine.filesystemCandidates.isEmpty {
                Text("No filesystem signatures were found at the whole-image or partition offsets. Use Hex, Search, Carving, and Region Intelligence for damaged or raw data.")
                    .font(.footnote)
                    .foregroundColor(.secondary)
            } else {
                ForEach(engine.filesystemCandidates) { candidate in
                    HStack(spacing: 12) {
                        Image(systemName: "externaldrive.connected.to.line.below")
                            .foregroundStyle(.teal)
                        VStack(alignment: .leading, spacing: 3) {
                            Text(candidate.fsType)
                                .fontWeight(.semibold)
                            Text("\(candidate.source) • offset 0x\(String(candidate.offset, radix: 16).uppercased()) • \(ByteCountFormatter.diskString(candidate.sizeBytes))")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                        Spacer()
                        Text("\(candidate.confidence)%")
                            .font(.caption)
                            .fontWeight(.bold)
                            .padding(.horizontal, 8)
                            .padding(.vertical, 4)
                            .background(Color.teal.opacity(0.14))
                            .clipShape(Capsule())
                        Button("Mount") {
                            _ = engine.mountFilesystem(partitionOffset: candidate.offset, partitionSize: candidate.sizeBytes)
                        }
                        .buttonStyle(.borderedProminent)
                        .controlSize(.small)
                    }
                    Divider()
                }
            }
        }
        .padding()
        .background(Color(UIColor.secondarySystemGroupedBackground))
        .clipShape(RoundedRectangle(cornerRadius: 18, style: .continuous))
    }

    private var regionMap: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Region Intelligence Map")
                    .font(.headline)
                Spacer()
                Button("Refresh") {
                    engine.classifyRegions(offset: 0, length: min(engine.totalSize, 64 * 1024 * 1024), regionSize: 1024 * 1024)
                }
                .font(.caption)
                .buttonStyle(.bordered)
                .disabled(!engine.isLoaded)
            }

            if engine.regionSummaries.isEmpty {
                Text("Open an image to classify sparse, text, high-entropy, and mixed regions without loading the whole image into memory.")
                    .font(.footnote)
                    .foregroundColor(.secondary)
            } else {
                VStack(spacing: 8) {
                    ForEach(engine.regionSummaries.prefix(16)) { region in
                        RegionSummaryRow(region: region)
                    }
                }
            }
        }
        .padding()
        .background(Color(UIColor.secondarySystemGroupedBackground))
        .clipShape(RoundedRectangle(cornerRadius: 18, style: .continuous))
    }

    private var partitionQuickActions: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Partition Map")
                    .font(.headline)
                Spacer()
                Text("\(engine.partitions.count) entries")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            if engine.partitions.isEmpty {
                Text("No MBR/GPT partitions detected. Use Hex, Search, Carving, and Diagnostics for raw or damaged images.")
                    .font(.footnote)
                    .foregroundColor(.secondary)
            } else {
                ForEach(engine.partitions) { p in
                    HStack(spacing: 12) {
                        Image(systemName: p.bootable ? "flag.fill" : "shippingbox.fill")
                            .foregroundStyle(p.bootable ? .green : .blue)
                        VStack(alignment: .leading, spacing: 3) {
                            Text(p.name).fontWeight(.semibold)
                            Text("LBA \(p.startSector) • \(ByteCountFormatter.diskString(p.sizeBytes))")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                        Spacer()
                        Button("Mount") {
                            _ = engine.mountFilesystem(partitionOffset: p.startSector * UInt64(engine.blockSize), partitionSize: p.sizeBytes)
                        }
                        .buttonStyle(.borderedProminent)
                        .controlSize(.small)
                    }
                    Divider()
                }
            }
        }
        .padding()
        .background(Color(UIColor.secondarySystemGroupedBackground))
        .clipShape(RoundedRectangle(cornerRadius: 18, style: .continuous))
    }
}

struct CapsuleLabel: View {
    let text: String
    let icon: String
    let tint: Color

    var body: some View {
        Label(text, systemImage: icon)
            .font(.caption)
            .fontWeight(.medium)
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .background(tint.opacity(0.14))
            .foregroundColor(tint)
            .clipShape(Capsule())
    }
}

struct ReadinessPill: View {
    let title: String
    let isReady: Bool
    let detail: String

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Label(title, systemImage: isReady ? "checkmark.circle.fill" : "circle")
                .font(.caption)
                .fontWeight(.semibold)
                .foregroundColor(isReady ? .green : .secondary)
            Text(detail)
                .font(.caption2)
                .foregroundColor(.secondary)
                .lineLimit(1)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(10)
        .background(Color(UIColor.secondarySystemGroupedBackground))
        .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
    }
}

struct RegionSummaryRow: View {
    let region: RegionSummaryModel

    private var tint: Color {
        switch region.kind {
        case "Zero-filled", "0xFF-filled": return .gray
        case "Mostly text": return .green
        case "High entropy": return .red
        default: return .blue
        }
    }

    var body: some View {
        HStack(spacing: 10) {
            RoundedRectangle(cornerRadius: 4)
                .fill(tint)
                .frame(width: 8, height: 36)
            VStack(alignment: .leading, spacing: 2) {
                Text(region.kind)
                    .font(.subheadline)
                    .fontWeight(.semibold)
                Text(String(format: "0x%08llX • %@ • entropy %.2f", region.offset, ByteCountFormatter.diskString(region.length), region.entropy))
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 2) {
                Text(String(format: "%.0f%% text", region.printableRatio * 100.0))
                    .font(.caption2)
                Text(String(format: "0x%02X %.0f%%", Int(region.dominantByte), region.dominantRatio * 100.0))
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }
        }
    }
}

struct MetricCard: View {
    let title: String
    let value: String
    let subtitle: String
    let icon: String

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Image(systemName: icon)
                    .foregroundColor(.blue)
                Spacer()
            }
            Text(value)
                .font(.title3)
                .fontWeight(.bold)
                .lineLimit(1)
                .minimumScaleFactor(0.7)
            Text(title)
                .font(.caption)
                .foregroundColor(.secondary)
            Text(subtitle)
                .font(.caption2)
                .foregroundColor(.gray)
                .lineLimit(2)
        }
        .padding()
        .background(Color(UIColor.secondarySystemGroupedBackground))
        .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
    }
}

private extension ByteCountFormatter {
    static let disk: ByteCountFormatter = {
        let formatter = ByteCountFormatter()
        formatter.countStyle = .file
        formatter.allowsNonnumericFormatting = false
        return formatter
    }()

    static func diskString(_ bytes: UInt64) -> String {
        let clamped = min(bytes, UInt64(Int64.max))
        return disk.string(fromByteCount: Int64(clamped))
    }
}
