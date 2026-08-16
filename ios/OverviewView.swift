import SwiftUI

struct OverviewView: View {
    @ObservedObject var engine: DiskAnalyzerEngine

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                // Header card
                VStack(alignment: .leading, spacing: 8) {
                    Text("Disk Image Technical Overview")
                        .font(.headline)
                        .foregroundColor(.secondary)

                    Text(engine.imagePath.isEmpty ? "No Image Loaded" : (engine.imagePath as NSString).lastPathComponent)
                        .font(.title2)
                        .bold()

                    HStack {
                        Label(engine.detectedMagic, systemImage: "doc.fill")
                            .font(.subheadline)
                            .padding(.horizontal, 10)
                            .padding(.vertical, 4)
                            .background(Color.blue.opacity(0.15))
                            .cornerRadius(8)

                        Spacer()
                    }
                }
                .padding()
                .background(Color(UIColor.secondarySystemBackground))
                .cornerRadius(12)

                // Key metrics grid
                LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 12) {
                    MetricCard(title: "Total Size", value: "\(engine.totalSize / (1024 * 1024)) MB", subtitle: "\(engine.totalSize) Bytes", icon: "internaldrive")
                    MetricCard(title: "Block Size", value: "\(engine.blockSize) B", subtitle: "Sector Alignment", icon: "square.grid.2x2")
                    MetricCard(title: "Partitions", value: "\(engine.partitions.count)", subtitle: "Table Entries", icon: "slider.horizontal.3")
                    MetricCard(title: "Entropy", value: String(format: "%.3f / 8.0", engine.currentEntropy), subtitle: engine.currentEntropy > 7.0 ? "Compressed / Encrypted" : "Uncompressed Data", icon: "waveform.path.ecg")
                }

                // Partition Table Quick List
                if !engine.partitions.isEmpty {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("Partition Map")
                            .font(.headline)

                        ForEach(engine.partitions) { p in
                            HStack {
                                Image(systemName: p.bootable ? "flag.fill" : "shippingbox")
                                    .foregroundColor(p.bootable ? .green : .blue)

                                VStack(alignment: .leading, spacing: 2) {
                                    Text(p.name).bold()
                                    Text("LBA \(p.startSector) | \(p.sizeBytes / (1024 * 1024)) MB")
                                        .font(.caption)
                                        .foregroundColor(.secondary)
                                }
                                Spacer()
                                Button("Mount FS") {
                                    _ = engine.mountFilesystem(partitionOffset: p.startSector * UInt64(engine.blockSize), partitionSize: p.sizeBytes)
                                }
                                .buttonStyle(.borderedProminent)
                                .font(.caption)
                            }
                            .padding(.vertical, 6)
                            Divider()
                        }
                    }
                    .padding()
                    .background(Color(UIColor.secondarySystemBackground))
                    .cornerRadius(12)
                }
            }
            .padding()
        }
    }
}

struct MetricCard: View {
    let title: String
    let value: String
    let subtitle: String
    let icon: String

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Image(systemName: icon)
                    .foregroundColor(.blue)
                Spacer()
            }
            Text(value)
                .font(.title3)
                .bold()
            Text(title)
                .font(.caption)
                .foregroundColor(.secondary)
            Text(subtitle)
                .font(.caption2)
                .foregroundColor(.gray)
        }
        .padding()
        .background(Color(UIColor.secondarySystemBackground))
        .cornerRadius(10)
    }
}
