import SwiftUI

struct PartitionView: View {
    @ObservedObject var engine: DiskAnalyzerEngine
    @State private var selectedPartition: PartitionModel?
    @State private var mountStatusMessage: String?

    var body: some View {
        VStack {
            List(engine.partitions) { partition in
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Text(partition.name)
                            .font(.headline)
                        if partition.bootable {
                            Text("BOOT")
                                .font(.caption2)
                                .padding(.horizontal, 6)
                                .padding(.vertical, 2)
                                .background(Color.green.opacity(0.2))
                                .foregroundColor(.green)
                                .cornerRadius(4)
                        }
                        Spacer()
                        Text("\(partition.sizeBytes / (1024 * 1024)) MB")
                            .font(.subheadline)
                            .foregroundColor(.secondary)
                    }

                    HStack {
                        Text("Start Sector: \(partition.startSector)")
                        Spacer()
                        Text("Sectors: \(partition.sectorCount)")
                    }
                    .font(.caption)
                    .foregroundColor(.gray)

                    if !partition.typeGuid.isEmpty {
                        Text("GUID: \(partition.typeGuid)")
                            .font(.caption2)
                            .foregroundColor(.secondary)
                    }

                    HStack {
                        Spacer()
                        Button("Mount Filesystem") {
                            let offset = partition.startSector * UInt64(engine.blockSize)
                            if engine.mountFilesystem(partitionOffset: offset, partitionSize: partition.sizeBytes) {
                                mountStatusMessage = "Mounted \(engine.mountedFsName) filesystem successfully!"
                            } else {
                                mountStatusMessage = "Failed to detect valid filesystem on partition."
                            }
                        }
                        .buttonStyle(.bordered)
                        .font(.caption)
                    }
                }
                .padding(.vertical, 4)
            }

            if let msg = mountStatusMessage {
                Text(msg)
                    .font(.caption)
                    .padding()
                    .background(Color.blue.opacity(0.1))
                    .cornerRadius(8)
            }
        }
        .navigationTitle("Partitions")
    }
}
