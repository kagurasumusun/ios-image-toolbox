import SwiftUI

struct CarvingView: View {
    @ObservedObject var engine: DiskAnalyzerEngine
    @State private var scanOffset: String = "0"
    @State private var isScanning: Bool = false

    var body: some View {
        VStack {
            HStack {
                Text("Scan Offset:")
                    .font(.caption)
                TextField("0", text: $scanOffset)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 100)

                Button(isScanning ? "Scanning..." : "Start File Carving") {
                    isScanning = true
                    let off = UInt64(scanOffset) ?? 0
                    let len = min(engine.totalSize - off, 50 * 1024 * 1024)
                    engine.carveFiles(offset: off, length: len)
                    isScanning = false
                }
                .buttonStyle(.borderedProminent)
                .disabled(isScanning)
            }
            .padding()

            List(engine.carvedFiles) { file in
                HStack {
                    Image(systemName: iconForType(file.extensionName))
                        .foregroundColor(.orange)

                    VStack(alignment: .leading, spacing: 2) {
                        Text(file.fileType)
                            .font(.headline)
                        Text("Offset 0x\(String(file.offset, radix: 16, uppercase: true)) | Estimated Size: \(file.sizeBytes / 1024) KB")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }

                    Spacer()

                    Text(".\(file.extensionName)")
                        .font(.caption2)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Color.orange.opacity(0.2))
                        .cornerRadius(4)
                }
            }
        }
        .navigationTitle("File Carving & Recovery")
    }

    private func iconForType(_ ext: String) -> String {
        switch ext.lowercased() {
        case "jpg", "png": return "photo"
        case "pdf": return "doc.text"
        case "zip": return "archivebox"
        case "elf": return "cpu"
        default: return "doc"
        }
    }
}
