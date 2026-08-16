import SwiftUI

struct BinaryAnalysisView: View {
    @ObservedObject var engine: DiskAnalyzerEngine
    @State private var inspectOffset: String = "0"

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Binary & Cryptographic Diagnostics")
                    .font(.title2)
                    .bold()

                VStack(alignment: .leading, spacing: 8) {
                    Text("Offset to Analyze (Bytes):")
                        .font(.caption)
                    HStack {
                        TextField("0", text: $inspectOffset)
                            .textFieldStyle(.roundedBorder)
                        Button("Calculate") {
                            let off = UInt64(inspectOffset) ?? 0
                            let len = min(engine.totalSize - off, 10 * 1024 * 1024)
                            engine.calculateEntropy(offset: off, size: len)
                            engine.calculateChecksums(offset: off, size: len)
                        }
                        .buttonStyle(.borderedProminent)
                    }
                }
                .padding()
                .background(Color(UIColor.secondarySystemBackground))
                .cornerRadius(10)

                VStack(alignment: .leading, spacing: 10) {
                    Text("Entropy Analysis").font(.headline)
                    Text(String(format: "Shannon Entropy: %.4f / 8.0", engine.currentEntropy))
                        .font(.system(.body, design: .monospaced))
                        .bold()
                    ProgressView(value: engine.currentEntropy, total: 8.0)
                        .tint(engine.currentEntropy > 7.0 ? .red : .blue)
                }
                .padding()
                .background(Color(UIColor.secondarySystemBackground))
                .cornerRadius(10)

                if let cs = engine.lastChecksums {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Checksum Hashes").font(.headline)

                        VStack(alignment: .leading) {
                            Text("CRC32").font(.caption).foregroundColor(.secondary)
                            Text(String(format: "0x%08X", cs.crc32)).font(.system(.body, design: .monospaced))
                        }

                        VStack(alignment: .leading) {
                            Text("MD5").font(.caption).foregroundColor(.secondary)
                            Text(cs.md5).font(.system(.caption, design: .monospaced))
                        }

                        VStack(alignment: .leading) {
                            Text("SHA-256").font(.caption).foregroundColor(.secondary)
                            Text(cs.sha256).font(.system(.caption2, design: .monospaced))
                        }
                    }
                    .padding()
                    .background(Color(UIColor.secondarySystemBackground))
                    .cornerRadius(10)
                }
            }
            .padding()
        }
        .navigationTitle("Binary Analysis")
    }
}
