import SwiftUI

struct HexView: View {
    @ObservedObject var engine: DiskAnalyzerEngine
    @State private var offsetText: String = "0"
    @State private var currentOffset: UInt64 = 0

    var body: some View {
        VStack {
            HStack {
                Text("Offset (Hex / Dec):")
                    .font(.caption)
                TextField("0", text: $offsetText)
                    .textFieldStyle(.roundedBorder)
                    .keyboardType(.asciiCapable)
                    .frame(width: 120)

                Button("Jump") {
                    if let dec = UInt64(offsetText) {
                        currentOffset = dec
                    } else if let hex = UInt64(offsetText.replacingOccurrences(of: "0x", with: ""), radix: 16) {
                        currentOffset = hex
                    }
                    engine.loadHexView(offset: currentOffset, size: 512)
                }
                .buttonStyle(.bordered)

                Spacer()

                Button("-512B") {
                    if currentOffset >= 512 { currentOffset -= 512 }
                    engine.loadHexView(offset: currentOffset, size: 512)
                }
                .font(.caption)

                Button("+512B") {
                    currentOffset += 512
                    engine.loadHexView(offset: currentOffset, size: 512)
                }
                .font(.caption)
            }
            .padding()

            ScrollView([.horizontal, .vertical]) {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(engine.hexRows) { row in
                        HStack(spacing: 12) {
                            Text(String(format: "%08X", row.offset))
                                .font(.system(.caption, design: .monospaced))
                                .foregroundColor(.blue)

                            Text(row.hexDump)
                                .font(.system(.caption, design: .monospaced))

                            Text(row.asciiDump)
                                .font(.system(.caption, design: .monospaced))
                                .foregroundColor(.green)
                        }
                    }
                }
                .padding()
            }
            .background(Color.black.opacity(0.9))
            .foregroundColor(.white)
            .cornerRadius(8)
            .padding()
        }
        .navigationTitle("Hex Inspection")
        .onAppear {
            engine.loadHexView(offset: currentOffset, size: 512)
        }
    }
}
