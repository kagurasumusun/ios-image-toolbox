import SwiftUI

struct ForensicsView: View {
    @ObservedObject var engine: DiskAnalyzerEngine
    @State private var scanLengthMB: Double = 256

    private var groupedHits: [(String, [SignatureHitModel])] {
        Dictionary(grouping: engine.signatureHits, by: { $0.category })
            .map { ($0.key, $0.value.sorted { $0.offset < $1.offset }) }
            .sorted { $0.0 < $1.0 }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                header
                controls
                if engine.signatureHits.isEmpty {
                    emptyState
                } else {
                    ForEach(groupedHits, id: \.0) { category, hits in
                        signatureGroup(title: category, hits: hits)
                    }
                }
            }
            .padding()
        }
        .background(Color(UIColor.systemGroupedBackground))
        .navigationTitle("Forensics")
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Embedded Signature Intelligence", systemImage: "scope")
                .font(.title2)
                .fontWeight(.bold)
            Text("Scan bounded regions for archives, firmware images, executables, filesystems, databases, and media without loading the whole image into memory.")
                .font(.subheadline)
                .foregroundColor(.secondary)
        }
        .padding()
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(LinearGradient(colors: [Color.indigo.opacity(0.18), Color.teal.opacity(0.10)], startPoint: .topLeading, endPoint: .bottomTrailing))
        .clipShape(RoundedRectangle(cornerRadius: 22, style: .continuous))
    }

    private var controls: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("Scan Window")
                    .font(.headline)
                Spacer()
                Text("\(Int(scanLengthMB)) MB")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            Slider(value: $scanLengthMB, in: 16...512, step: 16)
            Button {
                engine.scanSignatures(offset: 0, length: min(engine.totalSize, UInt64(scanLengthMB) * 1024 * 1024))
            } label: {
                Label("Run Signature Scan", systemImage: "play.circle.fill")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .disabled(!engine.isLoaded)
        }
        .padding()
        .background(Color(UIColor.secondarySystemGroupedBackground))
        .clipShape(RoundedRectangle(cornerRadius: 18, style: .continuous))
    }

    private var emptyState: some View {
        Text(engine.isLoaded ? "No embedded signatures found in the selected scan window." : "Open an image to scan for embedded artifacts and firmware structures.")
            .font(.footnote)
            .foregroundColor(.secondary)
            .padding()
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(UIColor.secondarySystemGroupedBackground))
            .clipShape(RoundedRectangle(cornerRadius: 18, style: .continuous))
    }

    private func signatureGroup(title: String, hits: [SignatureHitModel]) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text(title.capitalized)
                    .font(.headline)
                Spacer()
                Text("\(hits.count) hits")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            ForEach(hits) { hit in
                HStack(alignment: .top, spacing: 12) {
                    Image(systemName: iconName(for: hit.category))
                        .foregroundStyle(.indigo)
                        .frame(width: 28)
                    VStack(alignment: .leading, spacing: 3) {
                        Text(hit.format)
                            .fontWeight(.semibold)
                        Text(hit.description)
                            .font(.caption)
                            .foregroundColor(.secondary)
                        Text("offset 0x\(String(hit.offset, radix: 16).uppercased()) • .\(hit.extensionName) • confidence \(hit.confidence)%")
                            .font(.caption2)
                            .foregroundColor(.secondary)
                    }
                    Spacer()
                }
                Divider()
            }
        }
        .padding()
        .background(Color(UIColor.secondarySystemGroupedBackground))
        .clipShape(RoundedRectangle(cornerRadius: 18, style: .continuous))
    }

    private func iconName(for category: String) -> String {
        switch category {
        case "firmware": return "memorychip"
        case "archive": return "archivebox"
        case "executable": return "terminal"
        case "filesystem": return "externaldrive"
        case "database": return "cylinder.split.1x2"
        case "media": return "photo"
        default: return "doc.viewfinder"
        }
    }
}
