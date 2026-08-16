import SwiftUI

struct SearchView: View {
    @ObservedObject var engine: DiskAnalyzerEngine
    @State private var queryText: String = ""
    @State private var caseSensitive: Bool = false

    var body: some View {
        VStack {
            HStack {
                TextField("Search text pattern...", text: $queryText)
                    .textFieldStyle(.roundedBorder)

                Toggle("Case", isOn: $caseSensitive)
                    .labelsHidden()

                Button("Search") {
                    engine.search(query: queryText, caseSensitive: caseSensitive)
                }
                .buttonStyle(.borderedProminent)
            }
            .padding()

            List(engine.searchResults) { res in
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Text(String(format: "Offset: 0x%08X", res.offset))
                            .font(.system(.caption, design: .monospaced))
                            .bold()
                            .foregroundColor(.blue)
                        Spacer()
                        Text("Match: \(res.length) B")
                            .font(.caption2)
                            .foregroundColor(.secondary)
                    }

                    Text("Snippet: \(res.snippet)")
                        .font(.system(.footnote, design: .monospaced))
                        .padding(6)
                        .background(Color(UIColor.secondarySystemBackground))
                        .cornerRadius(6)
                }
                .padding(.vertical, 2)
            }
        }
        .navigationTitle("Pattern Search")
    }
}
