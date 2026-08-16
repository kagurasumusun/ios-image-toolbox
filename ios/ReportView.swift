import SwiftUI

struct ReportView: View {
    @ObservedObject var engine: DiskAnalyzerEngine

    var body: some View {
        VStack(spacing: 0) {
            reportToolbar
            Divider()
            if engine.jsonReport.isEmpty {
                emptyState
            } else {
                ScrollView([.vertical, .horizontal]) {
                    Text(engine.jsonReport)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding()
                }
                .background(Color(UIColor.systemBackground))
            }
        }
        .navigationTitle("Report")
    }

    private var reportToolbar: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Consolidated Analysis Report")
                    .font(.headline)
                Text("JSON report with device metadata, partitions, filesystem candidates, signature hits, region statistics, and bounded checksums.")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            Spacer()
            Button {
                _ = engine.generateJsonReport()
            } label: {
                Label("Generate", systemImage: "doc.badge.gearshape")
            }
            .buttonStyle(.borderedProminent)
            .disabled(!engine.isLoaded)

            if !engine.jsonReport.isEmpty {
                ShareLink(item: engine.jsonReport) {
                    Label("Share", systemImage: "square.and.arrow.up")
                }
                .buttonStyle(.bordered)
            }
        }
        .padding()
        .background(Color(UIColor.secondarySystemGroupedBackground))
    }

    private var emptyState: some View {
        VStack(spacing: 14) {
            Image(systemName: "doc.text.magnifyingglass")
                .font(.system(size: 44))
                .foregroundStyle(.secondary)
            Text(engine.isLoaded ? "Generate a report for the loaded image." : "Open an image to generate a professional analysis report.")
                .font(.headline)
            Text("Reports are generated from real Core analysis results and are suitable for sharing, auditing, and regression comparison.")
                .font(.subheadline)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(UIColor.systemGroupedBackground))
    }
}
