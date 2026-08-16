import SwiftUI

struct OverviewView: View {
    @ObservedObject var engine: DiskAnalyzerEngine

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Disk Image Summary")
                .font(.title)
                .bold()

            HStack {
                Text("Total Size:")
                    .bold()
                Text("\(engine.totalSize / (1024 * 1024)) MB (\(engine.totalSize) Bytes)")
            }

            HStack {
                Text("Partitions Detected:")
                    .bold()
                Text("\(engine.partitions.count)")
            }

            List(engine.partitions) { p in
                VStack(alignment: .leading) {
                    Text(p.name).font(.headline)
                    Text("Start Sector: \(p.startSector) | Size: \(p.sizeBytes / (1024 * 1024)) MB")
                        .font(.subheadline)
                        .foregroundColor(.gray)
                }
            }
        }
        .padding()
    }
}
