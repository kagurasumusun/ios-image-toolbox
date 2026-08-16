import SwiftUI
import UniformTypeIdentifiers

struct AppContentView: View {
    @StateObject private var engine = DiskAnalyzerEngine()
    @State private var isPickerPresented: Bool = false

    var body: some View {
        TabView {
            OverviewView(engine: engine)
                .tabItem {
                    Label("Overview", systemImage: "info.circle")
                }

            PartitionView(engine: engine)
                .tabItem {
                    Label("Partitions", systemImage: "square.split.2x2")
                }

            FileBrowserView(engine: engine)
                .tabItem {
                    Label("Files", systemImage: "folder")
                }

            CarvingView(engine: engine)
                .tabItem {
                    Label("Carving", systemImage: "wand.and.stars")
                }

            HexView(engine: engine)
                .tabItem {
                    Label("Hex", systemImage: "viewfinder")
                }

            SearchView(engine: engine)
                .tabItem {
                    Label("Search", systemImage: "magnifyingglass")
                }

            BinaryAnalysisView(engine: engine)
                .tabItem {
                    Label("Diagnostics", systemImage: "cpu")
                }
        }
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Button("Open Image") {
                    isPickerPresented = true
                }
            }
        }
        .fileImporter(
            isPresented: $isPickerPresented,
            allowedContentTypes: [.data, .diskImage, .item],
            allowsMultipleSelection: false
        ) { result in
            switch result {
            case .success(let urls):
                if let url = urls.first {
                    _ = engine.openImage(url: url)
                }
            case .failure(let err):
                print("Picker error: \(err.localizedDescription)")
            }
        }
    }
}

@main
struct DiskAnalyzerApp: App {
    var body: some Scene {
        WindowGroup {
            NavigationView {
                AppContentView()
            }
        }
    }
}
