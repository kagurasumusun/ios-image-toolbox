import SwiftUI
import UniformTypeIdentifiers

private enum WorkbenchSection: String, CaseIterable, Identifiable {
    case overview = "Overview"
    case partitions = "Partitions"
    case files = "Files"
    case forensics = "Forensics"
    case carving = "Carving"
    case hex = "Hex"
    case search = "Search"
    case diagnostics = "Diagnostics"

    var id: String { rawValue }

    var icon: String {
        switch self {
        case .overview: return "info.circle"
        case .partitions: return "square.split.2x2"
        case .files: return "folder"
        case .forensics: return "scope"
        case .carving: return "wand.and.stars"
        case .hex: return "viewfinder"
        case .search: return "magnifyingglass"
        case .diagnostics: return "cpu"
        }
    }
}

struct AppContentView: View {
    @StateObject private var engine = DiskAnalyzerEngine()
    @State private var isPickerPresented: Bool = false
    @State private var selectedSection: WorkbenchSection? = .overview

    var body: some View {
        NavigationSplitView {
            List(selection: $selectedSection) {
                Section("Image") {
                    statusHeader
                }
                Section("Workbench") {
                    ForEach(WorkbenchSection.allCases) { section in
                        Label(section.rawValue, systemImage: section.icon)
                            .tag(section as WorkbenchSection?)
                    }
                }
            }
            .navigationTitle("DiskLab")
            .toolbar { openToolbarItem }
        } detail: {
            NavigationStack {
                detailView
                    .navigationTitle(selectedSection?.rawValue ?? "Overview")
                    .toolbar { openToolbarItem }
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

    private var openToolbarItem: some ToolbarContent {
        ToolbarItem(placement: .primaryAction) {
            Button {
                isPickerPresented = true
            } label: {
                Label("Open Image", systemImage: "externaldrive.badge.plus")
            }
        }
    }

    private var statusHeader: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label(engine.isLoaded ? "Image Loaded" : "No Image", systemImage: engine.isLoaded ? "checkmark.seal.fill" : "externaldrive.badge.questionmark")
                .foregroundStyle(engine.isLoaded ? .green : .secondary)
                .fontWeight(.semibold)
            Text(engine.imagePath.isEmpty ? "Open an image to begin." : URL(fileURLWithPath: engine.imagePath).lastPathComponent)
                .font(.caption)
                .foregroundColor(.secondary)
                .lineLimit(2)
            if engine.isLoaded {
                Text(ByteCountFormatter.diskString(engine.totalSize))
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }
        }
        .padding(.vertical, 6)
    }

    @ViewBuilder
    private var detailView: some View {
        switch selectedSection ?? .overview {
        case .overview:
            OverviewView(engine: engine)
        case .partitions:
            PartitionView(engine: engine)
        case .files:
            FileBrowserView(engine: engine)
        case .forensics:
            ForensicsView(engine: engine)
        case .carving:
            CarvingView(engine: engine)
        case .hex:
            HexView(engine: engine)
        case .search:
            SearchView(engine: engine)
        case .diagnostics:
            BinaryAnalysisView(engine: engine)
        }
    }
}

@main
struct DiskAnalyzerApp: App {
    var body: some Scene {
        WindowGroup {
            AppContentView()
        }
    }
}
