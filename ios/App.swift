import SwiftUI

@main
struct DiskAnalyzerApp: App {
    @StateObject private var engine = DiskAnalyzerEngine()

    var body: some Scene {
        WindowGroup {
            NavigationView {
                VStack {
                    OverviewView(engine: engine)
                    FileBrowserView(engine: engine)
                }
                .navigationTitle("Disk Analyzer")
            }
        }
    }
}
