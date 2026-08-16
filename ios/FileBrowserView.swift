import SwiftUI

struct FileBrowserView: View {
    @ObservedObject var engine: DiskAnalyzerEngine
    @State private var currentDirectory: String = "/"

    var body: some View {
        VStack {
            HStack {
                Text("Path: \(currentDirectory)").bold()
                Spacer()
                Button("Refresh") {
                    engine.listDirectory(path: currentDirectory)
                }
            }
            .padding()

            List(engine.currentPathFiles) { file in
                HStack {
                    Image(systemName: file.isDirectory ? "folder.fill" : "doc.fill")
                        .foregroundColor(file.isDirectory ? .blue : .gray)
                    Text(file.name)
                    Spacer()
                    if !file.isDirectory {
                        Text("\(file.sizeBytes) B")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }
                .onTapGesture {
                    if file.isDirectory {
                        currentDirectory = file.path
                        engine.listDirectory(path: currentDirectory)
                    }
                }
            }
        }
        .onAppear {
            engine.listDirectory(path: currentDirectory)
        }
    }
}
