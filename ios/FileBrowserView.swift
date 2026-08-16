import SwiftUI

struct FileBrowserView: View {
    @ObservedObject var engine: DiskAnalyzerEngine
    @State private var currentDirectory: String = "/"
    @State private var statusMessage: String = ""

    var body: some View {
        VStack {
            HStack {
                Text("Mounted FS: \(engine.mountedFsName)")
                    .font(.caption)
                    .bold()
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background(Color.blue.opacity(0.15))
                    .cornerRadius(6)

                Spacer()

                if currentDirectory != "/" {
                    Button("Up..") {
                        navigateUp()
                    }
                    .font(.caption)
                }

                Button("Refresh") {
                    engine.listDirectory(path: currentDirectory)
                }
                .font(.caption)
            }
            .padding(.horizontal)

            Text("Path: \(currentDirectory)")
                .font(.footnote)
                .foregroundColor(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal)

            List(engine.currentPathFiles) { file in
                HStack {
                    Image(systemName: file.isDirectory ? "folder.fill" : "doc.fill")
                        .foregroundColor(file.isDirectory ? .blue : .gray)

                    VStack(alignment: .leading) {
                        Text(file.name).font(.body)
                        if !file.isDirectory {
                            Text("\(file.sizeBytes) bytes")
                                .font(.caption2)
                                .foregroundColor(.secondary)
                        }
                    }

                    Spacer()

                    if !file.isDirectory {
                        Button(action: {
                            extractFile(file: file)
                        }) {
                            Image(systemName: "square.and.arrow.down")
                        }
                        .buttonStyle(.plain)
                    }
                }
                .contentShape(Rectangle())
                .onTapGesture {
                    if file.isDirectory {
                        currentDirectory = file.path
                        engine.listDirectory(path: currentDirectory)
                    }
                }
            }

            if !statusMessage.isEmpty {
                Text(statusMessage)
                    .font(.caption)
                    .foregroundColor(.green)
                    .padding()
            }
        }
        .onAppear {
            engine.listDirectory(path: currentDirectory)
        }
    }

    private func navigateUp() {
        let components = currentDirectory.split(separator: "/").map(String.init)
        if components.count <= 1 {
            currentDirectory = "/"
        } else {
            currentDirectory = "/" + components.dropLast().joined(separator: "/")
        }
        engine.listDirectory(path: currentDirectory)
    }

    private func extractFile(file: FileEntryModel) {
        let tempDir = FileManager.default.temporaryDirectory
        let destURL = tempDir.appendingPathComponent(file.name)

        if engine.extractFile(filePath: file.path, destPath: destURL.path) {
            statusMessage = "Extracted \(file.name) to Temp folder!"
        } else {
            statusMessage = "Extraction failed for \(file.name)"
        }
    }
}
