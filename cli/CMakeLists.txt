add_executable(disk-analyzer-cli main.cpp)

target_link_libraries(disk-analyzer-cli PRIVATE disk_analyzer_core)
