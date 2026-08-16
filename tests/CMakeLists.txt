include(CTest)

add_executable(disk_analyzer_tests
    test_main.cpp
    test_block_device.cpp
    test_partition.cpp
    test_filesystem.cpp
    test_qcow2.cpp
    test_analysis.cpp
    test_signatures.cpp
)

target_link_libraries(disk_analyzer_tests PRIVATE disk_analyzer_core)

add_test(NAME AllTests COMMAND disk_analyzer_tests)
