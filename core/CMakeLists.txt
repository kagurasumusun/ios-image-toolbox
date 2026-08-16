file(GLOB_RECURSE CORE_SOURCES "*.cpp" "*.c")

add_library(disk_analyzer_core STATIC ${CORE_SOURCES})

target_include_directories(disk_analyzer_core PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include>
)

find_package(ZLIB REQUIRED)

target_link_libraries(disk_analyzer_core PUBLIC ZLIB::ZLIB)
