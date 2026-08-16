#include <iostream>
#include "test_suite.hpp"

int main() {
    std::cout << "=== Running C++ Disk Analyzer Test Suite ===" << std::endl;
    TestMemoryBlockDevice();
    TestPartition();
    TestFilesystem();
    TestQcow2();
    TestAnalysis();
    TestSignatureScanner();
    std::cout << "=== All C++ Disk Analyzer Tests Passed Successfully! ===" << std::endl;
    return 0;
}
