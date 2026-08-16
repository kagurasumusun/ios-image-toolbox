#ifndef TEST_SUITE_HPP
#define TEST_SUITE_HPP

#include <iostream>
#include <cstdlib>

#define REQUIRE(cond) \
    do { \
        if (!(cond)) { \
            std::cerr << "Test assertion failed at " << __FILE__ << ":" << __LINE__ << ": " << #cond << std::endl; \
            std::abort(); \
        } \
    } while (0)

void TestMemoryBlockDevice();
void TestPartition();
void TestFilesystem();
void TestQcow2();
void TestAnalysis();

#endif // TEST_SUITE_HPP
