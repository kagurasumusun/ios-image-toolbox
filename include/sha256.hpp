#ifndef SHA256_HPP
#define SHA256_HPP

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace disk_analyzer {

class Sha256 {
public:
    static std::string HexHash(const uint8_t* data, size_t len);
};

class Md5 {
public:
    static std::string HexHash(const uint8_t* data, size_t len);
};

} // namespace disk_analyzer

#endif // SHA256_HPP
