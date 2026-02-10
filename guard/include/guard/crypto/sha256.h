#pragma once
#include <array>
#include <cstddef>
#include <cstdint>

namespace guard {

std::array<uint8_t, 32> sha256(const uint8_t* data, size_t len);

} // namespace guard
