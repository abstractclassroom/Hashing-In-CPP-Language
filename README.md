# Hashing-In-C++-Language

A small CMake-based C++ library for teaching cryptographic hashing.

Currently implemented:
- MD5 (RFC 1321 style reference implementation)
- SHA1 (FIPS PUB 180-1 style reference implementation)
- SHA-256 (FIPS PUB 180-4 style reference implementation)
- SHA-512 (FIPS PUB 180-4 style reference implementation)
- HMAC-SHA256 (HMAC construction wrapping SHA-256)

## Project layout
- `include/hashlib/` public headers
- `src/` implementation files
- `examples/` small runnable samples
- `tests/` GoogleTest-based unit tests

## Build

```sh
cmake -S . -B build
cmake --build build
```

## Run example

```sh
./build/examples/md5_example
```

## Run tests

```sh
ctest --test-dir build
```

## Use from another project (FetchContent)

```cmake
include(FetchContent)

FetchContent_Declare(
  hashlib
  GIT_REPOSITORY https://github.com/abstractclassroom/Hashing-In-CPP-Language.git
  GIT_TAG v0.1.0
)

FetchContent_MakeAvailable(hashlib)

target_link_libraries(your_target PRIVATE hashlib::hashlib)
```

In code:

```cpp
#include <hashlib/md5.hpp>
// or
#include <hashlib/hashlib.hpp>
```

## Versions

This project uses semantic versioning for teaching purposes.

- `v0.1.0` - Added MD5 implementation and example.
- `v0.2.0` - Added SHA1 implementation and example.
- `v0.3.0` - Added SHA-256 implementation and example.
- `v0.4.0` - Added SHA-512 implementation and example.
- `v0.5.0` - Added HMAC-SHA256 implementation and example.
