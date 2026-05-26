# Hashing-In-C++-Language

A small CMake-based C++ library for teaching cryptographic hashing.

Currently implemented:
- MD5 (RFC 1321 style reference implementation)

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
  GIT_REPOSITORY https://github.com/<you>/Hashing-In-CPP-Language.git
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

## Notes for teaching
MD5 is not considered secure for modern cryptographic integrity/authentication, but it is useful for teaching:
- Merkle–Damgård construction
- message padding and length encoding
- block processing and round functions
