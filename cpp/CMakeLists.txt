# SPDX-License-Identifier: Apache-2.0
cmake_minimum_required(VERSION 3.20)
project(ajar_connector_cpp LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 99)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()
add_compile_options(-Wall -Wextra)

# Prefer the modern CONFIG package (macOS/brew, recent Linux); fall back to the
# CMake FindProtobuf module (older apt protobuf) so CI is portable.
find_package(protobuf CONFIG QUIET)
if(protobuf_FOUND)
  set(AJAR_PROTOBUF_LIB protobuf::libprotobuf)
  set(AJAR_PROTOC protobuf::protoc)
else()
  find_package(Protobuf MODULE REQUIRED)
  set(AJAR_PROTOBUF_LIB protobuf::libprotobuf)
  set(AJAR_PROTOC ${Protobuf_PROTOC_EXECUTABLE})
endif()

set(CONTRACT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../vendor/contract)
set(PROTO ${CONTRACT_DIR}/event.proto)
set(GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)
file(MAKE_DIRECTORY ${GEN_DIR})

# Generate C++ types from the vendored proto (same source of truth as Rust/Go).
add_custom_command(
  OUTPUT ${GEN_DIR}/event.pb.cc ${GEN_DIR}/event.pb.h
  COMMAND ${AJAR_PROTOC}
  ARGS --cpp_out=${GEN_DIR} --proto_path=${CONTRACT_DIR} ${PROTO}
  DEPENDS ${PROTO}
  COMMENT "Generating C++ from vendored event.proto")

# Vendored, heap-free crypto shared by desktop and embedded builds.
add_library(ajar_crypto STATIC
  vendor/monocypher/monocypher.c
  vendor/monocypher/monocypher-ed25519.c
  vendor/sha256/sha256.c)
target_include_directories(ajar_crypto PUBLIC
  vendor/monocypher vendor/sha256)

# The SDK library.
add_library(ajar_connector STATIC
  src/canonical.cpp
  src/seal.cpp
  src/builder.cpp
  src/profile.cpp
  ${GEN_DIR}/event.pb.cc)
target_include_directories(ajar_connector PUBLIC
  include ${GEN_DIR})
target_link_libraries(ajar_connector PUBLIC ${AJAR_PROTOBUF_LIB} ajar_crypto)

# Reference connector example.
add_library(cot_connector STATIC examples/cot_connector.cpp)
target_link_libraries(cot_connector PUBLIC ajar_connector)

add_executable(first_connector examples/first_connector.cpp)
target_link_libraries(first_connector PRIVATE cot_connector)

# Conformance gate.
add_executable(conformance conformance/golden_vectors.cpp)
target_include_directories(conformance PRIVATE conformance vendor/sha256)
target_link_libraries(conformance PRIVATE ajar_connector ajar_crypto)
target_compile_definitions(conformance PRIVATE
  AJAR_CONTRACT_DIR="${CONTRACT_DIR}")

# Round-trip test for the example.
add_executable(cot_roundtrip examples/cot_roundtrip.cpp)
target_link_libraries(cot_roundtrip PRIVATE cot_connector)

# --- Embedded (nanopb, no-heap) path -----------------------------------------
# The nanopb runtime + generated static types. Links NO libprotobuf: this is the
# radar/effector-controller path. event.pb.c is committed (regenerate with
# scripts/gen-nanopb.sh); a build needs only the vendored runtime.
add_library(ajar_nanopb STATIC
  vendor/nanopb/pb_common.c
  vendor/nanopb/pb_encode.c
  vendor/nanopb/pb_decode.c
  embedded/generated/event.pb.c)
target_include_directories(ajar_nanopb PUBLIC vendor/nanopb embedded/generated)

add_executable(embedded_conformance embedded/conformance_nanopb.cpp)
target_include_directories(embedded_conformance PRIVATE conformance vendor/sha256 vendor/monocypher)
target_link_libraries(embedded_conformance PRIVATE ajar_nanopb ajar_crypto)
target_compile_definitions(embedded_conformance PRIVATE AJAR_CONTRACT_DIR="${CONTRACT_DIR}")

enable_testing()
add_test(NAME conformance COMMAND conformance)
add_test(NAME cot_roundtrip COMMAND cot_roundtrip)
add_test(NAME embedded_conformance COMMAND embedded_conformance)
