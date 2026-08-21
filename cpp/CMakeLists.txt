# SPDX-License-Identifier: Apache-2.0
cmake_minimum_required(VERSION 3.20)
project(ajar_connector_cpp VERSION 0.5.5 LANGUAGES C CXX)

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

# In the repository the contract is vendored one level up; a release tarball
# ships it inside this directory so the extracted tree builds on its own.
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/../vendor/contract/event.proto)
  set(CONTRACT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../vendor/contract)
else()
  set(CONTRACT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/vendor/contract)
endif()
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

# Embed the vendored ontology so mapping validation is offline and cannot
# drift from the contract this build shipped with. Configure-time is right:
# the file is hash-pinned and a change to it must rebuild the library.
file(READ ${CONTRACT_DIR}/ontology.json AJAR_ONTOLOGY_HEX HEX)
string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1," AJAR_ONTOLOGY_BYTES "${AJAR_ONTOLOGY_HEX}")
configure_file(src/ontology_data.h.in ${GEN_DIR}/ontology_data.h @ONLY)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${CONTRACT_DIR}/ontology.json)

include(GNUInstallDirs)

# Vendored, heap-free crypto shared by desktop and embedded builds.
add_library(ajar_crypto STATIC
  vendor/monocypher/monocypher.c
  vendor/monocypher/monocypher-ed25519.c
  vendor/sha256/sha256.c)
target_include_directories(ajar_crypto PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/vendor/monocypher>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/vendor/sha256>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

# The SDK library.
add_library(ajar_connector STATIC
  src/canonical.cpp
  src/seal.cpp
  src/builder.cpp
  src/profile.cpp
  src/validate.cpp
  ${GEN_DIR}/event.pb.cc)
target_include_directories(ajar_connector PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<BUILD_INTERFACE:${GEN_DIR}>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_link_libraries(ajar_connector PUBLIC ${AJAR_PROTOBUF_LIB} ajar_crypto)
# Stable alias so in-tree consumers (add_subdirectory) and installed consumers
# (find_package) use the SAME name: ajar_connector::ajar_connector.
add_library(ajar_connector::ajar_connector ALIAS ajar_connector)

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
add_executable(validate_test conformance/validate_test.cpp)
target_link_libraries(validate_test PRIVATE ajar_connector)

add_executable(cot_roundtrip examples/cot_roundtrip.cpp)
target_link_libraries(cot_roundtrip PRIVATE cot_connector)

# Streaming example — uses the real NATS C client (cnats). Optional: only built
# when cnats is found, so the SDK + conformance build needs no NATS client. The
# transport dep is linked into this example only; the SDK stays transport-free.
find_package(cnats CONFIG QUIET)
if(cnats_FOUND)
  # cnats' imported target pulls in OpenSSL + Threads; make those targets exist.
  find_package(Threads REQUIRED)
  find_package(OpenSSL REQUIRED)
  add_executable(synthetic_radar examples/synthetic_radar.cpp)
  target_link_libraries(synthetic_radar PRIVATE ajar_connector cnats::nats)
  message(STATUS "cnats found: building synthetic_radar example")
else()
  message(STATUS "cnats not found: skipping synthetic_radar example "
                 "(install nats.c / `brew install cnats` to build it)")
endif()

# Minimal copy-me template (the C++ counterpart of rust/examples/connector-template).
# Built ALWAYS so `--dry-run` works with no system NATS client; the publish path is
# compiled in only when cnats is present (AJAR_WITH_NATS).
add_executable(connector_template examples/connector_template.cpp)
target_link_libraries(connector_template PRIVATE ajar_connector)
if(cnats_FOUND)
  target_compile_definitions(connector_template PRIVATE AJAR_WITH_NATS)
  target_link_libraries(connector_template PRIVATE cnats::nats)
endif()

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
add_test(NAME validate COMMAND validate_test)
add_test(NAME template_check COMMAND connector_template --check)
add_test(NAME embedded_conformance COMMAND embedded_conformance)
if(cnats_FOUND)
  # Broker-free smoke: builds + seals a couple of ticks and exits.
  add_test(NAME synthetic_radar_dry_run COMMAND synthetic_radar --dry-run --ticks 2)
endif()

# --- Install + find_package support ------------------------------------------
# Lets a vendor consume the SDK idiomatically from their own CMake project:
#   find_package(ajar_connector CONFIG REQUIRED)
#   target_link_libraries(my_connector PRIVATE ajar_connector::ajar_connector)
# (See cpp/README.md. In-tree `add_subdirectory()` works without installing.)
include(CMakePackageConfigHelpers)

install(TARGETS ajar_connector ajar_crypto
  EXPORT ajar_connectorTargets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

# Public API header (include/ajar/connector.hpp), the generated protobuf header
# the API exposes, and the vendored crypto headers — all flattened under the
# install include dir so the INSTALL_INTERFACE include path resolves them.
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(FILES ${GEN_DIR}/event.pb.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(FILES
    vendor/monocypher/monocypher.h
    vendor/monocypher/monocypher-ed25519.h
    vendor/sha256/sha256.h
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(EXPORT ajar_connectorTargets
  FILE ajar_connectorTargets.cmake
  NAMESPACE ajar_connector::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ajar_connector)

configure_package_config_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/cmake/ajar_connectorConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/ajar_connectorConfig.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ajar_connector)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/ajar_connectorConfig.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ajar_connector)
