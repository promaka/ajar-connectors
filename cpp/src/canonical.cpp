// SPDX-License-Identifier: Apache-2.0

#include "ajar/connector.hpp"

#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>

namespace ajar {

std::string canonical_bytes(const Event& event) {
  std::string out;
  {
    google::protobuf::io::StringOutputStream zos(&out);
    google::protobuf::io::CodedOutputStream cos(&zos);
    // Deterministic = ascending tag order, map keys sorted (no maps here).
    // The same wire shape prost (Rust) and Go's Deterministic marshaller emit.
    cos.SetSerializationDeterministic(true);
    if (!event.SerializeToCodedStream(&cos)) {
      out.clear();
    }
  }  // cos/zos flush into `out` on destruction
  return out;
}

}  // namespace ajar
