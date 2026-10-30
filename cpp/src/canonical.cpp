// SPDX-License-Identifier: Apache-2.0

#include "ajar/connector.hpp"

#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>

namespace ajar {

std::string canonical_bytes(const Event& event) {
  std::string out;
  // cos and zos flush into `out` when this scope ends.
  {
    google::protobuf::io::StringOutputStream zos(&out);
    google::protobuf::io::CodedOutputStream cos(&zos);
    // Ascending tag order, the same wire shape prost (Rust) and Go's
    // Deterministic marshaller emit.
    cos.SetSerializationDeterministic(true);
    if (!event.SerializeToCodedStream(&cos)) {
      out.clear();
    }
  }
  return out;
}

}  // namespace ajar
