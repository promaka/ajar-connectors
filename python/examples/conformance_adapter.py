# SPDX-License-Identifier: Apache-2.0
"""Reference conformance adapter (Python).

What `ajar-conformance` asks of any implementation, in any language: read the
fixture on stdin, write raw bytes on stdout, exit 0.

    ajar-conformance run --impl python3 python/examples/conformance_adapter.py
"""
import json
import os
import sys

from ajar_connector import SigningKey, canonical_bytes, seal
from conformance.golden_vectors import fixture_to_event

out = canonical_bytes(fixture_to_event(json.load(sys.stdin)))
if sys.argv[1] == "sealed":
    seed = bytes.fromhex(os.environ["AJAR_TEST_SIGNING_SEED"])
    out = seal(out, SigningKey.from_seed(seed))
sys.stdout.buffer.write(out)
