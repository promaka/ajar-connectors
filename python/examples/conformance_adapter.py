# SPDX-License-Identifier: Apache-2.0
"""Conformance adapter: reads a corpus fixture on stdin, writes canonical or sealed bytes."""
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
