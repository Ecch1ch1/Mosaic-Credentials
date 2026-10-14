import base64
import json
import os
import pytest
from mosaic_credential import (
    Char,
    Blob,
    encode,
    parse,
    streaming_prehash,
    enroll_with_salt,
    verify,
    VerifyResult,
    AuthParams,
    ResourceLimits,
    VerifierRecord,
)

VECTORS_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "test-vectors", "published_test_vectors.json"
)

def build_vector_elements(vec_id: str):
    """Build the exact element sequence for each published vector id."""
    if vec_id == "mc-v1-001-empty":
        return []
    elif vec_id == "mc-v1-002-single-char":
        return [Char('A')]
    elif vec_id == "mc-v1-003-word-with-backspaces":
        return [
            Char('P'), Char('a'), Char('s'), Char('s'),
            Char('\u0008'), Char('\u0008'), Char('\u0008'),
            Char('w'), Char('o'), Char('r'), Char('d')
        ]
    elif vec_id == "mc-v1-004-multilingual-emoji":
        return [Char('🦀'), Char('🔑'), Char('©'), Char('\0')]
    elif vec_id == "mc-v1-005-single-blob":
        return [Blob(b"hello world")]
    elif vec_id == "mc-v1-006-empty-blob":
        return [Blob(b"")]
    elif vec_id == "mc-v1-007-mixed-text-and-blob":
        return [
            Char('P'), Char('a'), Blob(bytes([0x00, 0x01, 0x02])), Char('\u0008'), Char('x')
        ]
    elif vec_id == "mc-v1-008-multiple-blobs":
        return [Blob(bytes([0xde, 0xad])), Blob(bytes([0xbe, 0xef]))]
    raise ValueError(f"Unknown vector: {vec_id}")


def test_all_published_test_vectors():
    with open(VECTORS_PATH, "r", encoding="utf-8") as f:
        vectors = json.load(f)

    assert len(vectors) == 8

    for v in vectors:
        vec_id = v["id"]
        elements = build_vector_elements(vec_id)

        # 1. Canonical encoding match
        canonical = encode(elements)
        assert canonical.hex() == v["canonical_hex"], f"Canonical mismatch in {vec_id}"

        # 2. Round-trip parser check
        parsed = parse(canonical)
        assert parsed == elements, f"Parser roundtrip mismatch in {vec_id}"

        # 3. Domain-separated prehash match
        digest = streaming_prehash(elements)
        assert digest.hex() == v["prehash_hex"], f"Prehash mismatch in {vec_id}"

        # 4. Verifier match with fixed salt
        # Argon2 parameters
        p = v["argon2_params"]
        params = AuthParams(
            memory_cost_kib=p["memory_cost_kib"],
            iterations=p["iterations"],
            parallelism=p["parallelism"],
            salt_length_bytes=p["salt_length_bytes"],
            output_length_bytes=p["output_length_bytes"],
        )
        raw_salt = v["salt_b64"]
        padded_salt = raw_salt + "=" * (-len(raw_salt) % 4)
        salt_bytes = base64.b64decode(padded_salt)
        record = enroll_with_salt(elements, params, salt_bytes)
        assert record.verifier == v["expected_verifier"], f"Verifier PHC mismatch in {vec_id}"


        # 5. Verification against record
        res = verify(elements, record, ResourceLimits(max_memory_kib=1024*1024, max_iterations=20))
        assert res == VerifyResult.OK, f"Verification failed in {vec_id}"
