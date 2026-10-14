import io
import pytest
from mosaic_credential import (
    Char,
    Blob,
    Policy,
    CredentialBuilder,
    encode,
    streaming_prehash,
    enroll,
    verify,
    VerifyResult,
    AuthParams,
    ResourceLimits,
)

def test_16_1_text_chunking_equivalence():
    policy = Policy.default_generous()

    # Single add_text
    b1 = CredentialBuilder(policy)
    b1.add_text("Pass")
    c1 = b1.finalize()

    # Multiple add_text calls
    b2 = CredentialBuilder(policy)
    b2.add_text("P").add_text("as").add_text("s")
    c2 = b2.finalize()

    # Character by character
    b3 = CredentialBuilder(policy)
    b3.add_text("P").add_text("a").add_text("s").add_text("s")
    c3 = b3.finalize()

    assert c1 == c2 == c3
    assert encode(c1) == encode(c2) == encode(c3)
    assert streaming_prehash(c1) == streaming_prehash(c2) == streaming_prehash(c3)

def test_16_1_blob_stream_equivalence():
    data = b"Testing blob stream chunking buffer sizes 1234567890"

    b1 = CredentialBuilder()
    b1.add_blob(data)
    c1 = b1.finalize()

    b2 = CredentialBuilder()
    b2.add_blob_stream(io.BytesIO(data), len(data))
    c2 = b2.finalize()

    assert c1 == c2
    assert encode(c1) == encode(c2)
    assert streaming_prehash(c1) == streaming_prehash(c2)

def test_16_2_order_matters():
    c1 = [Char("A"), Char("B")]
    c2 = [Char("B"), Char("A")]

    assert encode(c1) != encode(c2)
    assert streaming_prehash(c1) != streaming_prehash(c2)

    params = AuthParams.fast_testing()
    record = enroll(c1, params)
    assert verify(c1, record) == VerifyResult.OK
    assert verify(c2, record) == VerifyResult.DENIED

def test_16_2_backspace_matters():
    b1 = CredentialBuilder()
    b1.add_text("Pass").add_backspace(3).add_text("word")
    c1 = b1.finalize()

    b2 = CredentialBuilder()
    b2.add_text("Pword")
    c2 = b2.finalize()

    assert encode(c1) != encode(c2)
    assert streaming_prehash(c1) != streaming_prehash(c2)

def test_16_2_char_vs_blob():
    c1 = [Char("A")]
    c2 = [Blob(b"A")]

    assert encode(c1) != encode(c2)
    assert streaming_prehash(c1) != streaming_prehash(c2)

def test_16_2_separate_blobs_vs_concatenated():
    c_split = [Blob(b"hello "), Blob(b"world")]
    c_concat = [Blob(b"hello world")]

    assert encode(c_split) != encode(c_concat)
    assert streaming_prehash(c_split) != streaming_prehash(c_concat)

def test_16_2_empty_blob_vs_absent():
    c_empty = [Blob(b"")]
    c_none = []

    assert encode(c_empty) != encode(c_none)
    assert streaming_prehash(c_empty) != streaming_prehash(c_none)

def test_16_2_literal_label_vs_control_char():
    c_literal = [Char("<"), Char("B"), Char("S"), Char(">")]
    c_actual = [Char("\u0008")]

    assert encode(c_literal) != encode(c_actual)
    assert streaming_prehash(c_literal) != streaming_prehash(c_actual)
