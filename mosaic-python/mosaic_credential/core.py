"""Core data model, canonical binary encoder/parser, policy, and streaming prehash."""

from __future__ import annotations
import hashlib
import io
import struct
from dataclasses import dataclass
from typing import BinaryIO, List, Optional, Union

# Format constants (§6)
MAGIC = b"MCRD"
VERSION = 1
PROFILE = 1

TAG_CHAR = 0x01
TAG_BLOB = 0x02
TAG_END = 0xFF

HEADER_SIZE = 8
CHAR_SIZE = 5
BLOB_HEADER_SIZE = 9
END_SIZE = 1

BACKSPACE = "\u0008"
PREHASH_PREFIX = b"MOSAIC-CREDENTIAL/PREHASH/V1\x00"


# Internal diagnostic error codes (§13.4)
class MosaicError(Exception):
    """Base error for Mosaic Credential."""
    pass

class InvalidScalarError(MosaicError):
    def __init__(self, codepoint: int):
        super().__init__(f"INVALID_SCALAR: code point U+{codepoint:04X} is not a Unicode scalar value")
        self.codepoint = codepoint

class UnsupportedVersionError(MosaicError):
    def __init__(self, version: int):
        super().__init__(f"UNSUPPORTED_VERSION: version {version} is not supported")
        self.version = version

class UnsupportedProfileError(MosaicError):
    def __init__(self, profile: int):
        super().__init__(f"UNSUPPORTED_PROFILE: profile {profile} is not supported")
        self.profile = profile

class InvalidTagError(MosaicError):
    def __init__(self, tag: int):
        super().__init__(f"INVALID_TAG: tag 0x{tag:02X} is not recognized")
        self.tag = tag

class TruncatedInputError(MosaicError):
    def __init__(self, expected: int):
        super().__init__(f"TRUNCATED_INPUT: expected {expected} more bytes")
        self.expected = expected

class TrailingDataError(MosaicError):
    def __init__(self, count: int):
        super().__init__(f"TRAILING_DATA: {count} bytes after END marker")
        self.count = count

class LengthMismatchError(MosaicError):
    def __init__(self, declared: int, actual: int):
        super().__init__(f"LENGTH_MISMATCH: declared {declared} bytes, got {actual}")
        self.declared = declared
        self.actual = actual

class LimitExceededError(MosaicError):
    def __init__(self, description: str):
        super().__init__(f"LIMIT_EXCEEDED: {description}")
        self.description = description

class IntegerOverflowError(MosaicError):
    def __init__(self):
        super().__init__("INTEGER_OVERFLOW: size computation overflowed")

class RandomnessFailureError(MosaicError):
    def __init__(self):
        super().__init__("RANDOMNESS_FAILURE: could not obtain secure random bytes")

class InvalidVerifierError(MosaicError):
    def __init__(self, description: str):
        super().__init__(f"INVALID_VERIFIER: {description}")
        self.description = description

class ResourcePolicyRejectedError(MosaicError):
    def __init__(self, description: str):
        super().__init__(f"RESOURCE_POLICY_REJECTED: {description}")
        self.description = description

class BuilderFinalizedError(MosaicError):
    def __init__(self):
        super().__init__("BUILDER_FINALIZED: builder cannot accept further data")


def validate_scalar(codepoint: int) -> str:
    """Validate that codepoint is a valid Unicode scalar value (§4.1)."""
    if (0 <= codepoint <= 0xD7FF) or (0xE000 <= codepoint <= 0x10FFFF):
        return chr(codepoint)
    raise InvalidScalarError(codepoint)


@dataclass(frozen=True)
class Char:
    """A CHAR element representing one Unicode scalar value (§4.1)."""
    value: str

    def __post_init__(self):
        if len(self.value) != 1:
            raise ValueError("Char value must be a single Unicode character")
        cp = ord(self.value)
        validate_scalar(cp)

    @property
    def codepoint(self) -> int:
        return ord(self.value)


@dataclass(frozen=True)
class Blob:
    """A BLOB element representing an opaque byte sequence (§4.4)."""
    data: bytes

    def __post_init__(self):
        if not isinstance(self.data, (bytes, bytearray)):
            raise TypeError("Blob data must be bytes or bytearray")
        if isinstance(self.data, bytearray):
            object.__setattr__(self, "data", bytes(self.data))


Element = Union[Char, Blob]


@dataclass
class Policy:
    """Configurable size policies (§7.1)."""
    max_encoded_bits: int = 2_000_000_000  # 250 MB
    max_blob_bits: int = 2_000_000_000     # 250 MB
    max_elements: int = 100_000

    @property
    def max_encoded_bytes(self) -> int:
        return self.max_encoded_bits // 8

    @classmethod
    def default_generous(cls) -> Policy:
        return cls(2_000_000_000, 2_000_000_000, 100_000)

    @classmethod
    def text_only(cls) -> Policy:
        return cls(8_000, 0, 1_000)


class CredentialBuilder:
    """Incremental, single-use credential builder with policy enforcement (§12.3)."""

    def __init__(self, policy: Optional[Policy] = None):
        self.policy = policy or Policy.default_generous()
        self.elements: List[Element] = []
        self.finalized = False
        self.encoded_bytes = HEADER_SIZE
        self.element_count = 0

        # Check header fits
        if HEADER_SIZE > self.policy.max_encoded_bytes:
            raise LimitExceededError("Header size exceeds max_encoded_bits")

    def _check_not_finalized(self):
        if self.finalized:
            raise BuilderFinalizedError()

    def add_text(self, text: str) -> CredentialBuilder:
        """Add text as a sequence of CHAR elements (§4.2)."""
        self._check_not_finalized()
        for ch in text:
            cp = ord(ch)
            validate_scalar(cp)

            # Check element count
            new_count = self.element_count + 1
            if new_count > self.policy.max_elements:
                raise LimitExceededError(f"Element count ({new_count}) exceeds limit ({self.policy.max_elements})")

            # Check encoded bytes (tag 1 byte + codepoint 4 bytes = 5 bytes)
            new_bytes = self.encoded_bytes + CHAR_SIZE
            if new_bytes > self.policy.max_encoded_bytes:
                raise LimitExceededError(f"Encoded bytes ({new_bytes}) exceeds limit ({self.policy.max_encoded_bytes})")

            self.elements.append(Char(ch))
            self.element_count = new_count
            self.encoded_bytes = new_bytes
        return self

    def add_backspace(self, count: int = 1) -> CredentialBuilder:
        """Add `count` Backspace characters (U+0008) as secret elements (§5.1)."""
        self._check_not_finalized()
        if count < 0:
            raise ValueError("Backspace count must be non-negative")
        for _ in range(count):
            self.add_text(BACKSPACE)
        return self

    def add_blob(self, data: bytes) -> CredentialBuilder:
        """Add an opaque byte sequence as a BLOB element (§4.4)."""
        self._check_not_finalized()
        data_bytes = bytes(data)
        length = len(data_bytes)

        # Check blob bit limit
        blob_bits = length * 8
        if blob_bits > self.policy.max_blob_bits:
            raise LimitExceededError(f"BLOB size ({blob_bits} bits) exceeds limit ({self.policy.max_blob_bits})")

        # Check element limit
        new_count = self.element_count + 1
        if new_count > self.policy.max_elements:
            raise LimitExceededError(f"Element count ({new_count}) exceeds limit ({self.policy.max_elements})")

        # Check encoded bytes
        new_bytes = self.encoded_bytes + BLOB_HEADER_SIZE + length
        if new_bytes > self.policy.max_encoded_bytes:
            raise LimitExceededError(f"Encoded bytes ({new_bytes}) exceeds limit ({self.policy.max_encoded_bytes})")

        self.elements.append(Blob(data_bytes))
        self.element_count = new_count
        self.encoded_bytes = new_bytes
        return self

    def add_blob_stream(self, reader: BinaryIO, length_bytes: int) -> CredentialBuilder:
        """Stream a BLOB of declared length (§12.4)."""
        self._check_not_finalized()
        blob_bits = length_bytes * 8
        if blob_bits > self.policy.max_blob_bits:
            raise LimitExceededError(f"BLOB size ({blob_bits} bits) exceeds limit ({self.policy.max_blob_bits})")

        new_count = self.element_count + 1
        if new_count > self.policy.max_elements:
            raise LimitExceededError(f"Element count ({new_count}) exceeds limit ({self.policy.max_elements})")

        new_bytes = self.encoded_bytes + BLOB_HEADER_SIZE + length_bytes
        if new_bytes > self.policy.max_encoded_bytes:
            raise LimitExceededError(f"Encoded bytes ({new_bytes}) exceeds limit ({self.policy.max_encoded_bytes})")

        buf = bytearray()
        remaining = length_bytes
        while remaining > 0:
            chunk = reader.read(min(remaining, 8192))
            if not chunk:
                raise LengthMismatchError(declared=length_bytes, actual=length_bytes - remaining)
            buf.extend(chunk)
            remaining -= len(chunk)

        self.elements.append(Blob(bytes(buf)))
        self.element_count = new_count
        self.encoded_bytes = new_bytes
        return self

    def finalize(self) -> List[Element]:
        """Finalize the credential, accounting for the END marker. Single use!"""
        self._check_not_finalized()
        new_bytes = self.encoded_bytes + END_SIZE
        if new_bytes > self.policy.max_encoded_bytes:
            raise LimitExceededError(f"Encoded bytes with END ({new_bytes}) exceeds limit ({self.policy.max_encoded_bytes})")

        self.encoded_bytes = new_bytes
        self.finalized = True
        return list(self.elements)


def encode(elements: List[Element]) -> bytes:
    """Encode an ordered list of elements into the MC v1 canonical binary format (§6)."""
    out = bytearray()
    # Header: MCRD (4) + version (u16) + profile (u16)
    out.extend(MAGIC)
    out.extend(struct.pack(">HH", VERSION, PROFILE))

    for el in elements:
        if isinstance(el, Char):
            out.append(TAG_CHAR)
            out.extend(struct.pack(">I", el.codepoint))
        elif isinstance(el, Blob):
            out.append(TAG_BLOB)
            out.extend(struct.pack(">Q", len(el.data)))
            out.extend(el.data)
        else:
            raise TypeError(f"Unknown element type: {type(el)}")

    out.append(TAG_END)
    return bytes(out)


def parse(data: bytes) -> List[Element]:
    """Parse the canonical binary format with strict validation (§6)."""
    if len(data) < HEADER_SIZE:
        raise TruncatedInputError(expected=HEADER_SIZE - len(data))

    magic = data[0:4]
    if magic != MAGIC:
        raise InvalidTagError(magic[0])

    version, profile = struct.unpack(">HH", data[4:8])
    if version != VERSION:
        raise UnsupportedVersionError(version)
    if profile != PROFILE:
        raise UnsupportedProfileError(profile)

    cursor = HEADER_SIZE
    elements: List[Element] = []

    while cursor < len(data):
        tag = data[cursor]
        cursor += 1

        if tag == TAG_END:
            if cursor < len(data):
                raise TrailingDataError(len(data) - cursor)
            return elements

        elif tag == TAG_CHAR:
            if cursor + 4 > len(data):
                raise TruncatedInputError(expected=(cursor + 4) - len(data))
            cp = struct.unpack(">I", data[cursor:cursor+4])[0]
            cursor += 4
            ch = validate_scalar(cp)
            elements.append(Char(ch))

        elif tag == TAG_BLOB:
            if cursor + 8 > len(data):
                raise TruncatedInputError(expected=(cursor + 8) - len(data))
            length = struct.unpack(">Q", data[cursor:cursor+8])[0]
            cursor += 8
            available = len(data) - cursor
            if length > available:
                raise LengthMismatchError(declared=length, actual=available)
            payload = data[cursor:cursor+length]
            cursor += length
            elements.append(Blob(payload))

        else:
            raise InvalidTagError(tag)

    raise TruncatedInputError(expected=1)


def streaming_prehash(elements: List[Element]) -> bytes:
    """Compute domain-separated SHA-256 prehash streaming canonical bytes (§8.2)."""
    hasher = hashlib.sha256()
    hasher.update(PREHASH_PREFIX)

    # Stream Header
    hasher.update(MAGIC)
    hasher.update(struct.pack(">HH", VERSION, PROFILE))

    for el in elements:
        if isinstance(el, Char):
            hasher.update(bytes([TAG_CHAR]))
            hasher.update(struct.pack(">I", el.codepoint))
        elif isinstance(el, Blob):
            hasher.update(bytes([TAG_BLOB]))
            hasher.update(struct.pack(">Q", len(el.data)))
            hasher.update(el.data)

    hasher.update(bytes([TAG_END]))
    return hasher.digest()


def prehash(elements: List[Element]) -> bytes:
    """Prehash wrapper (equivalent to streaming_prehash)."""
    return streaming_prehash(elements)
