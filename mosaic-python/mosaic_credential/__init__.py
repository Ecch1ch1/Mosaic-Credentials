"""Mosaic Credential Python Library

Construct and verify structured authentication secrets composed of arbitrary
Unicode characters and arbitrary binary components in a user-selected sequence.

Follows the Mosaic Credential Technical Specification v0.1.
"""

from .core import (
    MAGIC,
    VERSION,
    PROFILE,
    TAG_CHAR,
    TAG_BLOB,
    TAG_END,
    PREHASH_PREFIX,
    BACKSPACE,
    Element,
    Char,
    Blob,
    Policy,
    CredentialBuilder,
    encode,
    parse,
    prehash,
    streaming_prehash,
    # Errors
    MosaicError,
    InvalidScalarError,
    UnsupportedVersionError,
    UnsupportedProfileError,
    InvalidTagError,
    TruncatedInputError,
    TrailingDataError,
    LengthMismatchError,
    LimitExceededError,
    IntegerOverflowError,
    RandomnessFailureError,
    InvalidVerifierError,
    ResourcePolicyRejectedError,
    BuilderFinalizedError,
)

from .auth import (
    AuthParams,
    ResourceLimits,
    VerifierRecord,
    VerifyResult,
    enroll,
    enroll_with_salt,
    verify,
    needs_upgrade,
    upgrade_verifier,
)

__version__ = "0.1.0"

__all__ = [
    "MAGIC",
    "VERSION",
    "PROFILE",
    "TAG_CHAR",
    "TAG_BLOB",
    "TAG_END",
    "PREHASH_PREFIX",
    "BACKSPACE",
    "Element",
    "Char",
    "Blob",
    "Policy",
    "CredentialBuilder",
    "encode",
    "parse",
    "prehash",
    "streaming_prehash",
    "MosaicError",
    "InvalidScalarError",
    "UnsupportedVersionError",
    "UnsupportedProfileError",
    "InvalidTagError",
    "TruncatedInputError",
    "TrailingDataError",
    "LengthMismatchError",
    "LimitExceededError",
    "IntegerOverflowError",
    "RandomnessFailureError",
    "InvalidVerifierError",
    "ResourcePolicyRejectedError",
    "BuilderFinalizedError",
    "AuthParams",
    "ResourceLimits",
    "VerifierRecord",
    "VerifyResult",
    "enroll",
    "enroll_with_salt",
    "verify",
    "needs_upgrade",
    "upgrade_verifier",
]
