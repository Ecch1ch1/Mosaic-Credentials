"""Enrollment, verification, record validation, and upgrades for Mosaic Credential."""

from __future__ import annotations
import base64
import json
import secrets
from dataclasses import asdict, dataclass
from enum import Enum
from typing import List, Optional

import argon2
from argon2.low_level import Type

from .core import (
    Element,
    InvalidVerifierError,
    ResourcePolicyRejectedError,
    streaming_prehash,
)


@dataclass
class AuthParams:
    """Argon2id parameter configuration (§8.3)."""
    memory_cost_kib: int = 65536
    iterations: int = 3
    parallelism: int = 1
    salt_length_bytes: int = 16
    output_length_bytes: int = 32

    @classmethod
    def default(cls) -> AuthParams:
        return cls(65536, 3, 1, 16, 32)

    @classmethod
    def fast_testing(cls) -> AuthParams:
        return cls(256, 1, 1, 16, 32)

    def validate(self):
        if self.memory_cost_kib < 8:
            raise ResourcePolicyRejectedError(f"memory_cost_kib ({self.memory_cost_kib}) is below minimum (8 KiB)")
        if self.memory_cost_kib > 4 * 1024 * 1024:
            raise ResourcePolicyRejectedError(f"memory_cost_kib ({self.memory_cost_kib}) exceeds maximum (4 GiB)")
        if self.iterations < 1:
            raise ResourcePolicyRejectedError("iterations must be at least 1")
        if self.iterations > 1000:
            raise ResourcePolicyRejectedError(f"iterations ({self.iterations}) exceeds maximum (1000)")
        if self.parallelism < 1:
            raise ResourcePolicyRejectedError("parallelism must be at least 1")
        if self.parallelism > 256:
            raise ResourcePolicyRejectedError(f"parallelism ({self.parallelism}) exceeds maximum (256)")
        if self.salt_length_bytes < 8:
            raise ResourcePolicyRejectedError(f"salt_length_bytes ({self.salt_length_bytes}) is below minimum (8)")
        if self.output_length_bytes < 16:
            raise ResourcePolicyRejectedError(f"output_length_bytes ({self.output_length_bytes}) is below minimum (16)")


@dataclass
class ResourceLimits:
    """Resource limits for accepting stored verifier parameters during verification (§13.3)."""
    max_memory_kib: int = 256 * 1024
    max_iterations: int = 10
    max_parallelism: int = 4

    @classmethod
    def default(cls) -> ResourceLimits:
        return cls()

    def check(self, params: AuthParams):
        if params.memory_cost_kib > self.max_memory_kib:
            raise ResourcePolicyRejectedError(
                f"memory_cost_kib ({params.memory_cost_kib}) exceeds resource limit ({self.max_memory_kib})"
            )
        if params.iterations > self.max_iterations:
            raise ResourcePolicyRejectedError(
                f"iterations ({params.iterations}) exceeds resource limit ({self.max_iterations})"
            )
        if params.parallelism > self.max_parallelism:
            raise ResourcePolicyRejectedError(
                f"parallelism ({params.parallelism}) exceeds resource limit ({self.max_parallelism})"
            )


@dataclass
class VerifierRecord:
    """Stored verifier record schema (§9)."""
    format: str = "mosaic-credential"
    format_version: int = 1
    profile: int = 1
    prehash: str = "sha256-domain-v1"
    verifier: str = ""

    FORMAT = "mosaic-credential"
    PREHASH_ID = "sha256-domain-v1"

    def validate(self):
        if self.format != self.FORMAT:
            raise InvalidVerifierError(f"unsupported format: expected '{self.FORMAT}', got '{self.format}'")
        if self.format_version != 1:
            raise InvalidVerifierError(f"unsupported format_version: expected 1, got {self.format_version}")
        if self.profile != 1:
            raise InvalidVerifierError(f"unsupported profile: expected 1, got {self.profile}")
        if self.prehash != self.PREHASH_ID:
            raise InvalidVerifierError(f"unsupported prehash: expected '{self.PREHASH_ID}', got '{self.prehash}'")
        if not self.verifier:
            raise InvalidVerifierError("verifier string is empty")
        if not self.verifier.startswith("$argon2id$"):
            raise InvalidVerifierError("verifier does not appear to be an Argon2id PHC string")

    def to_json(self, indent: Optional[int] = 2) -> str:
        return json.dumps(asdict(self), indent=indent)

    @classmethod
    def from_json(cls, json_str: str) -> VerifierRecord:
        data = json.loads(json_str)
        return cls(
            format=data.get("format", ""),
            format_version=data.get("format_version", 0),
            profile=data.get("profile", 0),
            prehash=data.get("prehash", ""),
            verifier=data.get("verifier", ""),
        )


class VerifyResult(Enum):
    OK = "OK"
    DENIED = "DENIED"


def _hash_argon2(digest: bytes, salt: bytes, params: AuthParams) -> str:
    """Derive Argon2id PHC string."""
    hash_bytes = argon2.low_level.hash_secret(
        secret=digest,
        salt=salt,
        time_cost=params.iterations,
        memory_cost=params.memory_cost_kib,
        parallelism=params.parallelism,
        hash_len=params.output_length_bytes,
        type=Type.ID,
    )
    return hash_bytes.decode("ascii")


def enroll(elements: List[Element], params: Optional[AuthParams] = None) -> VerifierRecord:
    """Enroll a credential: stream canonical serialization into SHA-256 prehash,

    generate a fresh random salt from OS CSPRNG, derive Argon2id verifier, and return VerifierRecord (§10.1).
    """
    params = params or AuthParams.default()
    params.validate()

    digest = streaming_prehash(elements)
    salt = secrets.token_bytes(params.salt_length_bytes)
    phc = _hash_argon2(digest, salt, params)
    return VerifierRecord(verifier=phc)


def enroll_with_salt(
    elements: List[Element],
    params: AuthParams,
    salt: bytes,
) -> VerifierRecord:
    """Enroll with a fixed salt — FOR TESTING AND DETERMINISTIC TEST VECTORS ONLY (§16.4)."""
    params.validate()
    digest = streaming_prehash(elements)
    phc = _hash_argon2(digest, salt, params)
    return VerifierRecord(verifier=phc)


def parse_phc_params(phc: str) -> Optional[AuthParams]:
    """Extract parameters from an Argon2id PHC string."""
    try:
        parts = phc.split("$")
        # $argon2id$v=19$m=65536,t=3,p=1$...
        if len(parts) < 5 or parts[1] != "argon2id":
            return None
        param_part = parts[3]
        params_dict = {}
        for item in param_part.split(","):
            k, v = item.split("=")
            params_dict[k] = int(v)

        return AuthParams(
            memory_cost_kib=params_dict.get("m", 65536),
            iterations=params_dict.get("t", 3),
            parallelism=params_dict.get("p", 1),
            salt_length_bytes=16,
            output_length_bytes=32,
        )
    except Exception:
        return None


def verify(
    elements: List[Element],
    record: VerifierRecord,
    limits: Optional[ResourceLimits] = None,
) -> VerifyResult:
    """Verify a candidate credential against a stored record (§10.2).

    Returns VerifyResult.OK on match, VerifyResult.DENIED otherwise.
    Never exposes internal error details to caller.
    """
    try:
        record.validate()
        limits = limits or ResourceLimits()

        params = parse_phc_params(record.verifier)
        if params is not None:
            limits.check(params)

        digest = streaming_prehash(elements)
        argon2.low_level.verify_secret(
            record.verifier.encode("ascii"),
            digest,
            Type.ID,
        )
        return VerifyResult.OK
    except Exception:
        return VerifyResult.DENIED


def needs_upgrade(record: VerifierRecord, target_params: AuthParams) -> bool:
    """Check if stored verifier parameters are weaker than target parameters (§10.2 step 7, §10.3)."""
    current_params = parse_phc_params(record.verifier)
    if not current_params:
        return False
    return (
        current_params.memory_cost_kib < target_params.memory_cost_kib
        or current_params.iterations < target_params.iterations
        or current_params.parallelism < target_params.parallelism
    )


def upgrade_verifier(elements: List[Element], target_params: AuthParams) -> VerifierRecord:
    """Upgrade verifier after successful verification (§10.3)."""
    return enroll(elements, target_params)
