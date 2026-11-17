"""Data model for SNMPv3 USM / VACM / session configuration."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Tuple

Oid = Tuple[int, ...]


def parse_oid(text: str) -> Oid:
    """Parse a dotted OID string (leading dot allowed) into a tuple of ints."""
    cleaned = text.strip().lstrip(".")
    if not cleaned:
        return ()
    return tuple(int(part) for part in cleaned.split("."))


def format_oid(oid: Oid) -> str:
    return "." + ".".join(str(part) for part in oid)


class SecurityLevel(Enum):
    NO_AUTH_NO_PRIV = 1
    AUTH_NO_PRIV = 2
    AUTH_PRIV = 3

    @classmethod
    def parse(cls, text: str) -> "SecurityLevel":
        normalized = text.strip().lower().replace("-", "").replace("_", "")
        mapping = {
            "noauthnopriv": cls.NO_AUTH_NO_PRIV,
            "authnopriv": cls.AUTH_NO_PRIV,
            "authpriv": cls.AUTH_PRIV,
        }
        if normalized not in mapping:
            raise ValueError(f"unknown security level: {text!r}")
        return mapping[normalized]


# RFC 3414 / RFC 7860 protocol identifiers (canonical short names).
AUTH_PROTOCOLS = {
    "HMAC-MD5": "usmHMACMD5AuthProtocol",
    "HMAC-SHA": "usmHMACSHAAuthProtocol",
    "HMAC-SHA-224": "usmHMAC128SHA224AuthProtocol",
    "HMAC-SHA-256": "usmHMAC192SHA256AuthProtocol",
    "HMAC-SHA-384": "usmHMAC256SHA384AuthProtocol",
    "HMAC-SHA-512": "usmHMAC384SHA512AuthProtocol",
}

PRIV_PROTOCOLS = {
    "DES": "usmDESPrivProtocol",
    "AES-128": "usmAesCfb128Protocol",
    "AES-192": "usmAesCfb192Protocol",
    "AES-256": "usmAesCfb256Protocol",
}

# Protocols considered cryptographically weak by current standards.
WEAK_AUTH_PROTOCOLS = {"HMAC-MD5"}
WEAK_PRIV_PROTOCOLS = {"DES"}


@dataclass
class UsmUser:
    """One USM user entry (vacmSecurityName source)."""

    name: str
    auth_protocol: Optional[str] = None  # key of AUTH_PROTOCOLS
    priv_protocol: Optional[str] = None  # key of PRIV_PROTOCOLS
    auth_key_set: bool = False
    priv_key_set: bool = False

    def max_security_level(self) -> SecurityLevel:
        if self.auth_protocol and self.priv_protocol:
            return SecurityLevel.AUTH_PRIV
        if self.auth_protocol:
            return SecurityLevel.AUTH_NO_PRIV
        return SecurityLevel.NO_AUTH_NO_PRIV


@dataclass
class SecurityToGroup:
    """vacmSecurityToGroupTable row."""

    security_model: str  # "usm"
    security_name: str
    group_name: str


@dataclass
class AccessEntry:
    """vacmAccessTable row."""

    group_name: str
    context_prefix: str = ""
    context_match: str = "exact"  # "exact" | "prefix"
    security_model: str = "usm"  # or "any"
    security_level: SecurityLevel = SecurityLevel.NO_AUTH_NO_PRIV
    read_view: Optional[str] = None
    write_view: Optional[str] = None
    notify_view: Optional[str] = None

    def context_matches(self, context: str) -> bool:
        if self.context_match == "prefix":
            return context.startswith(self.context_prefix)
        return context == self.context_prefix


@dataclass
class ViewSubtree:
    """vacmViewTreeFamilyTable row."""

    subtree: Oid
    included: bool = True
    mask: bytes = b""  # vacmViewTreeFamilyMask, empty = all bits significant


@dataclass
class View:
    """A named VACM view composed of included/excluded subtree families."""

    name: str
    families: list = field(default_factory=list)  # list[ViewSubtree]


@dataclass
class SessionConfig:
    """One management session to evaluate."""

    user: str
    security_level: SecurityLevel = SecurityLevel.NO_AUTH_NO_PRIV
    context: str = ""
    request: str = "read"  # "read" | "write"


@dataclass
class SnmpV3Config:
    users: list = field(default_factory=list)  # list[UsmUser]
    groups: list = field(default_factory=list)  # list[SecurityToGroup]
    access: list = field(default_factory=list)  # list[AccessEntry]
    views: dict = field(default_factory=dict)  # name -> View
    sessions: list = field(default_factory=list)  # list[SessionConfig]
    # Subtrees considered sensitive management data for the audit.
    management_subtrees: list = field(
        default_factory=lambda: [
            parse_oid("1.3.6.1.2.1.1"),  # system
            parse_oid("1.3.6.1.2.1.2"),  # interfaces
            parse_oid("1.3.6.1.6.3.15"),  # usmMIBObjects
            parse_oid("1.3.6.1.6.3.16"),  # vacmMIBObjects
        ]
    )
