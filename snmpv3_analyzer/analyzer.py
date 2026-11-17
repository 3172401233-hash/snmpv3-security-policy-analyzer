"""SNMPv3 configuration analyzer.

Resolves the effective VACM permission of a USM user for a given OID and
audits the configuration for weak crypto, empty contexts, overly broad
views and noAuthNoPriv exposure of management subtrees.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Tuple

from .models import (
    AccessEntry,
    Oid,
    SecurityLevel,
    SecurityToGroup,
    SnmpV3Config,
    UsmUser,
    View,
    ViewSubtree,
    WEAK_AUTH_PROTOCOLS,
    WEAK_PRIV_PROTOCOLS,
    format_oid,
)

# OIDs at or above iso.org.dod.internet are considered "the whole world".
BROAD_VIEW_MAX_PREFIX: Oid = (1, 3, 6, 1)


def subtree_matches(oid: Oid, subtree: Oid, mask: bytes = b"") -> bool:
    """RFC 3415 vacmViewTreeFamilyMask matching.

    Each mask bit governs one sub-identifier of the family subtree: 1 means
    the OID must match that position, 0 means wildcard. An empty mask means
    every position is significant (plain prefix match).
    """
    if len(oid) < len(subtree):
        return False
    for index, expected in enumerate(subtree):
        byte_index, bit_index = divmod(index, 8)
        significant = True
        if byte_index < len(mask):
            significant = bool(mask[byte_index] & (1 << (7 - bit_index)))
        if significant and oid[index] != expected:
            return False
    return True


@dataclass
class PermissionResult:
    user: str
    oid: Oid
    request: str
    context: str
    security_level: SecurityLevel
    allowed: bool
    reason: str
    group: Optional[str] = None
    view: Optional[str] = None
    matched_subtree: Optional[Oid] = None


@dataclass
class Finding:
    severity: str  # "critical" | "high" | "medium" | "low"
    check: str
    message: str
    user: Optional[str] = None
    group: Optional[str] = None
    view: Optional[str] = None
    oid: Optional[Oid] = None

    def __str__(self) -> str:
        parts = [f"[{self.severity}] {self.check}: {self.message}"]
        location = []
        if self.user:
            location.append(f"user={self.user}")
        if self.group:
            location.append(f"group={self.group}")
        if self.view:
            location.append(f"view={self.view}")
        if self.oid is not None:
            location.append(f"oid={format_oid(self.oid)}")
        if location:
            parts.append("(" + ", ".join(location) + ")")
        return " ".join(parts)


class SnmpV3Analyzer:
    def __init__(self, config: SnmpV3Config):
        self.config = config
        self._users = {user.name: user for user in config.users}

    # ------------------------------------------------------------------
    # VACM resolution
    # ------------------------------------------------------------------
    def group_for_user(self, user_name: str) -> Optional[str]:
        for mapping in self.config.groups:
            if (
                isinstance(mapping, SecurityToGroup)
                and mapping.security_model in ("usm", "any")
                and mapping.security_name == user_name
            ):
                return mapping.group_name
        return None

    def _select_access_entry(
        self, group: str, context: str, level: SecurityLevel
    ) -> Optional[AccessEntry]:
        candidates = [
            entry
            for entry in self.config.access
            if entry.group_name == group
            and entry.security_model in ("usm", "any")
            and entry.security_level.value <= level.value
            and entry.context_matches(context)
        ]
        if not candidates:
            return None
        # Prefer the entry demanding the highest security level, then the
        # longest context prefix (most specific match wins).
        return max(
            candidates,
            key=lambda entry: (entry.security_level.value, len(entry.context_prefix)),
        )

    def _view_allows(self, view: View, oid: Oid) -> Tuple[bool, Optional[Oid]]:
        """Longest-prefix match across the view's families; excluded wins ties."""
        best: Optional[ViewSubtree] = None
        for family in view.families:
            if subtree_matches(oid, family.subtree, family.mask):
                if best is None or len(family.subtree) > len(best.subtree):
                    best = family
        if best is None:
            return False, None
        return best.included, best.subtree

    def effective_permission(
        self,
        user_name: str,
        oid: Oid,
        request: str = "read",
        context: str = "",
        security_level: Optional[SecurityLevel] = None,
    ) -> PermissionResult:
        user = self._users.get(user_name)
        if user is None:
            level = security_level or SecurityLevel.NO_AUTH_NO_PRIV
            return PermissionResult(
                user_name, oid, request, context, level, False,
                "unknown USM user",
            )
        level = security_level or user.max_security_level()
        if level.value > user.max_security_level().value:
            return PermissionResult(
                user_name, oid, request, context, level, False,
                "session security level exceeds the user's configured "
                "auth/priv capability",
            )

        group = self.group_for_user(user_name)
        if group is None:
            return PermissionResult(
                user_name, oid, request, context, level, False,
                "user is not mapped to any VACM group",
            )

        entry = self._select_access_entry(group, context, level)
        if entry is None:
            return PermissionResult(
                user_name, oid, request, context, level, False,
                "no vacmAccess entry matches group/context/securityLevel",
                group=group,
            )

        view_name = {
            "read": entry.read_view,
            "write": entry.write_view,
            "notify": entry.notify_view,
        }.get(request)
        if view_name is None:
            return PermissionResult(
                user_name, oid, request, context, level, False,
                f"access entry grants no {request} view",
                group=group,
            )
        view = self.config.views.get(view_name)
        if view is None:
            return PermissionResult(
                user_name, oid, request, context, level, False,
                f"view {view_name!r} referenced but not defined",
                group=group, view=view_name,
            )

        allowed, matched = self._view_allows(view, oid)
        reason = (
            f"allowed by included subtree {format_oid(matched)}"
            if allowed
            else (
                f"denied by excluded subtree {format_oid(matched)}"
                if matched is not None
                else "OID is outside every family in the view"
            )
        )
        return PermissionResult(
            user_name, oid, request, context, level, allowed, reason,
            group=group, view=view_name, matched_subtree=matched,
        )

    # ------------------------------------------------------------------
    # Audit
    # ------------------------------------------------------------------
    def audit(self) -> List[Finding]:
        findings: List[Finding] = []
        findings.extend(self._audit_users())
        findings.extend(self._audit_groups())
        findings.extend(self._audit_access_entries())
        findings.extend(self._audit_views())
        findings.extend(self._audit_no_auth_exposure())
        findings.extend(self._audit_sessions())
        return findings

    def _audit_users(self) -> List[Finding]:
        findings = []
        for user in self.config.users:
            group = self.group_for_user(user.name)
            if user.auth_protocol in WEAK_AUTH_PROTOCOLS:
                findings.append(Finding(
                    "high", "weak-auth-protocol",
                    f"user {user.name!r} uses weak HMAC "
                    f"({user.auth_protocol}); use SHA-2 family",
                    user=user.name, group=group,
                ))
            if user.priv_protocol in WEAK_PRIV_PROTOCOLS:
                findings.append(Finding(
                    "high", "weak-priv-protocol",
                    f"user {user.name!r} uses weak privacy protocol "
                    f"({user.priv_protocol}); use AES",
                    user=user.name, group=group,
                ))
            if user.auth_protocol and not user.auth_key_set:
                findings.append(Finding(
                    "high", "missing-auth-key",
                    f"user {user.name!r} configures "
                    f"{user.auth_protocol} but has no auth key",
                    user=user.name, group=group,
                ))
            if user.priv_protocol and not user.priv_key_set:
                findings.append(Finding(
                    "high", "missing-priv-key",
                    f"user {user.name!r} configures "
                    f"{user.priv_protocol} but has no privacy key",
                    user=user.name, group=group,
                ))
        return findings

    def _audit_groups(self) -> List[Finding]:
        findings = []
        for user in self.config.users:
            if self.group_for_user(user.name) is None:
                findings.append(Finding(
                    "medium", "unknown-group",
                    f"user {user.name!r} has no vacmSecurityToGroup mapping "
                    "and gets no access at all",
                    user=user.name,
                ))
        return findings

    def _audit_access_entries(self) -> List[Finding]:
        findings = []
        known_groups = {mapping.group_name for mapping in self.config.groups}
        for entry in self.config.access:
            if entry.group_name not in known_groups:
                findings.append(Finding(
                    "low", "orphan-access-entry",
                    f"access entry references group {entry.group_name!r} "
                    "with no members",
                    group=entry.group_name,
                ))
            if entry.context_prefix == "" and entry.context_match == "prefix":
                findings.append(Finding(
                    "medium", "empty-context",
                    f"group {entry.group_name!r} matches every context "
                    "(empty contextPrefix with prefix match)",
                    group=entry.group_name,
                ))
        return findings

    def _audit_views(self) -> List[Finding]:
        findings = []
        for view in self.config.views.values():
            for family in view.families:
                if family.included and len(family.subtree) <= len(BROAD_VIEW_MAX_PREFIX):
                    findings.append(Finding(
                        "medium", "broad-view",
                        f"view {view.name!r} includes "
                        f"{format_oid(family.subtree)}, covering the entire "
                        "internet subtree",
                        view=view.name, oid=family.subtree,
                    ))
        return findings

    def _audit_no_auth_exposure(self) -> List[Finding]:
        findings = []
        for user in self.config.users:
            if user.max_security_level() != SecurityLevel.NO_AUTH_NO_PRIV:
                continue
            for subtree in self.config.management_subtrees:
                result = self.effective_permission(
                    user.name, subtree, "read", "",
                    SecurityLevel.NO_AUTH_NO_PRIV,
                )
                if result.allowed:
                    findings.append(Finding(
                        "critical", "noauth-management-read",
                        f"noAuthNoPriv user {user.name!r} can read the "
                        f"management subtree {format_oid(subtree)}",
                        user=user.name, group=result.group,
                        view=result.view, oid=subtree,
                    ))
        return findings

    def _audit_sessions(self) -> List[Finding]:
        findings = []
        for session in self.config.sessions:
            user = self._users.get(session.user)
            if user is None:
                findings.append(Finding(
                    "medium", "session-unknown-user",
                    f"session references unknown user {session.user!r}",
                    user=session.user,
                ))
                continue
            if session.security_level.value > user.max_security_level().value:
                findings.append(Finding(
                    "high", "session-level-mismatch",
                    f"session for {session.user!r} requests "
                    f"{session.security_level.name} but the user only "
                    f"supports {user.max_security_level().name}",
                    user=session.user, group=self.group_for_user(user.name),
                ))
            if (
                session.security_level == SecurityLevel.NO_AUTH_NO_PRIV
                and user.auth_protocol
            ):
                findings.append(Finding(
                    "medium", "session-downgrade",
                    f"session for {session.user!r} runs noAuthNoPriv even "
                    "though the user has authentication configured",
                    user=session.user, group=self.group_for_user(user.name),
                ))
        return findings
