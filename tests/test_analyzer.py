import unittest

from snmpv3_analyzer import (
    AccessEntry,
    SecurityLevel,
    SecurityToGroup,
    SessionConfig,
    SnmpV3Analyzer,
    SnmpV3Config,
    UsmUser,
    View,
    ViewSubtree,
    parse_oid,
    subtree_matches,
)

SYSTEM = parse_oid("1.3.6.1.2.1.1")
SYS_DESCR = parse_oid("1.3.6.1.2.1.1.1.0")
SYS_NAME = parse_oid("1.3.6.1.2.1.1.5.0")
IF_TABLE = parse_oid("1.3.6.1.2.1.2.2")
ENTERPRISES = parse_oid("1.3.6.1.4.1")


def base_config() -> SnmpV3Config:
    """Mirror of the scenario: a noAuthNoPriv user that can read management
    OIDs, and an authenticated user with a weak HMAC."""
    return SnmpV3Config(
        users=[
            UsmUser("guest"),
            UsmUser("ops", auth_protocol="HMAC-MD5", auth_key_set=True),
            UsmUser("admin", auth_protocol="HMAC-SHA-256", auth_key_set=True,
                    priv_protocol="AES-128", priv_key_set=True),
        ],
        groups=[
            SecurityToGroup("usm", "guest", "guest-grp"),
            SecurityToGroup("usm", "ops", "ops-grp"),
            SecurityToGroup("usm", "admin", "admin-grp"),
        ],
        access=[
            AccessEntry("guest-grp", read_view="mgmt-view"),
            AccessEntry("ops-grp", security_level=SecurityLevel.AUTH_NO_PRIV,
                        read_view="mgmt-view"),
            AccessEntry("admin-grp", security_level=SecurityLevel.AUTH_PRIV,
                        read_view="all-view", write_view="all-view"),
        ],
        views={
            "mgmt-view": View("mgmt-view", [
                ViewSubtree(SYSTEM, included=True),
                ViewSubtree(IF_TABLE, included=True),
            ]),
            "all-view": View("all-view", [
                ViewSubtree(parse_oid("1.3.6.1"), included=True),
            ]),
        },
    )


class TestSubtreeMatching(unittest.TestCase):
    def test_plain_prefix(self):
        self.assertTrue(subtree_matches(SYS_DESCR, SYSTEM))
        self.assertFalse(subtree_matches(ENTERPRISES, SYSTEM))
        self.assertFalse(subtree_matches(SYSTEM, SYS_DESCR))

    def test_mask_wildcard(self):
        # Subtree covers the ifTable columns; the last sub-identifier
        # (index 9) differs between ifDescr(2) and ifType(3).
        subtree = parse_oid("1.3.6.1.2.1.2.2.1.2")
        oid = parse_oid("1.3.6.1.2.1.2.2.1.3")
        # Bit 9 set (0x40 in the second byte) -> significant -> mismatch.
        self.assertFalse(subtree_matches(oid, subtree, b"\xff\x40"))
        # Bit 9 clear -> wildcard -> match.
        self.assertTrue(subtree_matches(oid, subtree, b"\xff\x00"))


class TestEffectivePermission(unittest.TestCase):
    def setUp(self):
        self.analyzer = SnmpV3Analyzer(base_config())

    def test_noauth_user_reads_management_oid(self):
        result = self.analyzer.effective_permission("guest", SYS_DESCR)
        self.assertTrue(result.allowed)
        self.assertEqual(result.group, "guest-grp")
        self.assertEqual(result.view, "mgmt-view")
        self.assertEqual(result.matched_subtree, SYSTEM)

    def test_oid_outside_view_denied(self):
        result = self.analyzer.effective_permission("guest", ENTERPRISES)
        self.assertFalse(result.allowed)
        self.assertIn("outside", result.reason)

    def test_subtree_overlap_longest_match_wins(self):
        config = base_config()
        config.views["overlap"] = View("overlap", [
            ViewSubtree(parse_oid("1.3.6.1.2.1"), included=True),
            ViewSubtree(SYSTEM, included=False),
        ])
        config.access.append(AccessEntry(
            "guest-grp", context_prefix="ov", context_match="prefix",
            read_view="overlap",
        ))
        analyzer = SnmpV3Analyzer(config)
        # sysDescr falls under the more specific excluded family.
        denied = analyzer.effective_permission("guest", SYS_DESCR, context="ov")
        self.assertFalse(denied.allowed)
        self.assertEqual(denied.matched_subtree, SYSTEM)
        # ifTable only matches the broader included family.
        allowed = analyzer.effective_permission(
            "guest", parse_oid("1.3.6.1.2.1.2.2.1.1.1"), context="ov")
        self.assertTrue(allowed.allowed)

    def test_excluded_node(self):
        config = base_config()
        config.views["mgmt-view"].families.append(
            ViewSubtree(parse_oid("1.3.6.1.2.1.1.5"), included=False))
        analyzer = SnmpV3Analyzer(config)
        self.assertFalse(
            analyzer.effective_permission("guest", SYS_NAME).allowed)
        self.assertTrue(
            analyzer.effective_permission("guest", SYS_DESCR).allowed)

    def test_security_level_gating(self):
        # ops-grp requires authNoPriv; a noAuthNoPriv session gets nothing.
        low = self.analyzer.effective_permission(
            "ops", SYS_DESCR, security_level=SecurityLevel.NO_AUTH_NO_PRIV)
        self.assertFalse(low.allowed)
        ok = self.analyzer.effective_permission(
            "ops", SYS_DESCR, security_level=SecurityLevel.AUTH_NO_PRIV)
        self.assertTrue(ok.allowed)

    def test_session_level_above_user_capability(self):
        result = self.analyzer.effective_permission(
            "ops", SYS_DESCR, security_level=SecurityLevel.AUTH_PRIV)
        self.assertFalse(result.allowed)
        self.assertIn("exceeds", result.reason)

    def test_unknown_group(self):
        config = base_config()
        config.users.append(UsmUser("orphan"))
        analyzer = SnmpV3Analyzer(config)
        result = analyzer.effective_permission("orphan", SYS_DESCR)
        self.assertFalse(result.allowed)
        self.assertIn("not mapped to any VACM group", result.reason)
        checks = {finding.check for finding in analyzer.audit()}
        self.assertIn("unknown-group", checks)

    def test_read_only_request(self):
        # guest-grp has no write view: writes are denied, reads allowed.
        read = self.analyzer.effective_permission("guest", SYS_DESCR, "read")
        write = self.analyzer.effective_permission("guest", SYS_NAME, "write")
        self.assertTrue(read.allowed)
        self.assertFalse(write.allowed)
        self.assertIn("no write view", write.reason)
        # admin has a write view at authPriv.
        admin_write = self.analyzer.effective_permission(
            "admin", SYS_NAME, "write",
            security_level=SecurityLevel.AUTH_PRIV)
        self.assertTrue(admin_write.allowed)


class TestAudit(unittest.TestCase):
    def setUp(self):
        self.analyzer = SnmpV3Analyzer(base_config())
        self.findings = self.analyzer.audit()
        self.by_check = {}
        for finding in self.findings:
            self.by_check.setdefault(finding.check, []).append(finding)

    def test_weak_hmac_flagged(self):
        weak = self.by_check["weak-auth-protocol"]
        self.assertEqual(len(weak), 1)
        self.assertEqual(weak[0].user, "ops")
        self.assertEqual(weak[0].group, "ops-grp")

    def test_noauth_management_read_located(self):
        exposure = self.by_check["noauth-management-read"]
        self.assertTrue(exposure)
        for finding in exposure:
            self.assertEqual(finding.user, "guest")
            self.assertEqual(finding.group, "guest-grp")
            self.assertEqual(finding.view, "mgmt-view")
            self.assertIsNotNone(finding.oid)

    def test_broad_view_flagged(self):
        broad = self.by_check["broad-view"]
        self.assertEqual(len(broad), 1)
        self.assertEqual(broad[0].view, "all-view")
        self.assertEqual(broad[0].oid, parse_oid("1.3.6.1"))

    def test_empty_context_flagged(self):
        config = base_config()
        config.access.append(AccessEntry(
            "guest-grp", context_prefix="", context_match="prefix",
            read_view="mgmt-view",
        ))
        checks = {f.check for f in SnmpV3Analyzer(config).audit()}
        self.assertIn("empty-context", checks)

    def test_missing_keys_flagged(self):
        config = base_config()
        config.users.append(UsmUser(
            "broken", auth_protocol="HMAC-SHA", auth_key_set=False,
            priv_protocol="DES", priv_key_set=False))
        findings = SnmpV3Analyzer(config).audit()
        checks = {f.check for f in findings}
        self.assertIn("missing-auth-key", checks)
        self.assertIn("missing-priv-key", checks)
        self.assertIn("weak-priv-protocol", checks)

    def test_session_audit(self):
        config = base_config()
        config.sessions = [
            SessionConfig("ops", SecurityLevel.AUTH_PRIV),       # too high
            SessionConfig("admin", SecurityLevel.NO_AUTH_NO_PRIV),  # downgrade
            SessionConfig("ghost", SecurityLevel.NO_AUTH_NO_PRIV),  # unknown
        ]
        checks = {f.check for f in SnmpV3Analyzer(config).audit()}
        self.assertIn("session-level-mismatch", checks)
        self.assertIn("session-downgrade", checks)
        self.assertIn("session-unknown-user", checks)


if __name__ == "__main__":
    unittest.main()
