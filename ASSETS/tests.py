from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient

from .models import DlpPolicy, DlpRule, DlpThreat


class DlpPolicyModelTest(TestCase):
    def test_create_policy(self):
        policy = DlpPolicy.objects.create(
            code="test-policy",
            name="Test Policy",
            severity="high",
            scan_paths=["C:\\Users\\Public"],
            monitored_extensions=[".txt", ".pdf"],
        )
        self.assertEqual(str(policy), "test-policy: Test Policy (active)")
        self.assertTrue(policy.is_active)

    def test_create_policy_with_rules(self):
        policy = DlpPolicy.objects.create(code="test", name="Test", severity="medium")
        rule = DlpRule.objects.create(
            policy=policy,
            name="Confidential",
            classification="confidential",
            severity="critical",
            match_type="keyword",
            pattern="confidential",
        )
        self.assertEqual(rule.policy, policy)
        self.assertEqual(policy.rules.count(), 1)

    def test_inactive_policy_not_returned_by_default(self):
        DlpPolicy.objects.create(code="active", name="Active", is_active=True)
        DlpPolicy.objects.create(code="inactive", name="Inactive", is_active=False)
        active = DlpPolicy.objects.filter(is_active=True)
        self.assertEqual(active.count(), 1)


class DlpThreatModelTest(TestCase):
    def test_create_threat(self):
        threat = DlpThreat.objects.create(
            fingerprint="abc123",
            agent_id="00000000-0000-0000-0000-000000000001",
            agent_hostname="test-pc",
            policy_code="test-policy",
            rule_name="Test Rule",
            classification="confidential",
            severity="critical",
            file_name="secret.docx",
            file_path="C:\\Users\\test\\Desktop\\secret.docx",
            file_hash="deadbeef",
            actor="testuser",
            channel="desktop",
            summary="DLP match on secret.docx",
            matched_keywords=["confidential"],
        )
        self.assertEqual(str(threat), "[critical] secret.docx via desktop")
        self.assertFalse(threat.event_published)

    def test_deduplicate_by_fingerprint(self):
        _, created = DlpThreat.objects.get_or_create(
            fingerprint="dup1",
            defaults=dict(agent_id="00000000-0000-0000-0000-000000000001", file_name="a.txt"),
        )
        self.assertTrue(created)
        # Second attempt with same fingerprint should not create a new record
        obj, created = DlpThreat.objects.get_or_create(
            fingerprint="dup1",
            defaults=dict(agent_id="00000000-0000-0000-0000-000000000001", file_name="b.txt"),
        )
        self.assertFalse(created)
        self.assertEqual(obj.file_name, "a.txt")
        self.assertEqual(DlpThreat.objects.count(), 1)


class AgentDlpConfigApiTest(TestCase):
    def setUp(self):
        self.client = APIClient()

    def test_agent_dlp_config_empty(self):
        resp = self.client.get("/assets/api/agent/dlp/config/")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.data["policies"], [])

    def test_agent_dlp_config_returns_active_policies(self):
        policy = DlpPolicy.objects.create(
            code="test-policy", name="Test", severity="high", is_active=True,
        )
        DlpRule.objects.create(
            policy=policy, name="Rule1", classification="c1",
            severity="high", match_type="keyword", pattern="secret",
        )
        DlpPolicy.objects.create(
            code="inactive-policy", name="Inactive", severity="low", is_active=False,
        )

        resp = self.client.get("/assets/api/agent/dlp/config/")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(resp.data["policies"]), 1)
        self.assertEqual(resp.data["policies"][0]["code"], "test-policy")
        self.assertEqual(len(resp.data["policies"][0]["rules"]), 1)


class AgentSubmitThreatsApiTest(TestCase):
    def setUp(self):
        self.client = APIClient()

    @override_settings(
        REDIS_URL=None,
        CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    )
    def test_submit_valid_threat(self):
        payload = {
            "agent_id": "00000000-0000-0000-0000-000000000001",
            "incidents": [
                {
                    "fingerprint": "threat1",
                    "policy_code": "test",
                    "rule_name": "R1",
                    "classification": "confidential",
                    "severity": "critical",
                    "file_name": "secret.docx",
                    "file_path": "/tmp/secret.docx",
                    "actor": "user1",
                    "channel": "desktop",
                    "summary": "Match found",
                    "matched_keywords": ["secret"],
                }
            ],
        }
        resp = self.client.post("/assets/api/agent/dlp/threats/", payload, format="json")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.data["created"], 1)
        self.assertEqual(resp.data["skipped"], 0)

    @override_settings(
        REDIS_URL=None,
        CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    )
    def test_submit_duplicate_threat(self):
        payload = {
            "incidents": [{"fingerprint": "dup", "file_name": "a.txt"}],
        }
        self.client.post("/assets/api/agent/dlp/threats/", payload, format="json")
        resp = self.client.post("/assets/api/agent/dlp/threats/", payload, format="json")
        self.assertEqual(resp.data["created"], 0)
        self.assertEqual(resp.data["skipped"], 1)

    def test_submit_without_fingerprint_returns_error(self):
        payload = {
            "incidents": [{"file_name": "a.txt"}],
        }
        resp = self.client.post("/assets/api/agent/dlp/threats/", payload, format="json")
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_submit_empty_list_returns_error(self):
        payload = {"incidents": []}
        resp = self.client.post("/assets/api/agent/dlp/threats/", payload, format="json")
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)


class HealthCheckTest(TestCase):
    def setUp(self):
        self.client = APIClient()

    def test_health_returns_ok(self):
        resp = self.client.get("/assets/api/health/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(resp.data["status"], ["healthy", "degraded"])


class ThreatStatsTest(TestCase):
    def setUp(self):
        self.client = APIClient()

    def test_stats_empty(self):
        resp = self.client.get("/assets/api/stats/")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["total"], 0)

    def test_stats_with_data(self):
        DlpThreat.objects.create(
            fingerprint="s1", agent_id="00000000-0000-0000-0000-000000000001",
            severity="critical", file_name="a.txt",
        )
        DlpThreat.objects.create(
            fingerprint="s2", agent_id="00000000-0000-0000-0000-000000000001",
            severity="low", file_name="b.txt",
        )
        resp = self.client.get("/assets/api/stats/")
        self.assertEqual(resp.data["total"], 2)
        self.assertEqual(resp.data["by_severity"]["critical"], 1)
        self.assertEqual(resp.data["by_severity"]["low"], 1)
