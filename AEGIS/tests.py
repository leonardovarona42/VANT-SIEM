from datetime import datetime, timedelta, timezone
from django.test import TestCase, override_settings
from rest_framework import status
from rest_framework.test import APIClient

from .models import DlpPolicy, DlpRule, DlpThreat, DlpScanSummary


class DlpPolicyModelTest(TestCase):
    databases = ["vant_dlp"]
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

    def test_inactive_policy_not_returned(self):
        DlpPolicy.objects.create(code="active", name="Active", is_active=True)
        DlpPolicy.objects.create(code="inactive", name="Inactive", is_active=False)
        active = DlpPolicy.objects.filter(is_active=True)
        self.assertEqual(active.count(), 1)


class DlpThreatModelTest(TestCase):
    databases = ["vant_dlp"]
    def test_create_incident(self):
        incident = DlpThreat.objects.create(
            fingerprint="abc123",
            agent_id="agent-1",
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
            detected_at=datetime.now(timezone.utc),
        )
        self.assertFalse(incident.event_published)
        self.assertEqual(incident.status, "open")

    def test_deduplicate_by_fingerprint(self):
        _, created = DlpThreat.objects.get_or_create(
            fingerprint="dup1",
            defaults=dict(agent_id="agent-1", file_name="a.txt", detected_at=datetime.now(timezone.utc)),
        )
        self.assertTrue(created)
        obj, created = DlpThreat.objects.get_or_create(
            fingerprint="dup1",
            defaults=dict(agent_id="agent-1", file_name="b.txt", detected_at=datetime.now(timezone.utc)),
        )
        self.assertFalse(created)
        self.assertEqual(obj.file_name, "a.txt")
        self.assertEqual(DlpThreat.objects.count(), 1)


class DlpScanSummaryModelTest(TestCase):
    databases = ["vant_dlp"]

    def test_create_summary(self):
        summary = DlpScanSummary.objects.create(
            agent_id="agent-1",
            started_at=datetime.now(timezone.utc),
            files_scanned=100,
            files_flagged=3,
            status="completed",
        )
        self.assertEqual(summary.files_scanned, 100)
        self.assertEqual(str(summary.status), "completed")


class AgentDlpConfigApiTest(TestCase):
    databases = ["vant_dlp"]

    def setUp(self):
        self.client = APIClient()

    def test_agent_dlp_config_empty(self):
        resp = self.client.get("/aegis/api/agent/dlp/config/")
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
        resp = self.client.get("/aegis/api/agent/dlp/config/")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(resp.data["policies"]), 1)
        self.assertEqual(resp.data["policies"][0]["code"], "test-policy")
        self.assertEqual(len(resp.data["policies"][0]["rules"]), 1)


class AgentIngestThreatsApiTest(TestCase):
    databases = ["vant_dlp"]

    def setUp(self):
        self.client = APIClient()

    @override_settings(
        REDIS_URL=None,
        CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    )
    def test_ingest_valid_threat(self):
        payload = {
            "agent_id": "agent-1",
            "incidents": [{
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
                "detected_at": datetime.now(timezone.utc).isoformat(),
            }],
        }
        resp = self.client.post("/aegis/api/agent/dlp/threats/", payload, format="json")
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        self.assertEqual(resp.data["ingested"], 1)

    @override_settings(
        REDIS_URL=None,
        CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    )
    def test_ingest_duplicate(self):
        payload = {
            "incidents": [
                {"fingerprint": "dup", "file_name": "a.txt", "detected_at": datetime.now(timezone.utc).isoformat()},
            ],
        }
        self.client.post("/aegis/api/agent/dlp/threats/", payload, format="json")
        resp = self.client.post("/aegis/api/agent/dlp/threats/", payload, format="json")
        self.assertEqual(resp.data["ingested"], 0)
        self.assertEqual(resp.data["skipped"], 0)

    def test_ingest_without_fingerprint_returns_400(self):
        payload = {"incidents": [{"file_name": "a.txt"}]}
        resp = self.client.post("/aegis/api/agent/dlp/threats/", payload, format="json")
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_ingest_empty_list(self):
        payload = {"incidents": []}
        resp = self.client.post("/aegis/api/agent/dlp/threats/", payload, format="json")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.data["ingested"], 0)


class HealthCheckTest(TestCase):
    databases = ["vant_dlp"]

    def setUp(self):
        self.client = APIClient()

    def test_health_returns_ok(self):
        resp = self.client.get("/aegis/api/health/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(resp.data["status"], ["healthy", "degraded"])


class StatisticsApiTest(TestCase):
    databases = ["vant_dlp"]

    def setUp(self):
        self.client = APIClient()

    def test_stats_requires_admin(self):
        resp = self.client.get("/aegis/api/stats/")
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)
