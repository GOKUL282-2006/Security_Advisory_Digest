from github_advisory_client import GitHubAdvisoryClient
from nvd_client import NVDClient
from osv_client import OSVClient


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


class FakeGitHubHttp:
    def get(self, url, **kwargs):
        return FakeResponse(
            [
                {
                    "ghsa_id": "GHSA-1234",
                    "severity": "HIGH",
                    "summary": "summary",
                    "description": "desc",
                    "references": ["https://example.test/a"],
                    "vulnerabilities": [{"package": {"name": "openssl"}}],
                }
            ]
        )


class FakeOSVHttp:
    def post(self, url, **kwargs):
        return FakeResponse(
            {
                "vulns": [
                    {
                        "id": "OSV-1",
                        "summary": "bad package",
                        "affected": [{"package": {"name": "requests"}}],
                        "database_specific": {"severity": "CRITICAL"},
                        "references": [{"url": "https://osv.dev/OSV-1"}],
                    }
                ]
            }
        )


class FakeNVDHttp:
    def get(self, url, **kwargs):
        return FakeResponse(
            {
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2025-1234",
                            "descriptions": [{"lang": "en", "value": "OpenSSL issue"}],
                            "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "CRITICAL"}}]},
                            "references": {"referenceData": [{"url": "https://nvd.test/CVE-2025-1234"}]},
                        }
                    }
                ]
            }
        )


def test_github_client_normalizes_common_schema():
    advisories = GitHubAdvisoryClient(http_client=FakeGitHubHttp()).fetch(package="openssl")

    assert advisories[0].id == "GHSA-1234"
    assert advisories[0].source == "github"
    assert advisories[0].product == "openssl"
    assert advisories[0].severity == "high"


def test_github_client_legacy_shape():
    advisories = GitHubAdvisoryClient(http_client=FakeGitHubHttp()).fetch_normalized(package="openssl")

    assert advisories[0]["advisory_id"] == "GHSA-1234"
    assert advisories[0]["package_name"] == "openssl"


def test_osv_client_normalizes_common_schema():
    advisories = OSVClient(http_client=FakeOSVHttp()).fetch("requests", "PyPI")

    assert advisories[0].id == "OSV-1"
    assert advisories[0].source == "osv"
    assert advisories[0].product == "requests"
    assert advisories[0].severity == "critical"


def test_nvd_client_normalizes_common_schema():
    advisories = NVDClient(http_client=FakeNVDHttp()).fetch(keyword="openssl")

    assert advisories[0].id == "CVE-2025-1234"
    assert advisories[0].source == "nvd"
    assert advisories[0].product == "openssl"
    assert advisories[0].severity == "critical"
