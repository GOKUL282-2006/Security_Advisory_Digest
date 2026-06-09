from advisory_model import Advisory
from advisor_agent import AdvisorAgent


class FakeRepo:
    def query(self, product=None, severity=None):
        return [
            Advisory(
                id="CVE-2025-1234",
                source="nvd",
                product=product,
                severity="critical",
                description="OpenSSL 3.0.7 and prior versions are affected.",
                references=(),
            )
        ]


def test_agent_generates_findings(tmp_path):
    inventory = tmp_path / "stack.yaml"
    inventory.write_text("packages:\n  - name: openssl\n    version: '3.0.7'\n", encoding="utf-8")

    findings = AdvisorAgent(FakeRepo()).run(inventory)

    assert findings == [
        {
            "product": "openssl",
            "affected": True,
            "cve": "CVE-2025-1234",
            "severity": "critical",
            "confidence": "high",
            "advisory_id": "CVE-2025-1234",
        }
    ]
