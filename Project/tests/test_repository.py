from advisory_model import Advisory
from advisory_repository import AdvisoryRepository


def test_repository_crud_and_deduplication(tmp_path):
    repo = AdvisoryRepository(tmp_path / "advisories.db")
    advisory = Advisory(
        id="CVE-1",
        source="nvd",
        product="openssl",
        severity="high",
        description="first",
        references=("https://example.test/1",),
    )
    updated = Advisory(
        id="CVE-1",
        source="nvd",
        product="openssl",
        severity="critical",
        description="updated",
        references=("https://example.test/2",),
    )

    repo.insert(advisory)
    repo.insert(updated)

    assert repo.get("CVE-1").severity == "critical"
    assert len(repo.query(product="openssl")) == 1
    assert repo.delete("CVE-1") is True
    assert repo.get("CVE-1") is None
