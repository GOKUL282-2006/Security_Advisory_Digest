from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from advisory_model import Advisory
from advisory_repository import AdvisoryRepository
from inventory_parser import InventoryItem, parse_inventory


class AdvisorySearcher(Protocol):
    def query(self, product: str | None = None, severity: str | None = None) -> list[Advisory]:
        ...


@dataclass(frozen=True, slots=True)
class Finding:
    product: str
    affected: bool
    cve: str
    severity: str
    confidence: str = "medium"
    advisory_id: str | None = None

    def to_dict(self) -> dict[str, str | bool | None]:
        return {
            "product": self.product,
            "affected": self.affected,
            "cve": self.cve,
            "severity": self.severity,
            "confidence": self.confidence,
            "advisory_id": self.advisory_id,
        }


class AdvisorAgent:
    def __init__(self, repository: AdvisorySearcher | None = None) -> None:
        self.repository = repository or AdvisoryRepository()

    def run(self, inventory_path: str | Path) -> list[dict[str, str | bool | None]]:
        inventory = parse_inventory(inventory_path)
        findings: list[Finding] = []
        for item in inventory:
            for advisory in self.repository.query(product=item.product):
                findings.append(self._evaluate(item, advisory))
        return [finding.to_dict() for finding in findings]

    def _evaluate(self, item: InventoryItem, advisory: Advisory) -> Finding:
        affected, confidence = self._version_relevance(item, advisory)
        return Finding(
            product=item.product,
            affected=affected,
            cve=self._cve(advisory),
            severity=advisory.severity,
            confidence=confidence,
            advisory_id=advisory.id,
        )

    @staticmethod
    def _version_relevance(item: InventoryItem, advisory: Advisory) -> tuple[bool, str]:
        if not item.version:
            return True, "low"
        text = advisory.description.lower()
        version = item.version.lower()
        if version in text:
            return True, "high"
        if any(term in text for term in ("all versions", "prior to", "before", "<", "through")):
            return True, "medium"
        return True, "low"

    @staticmethod
    def _cve(advisory: Advisory) -> str:
        match = re.search(r"CVE-\d{4}-\d{4,}", advisory.id + " " + advisory.description, re.I)
        return match.group(0).upper() if match else advisory.id
