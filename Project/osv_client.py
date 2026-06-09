from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

import requests

from advisory_model import Advisory, AdvisorySource, normalize_severity


class HttpClient(Protocol):
    def post(self, url: str, **kwargs: Any) -> Any:
        ...


@dataclass(slots=True)
class OSVClient:
    http_client: HttpClient = requests
    base_url: str = "https://api.osv.dev/v1/query"
    timeout: float = 20.0

    def fetch(self, package_name: str, ecosystem: str, version: str | None = None) -> list[Advisory]:
        payload: dict[str, Any] = {"package": {"name": package_name, "ecosystem": ecosystem}}
        if version:
            payload["version"] = version
        response = self.http_client.post(self.base_url, json=payload, timeout=self.timeout)
        response.raise_for_status()
        return [self.normalize(vuln, fallback_product=package_name) for vuln in response.json().get("vulns", [])]

    def normalize(self, item: dict[str, Any], fallback_product: str = "") -> Advisory:
        references = tuple(
            ref.get("url", "") for ref in item.get("references", []) if isinstance(ref, dict) and ref.get("url")
        )
        affected = item.get("affected") or []
        product = fallback_product
        if affected:
            package = affected[0].get("package") or {}
            product = str(package.get("name") or fallback_product)
        severity = self._severity(item)
        return Advisory(
            id=str(item.get("id") or ""),
            source=AdvisorySource.OSV.value,
            product=product,
            severity=severity,
            description=str(item.get("summary") or item.get("details") or ""),
            references=references,
        )

    @staticmethod
    def _severity(item: dict[str, Any]) -> str:
        severities = item.get("severity") or []
        if severities:
            return normalize_severity(severities[0].get("score"))
        database_specific = item.get("database_specific") or {}
        return normalize_severity(database_specific.get("severity"))
