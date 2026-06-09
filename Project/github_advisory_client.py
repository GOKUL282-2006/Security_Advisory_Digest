from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

import requests

from advisory_model import Advisory, AdvisorySource, normalize_severity


class HttpClient(Protocol):
    def get(self, url: str, **kwargs: Any) -> Any:
        ...


@dataclass(slots=True)
class GitHubAdvisoryClient:
    token: str | None = None
    http_client: HttpClient = requests
    base_url: str = "https://api.github.com/advisories"
    timeout: float = 20.0

    def fetch(self, ecosystem: str | None = None, package: str | None = None) -> list[Advisory]:
        params: dict[str, str] = {}
        if ecosystem:
            params["ecosystem"] = ecosystem
        if package:
            params["affects"] = package
        headers = {"Accept": "application/vnd.github+json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        response = self.http_client.get(
            self.base_url, headers=headers, params=params, timeout=self.timeout
        )
        response.raise_for_status()
        return [self.normalize(item) for item in response.json()]

    def normalize(self, item: dict[str, Any]) -> Advisory:
        package = self._package_name(item)
        references = tuple(ref for ref in item.get("references", []) if isinstance(ref, str))
        return Advisory(
            id=str(item.get("ghsa_id") or item.get("cve_id") or item.get("id") or ""),
            source=AdvisorySource.GITHUB.value,
            product=package,
            severity=normalize_severity(item.get("severity")),
            description=str(item.get("description") or item.get("summary") or ""),
            references=references,
        )

    def fetch_normalized(self, **kwargs: Any) -> list[dict[str, Any]]:
        return [self._legacy_shape(advisory) for advisory in self.fetch(**kwargs)]

    @staticmethod
    def _legacy_shape(advisory: Advisory) -> dict[str, Any]:
        return {
            "advisory_id": advisory.id,
            "package_name": advisory.product,
            "severity": advisory.severity,
            "description": advisory.description,
            "references": list(advisory.references),
        }

    @staticmethod
    def _package_name(item: dict[str, Any]) -> str:
        vulnerabilities = item.get("vulnerabilities") or []
        if vulnerabilities:
            package = vulnerabilities[0].get("package") or {}
            return str(package.get("name") or "")
        return ""
