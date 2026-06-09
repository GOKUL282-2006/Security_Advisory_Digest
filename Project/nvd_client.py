from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

import requests

from advisory_model import Advisory, AdvisorySource, normalize_severity


class HttpClient(Protocol):
    def get(self, url: str, **kwargs: Any) -> Any:
        ...


@dataclass(slots=True)
class NVDClient:
    api_key: str | None = None
    http_client: HttpClient = requests
    base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    timeout: float = 20.0

    def fetch(self, keyword: str | None = None) -> list[Advisory]:
        params: dict[str, str] = {}
        if keyword:
            params["keywordSearch"] = keyword
        headers: dict[str, str] = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        response = self.http_client.get(
            self.base_url, params=params, headers=headers, timeout=self.timeout
        )
        response.raise_for_status()
        return [self.normalize(item, fallback_product=keyword or "") for item in response.json().get("vulnerabilities", [])]

    def normalize(self, item: dict[str, Any], fallback_product: str = "") -> Advisory:
        cve = item.get("cve") or item
        advisory_id = str(cve.get("id") or "")
        descriptions = cve.get("descriptions") or []
        description = ""
        for entry in descriptions:
            if entry.get("lang") == "en":
                description = str(entry.get("value") or "")
                break
        references = tuple(
            ref.get("url", "") for ref in (cve.get("references") or {}).get("referenceData", []) if ref.get("url")
        )
        return Advisory(
            id=advisory_id,
            source=AdvisorySource.NVD.value,
            product=fallback_product,
            severity=self._severity(cve),
            description=description,
            references=references,
        )

    @staticmethod
    def _severity(cve: dict[str, Any]) -> str:
        metrics = cve.get("metrics") or {}
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key) or []
            if entries:
                cvss = entries[0].get("cvssData") or {}
                return normalize_severity(entries[0].get("baseSeverity") or cvss.get("baseSeverity"))
        return "unknown"
