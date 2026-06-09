from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Protocol

import requests
from requests import RequestException

from prompt_templates import SECURITY_DIGEST_PROMPT


class HttpClient(Protocol):
    def post(self, url: str, **kwargs: Any) -> Any:
        ...


@dataclass(slots=True)
class OllamaReportGenerator:
    model: str = "llama3"
    base_url: str = "http://localhost:11434/api/generate"
    http_client: HttpClient = requests
    timeout: float = 120.0

    def generate(self, findings: list[dict[str, Any]]) -> str:
        prompt = SECURITY_DIGEST_PROMPT.format(findings=json.dumps(findings, indent=2))
        try:
            response = self.http_client.post(
                self.base_url,
                json={"model": self.model, "prompt": prompt, "stream": False},
                timeout=self.timeout,
            )
            response.raise_for_status()
            text = response.json().get("response", "").strip()
        except (RequestException, ValueError, KeyError):
            text = ""
        return text or self._fallback(findings)

    @staticmethod
    def _fallback(findings: list[dict[str, Any]]) -> str:
        critical = [finding for finding in findings if str(finding.get("severity")).lower() == "critical"]
        lines = [
            "# Security Advisory Digest",
            "",
            "## Critical Issues",
            f"{len(critical)} critical issue(s) found.",
            "",
            "## Summary",
            f"{len(findings)} finding(s) were identified from the inventory.",
            "",
            "## Impact",
            "Affected products may be exposed to known vulnerabilities.",
            "",
            "## Recommendations",
            "Patch affected components and review advisory references.",
        ]
        return "\n".join(lines)


ReportGenerator = OllamaReportGenerator
