from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping


class AdvisorySource(str, Enum):
    NVD = "nvd"
    GITHUB = "github"
    OSV = "osv"


@dataclass(frozen=True, slots=True)
class Advisory:
    id: str
    source: str
    product: str
    severity: str
    description: str
    references: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not self.id:
            raise ValueError("advisory id is required")
        if not self.source:
            raise ValueError("advisory source is required")

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "Advisory":
        refs = data.get("references") or ()
        if isinstance(refs, str):
            refs = (refs,)
        return cls(
            id=str(data.get("id") or data.get("advisory_id") or data.get("cve") or ""),
            source=str(data.get("source") or ""),
            product=str(data.get("product") or data.get("package_name") or ""),
            severity=str(data.get("severity") or "unknown").lower(),
            description=str(data.get("description") or ""),
            references=tuple(str(ref) for ref in refs if ref),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source": self.source,
            "product": self.product,
            "severity": self.severity,
            "description": self.description,
            "references": list(self.references),
        }


def normalize_severity(value: Any) -> str:
    if value is None:
        return "unknown"
    severity = str(value).strip().lower()
    return severity if severity else "unknown"
