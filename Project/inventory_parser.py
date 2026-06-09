from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True, slots=True)
class InventoryItem:
    product: str
    version: str | None = None
    ecosystem: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        return {"product": self.product, "version": self.version, "ecosystem": self.ecosystem}


def parse_inventory(path: str | Path) -> list[InventoryItem]:
    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid inventory YAML: {exc}") from exc

    if isinstance(raw, list):
        entries = raw
    elif isinstance(raw, dict):
        entries = (
            raw.get("packages")
            or raw.get("applications")
            or raw.get("dependencies")
            or raw.get("components")
            or []
        )
    else:
        entries = []

    items: list[InventoryItem] = []
    for entry in entries:
        if isinstance(entry, str):
            items.append(InventoryItem(product=entry))
        elif isinstance(entry, dict):
            product = (
                entry.get("product")
                or entry.get("name")
                or entry.get("package")
                or entry.get("package_name")
            )
            if product:
                items.append(
                    InventoryItem(
                        product=str(product),
                        version=str(entry["version"]) if entry.get("version") is not None else None,
                        ecosystem=str(entry["ecosystem"]) if entry.get("ecosystem") else None,
                    )
                )
    return items
