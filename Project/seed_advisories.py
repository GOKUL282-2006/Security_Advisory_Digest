from __future__ import annotations

import json
from pathlib import Path

from advisory_model import Advisory
from advisory_repository import AdvisoryRepository


def seed(sample_path: str = "data/sample_advisories.json", db_path: str = "advisories.db") -> int:
    payload = json.loads(Path(sample_path).read_text(encoding="utf-8"))
    advisories = [Advisory.from_mapping(item) for item in payload]
    AdvisoryRepository(db_path).insert_many(advisories)
    return len(advisories)


if __name__ == "__main__":
    count = seed()
    print(f"Seeded {count} advisories")
