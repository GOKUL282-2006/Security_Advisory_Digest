from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Iterable

from advisory_model import Advisory


class AdvisoryRepository:
    def __init__(self, db_path: str | Path = "advisories.db", schema_path: str | Path = "schema.sql") -> None:
        self.db_path = Path(db_path)
        self.schema_path = Path(schema_path)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _initialize(self) -> None:
        with self._connect() as conn:
            conn.executescript(self.schema_path.read_text(encoding="utf-8"))

    def insert(self, advisory: Advisory) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO advisories (id, source, product, severity, description, reference_urls)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    source=excluded.source,
                    product=excluded.product,
                    severity=excluded.severity,
                    description=excluded.description,
                    reference_urls=excluded.reference_urls,
                    updated_at=CURRENT_TIMESTAMP
                """,
                (
                    advisory.id,
                    advisory.source,
                    advisory.product,
                    advisory.severity,
                    advisory.description,
                    json.dumps(list(advisory.references)),
                ),
            )

    def insert_many(self, advisories: Iterable[Advisory]) -> None:
        with self._connect() as conn:
            for advisory in advisories:
                conn.execute(
                    """
                    INSERT INTO advisories (id, source, product, severity, description, reference_urls)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        source=excluded.source,
                        product=excluded.product,
                        severity=excluded.severity,
                        description=excluded.description,
                        reference_urls=excluded.reference_urls,
                        updated_at=CURRENT_TIMESTAMP
                    """,
                    (
                        advisory.id,
                        advisory.source,
                        advisory.product,
                        advisory.severity,
                        advisory.description,
                        json.dumps(list(advisory.references)),
                    ),
                )

    def get(self, advisory_id: str) -> Advisory | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM advisories WHERE id = ?", (advisory_id,)).fetchone()
        return self._from_row(row) if row else None

    def query(self, product: str | None = None, severity: str | None = None) -> list[Advisory]:
        clauses: list[str] = []
        params: list[str] = []
        if product:
            clauses.append("lower(product) = lower(?)")
            params.append(product)
        if severity:
            clauses.append("lower(severity) = lower(?)")
            params.append(severity)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._connect() as conn:
            rows = conn.execute(f"SELECT * FROM advisories {where} ORDER BY severity, id", params).fetchall()
        return [self._from_row(row) for row in rows]

    def delete(self, advisory_id: str) -> bool:
        with self._connect() as conn:
            cursor = conn.execute("DELETE FROM advisories WHERE id = ?", (advisory_id,))
            return cursor.rowcount > 0

    @staticmethod
    def _from_row(row: sqlite3.Row) -> Advisory:
        return Advisory(
            id=row["id"],
            source=row["source"],
            product=row["product"],
            severity=row["severity"],
            description=row["description"],
            references=tuple(json.loads(row["reference_urls"] or "[]")),
        )
