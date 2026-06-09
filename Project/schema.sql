CREATE TABLE IF NOT EXISTS advisories (
    id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    product TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT NOT NULL,
    reference_urls TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_advisories_product ON advisories(product);
CREATE INDEX IF NOT EXISTS idx_advisories_severity ON advisories(severity);
