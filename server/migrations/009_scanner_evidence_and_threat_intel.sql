ALTER TABLE finding_observations
    ADD COLUMN IF NOT EXISTS datacentre text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS times_detected integer NOT NULL DEFAULT 1 CHECK (times_detected > 0),
    ADD COLUMN IF NOT EXISTS vendor_severity_label text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS vulnerability_status text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS vulnerability_confidence text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS exploit_evidence_source text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS threat text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS impact text NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS finding_observations_datacentre_idx
    ON finding_observations (scan_run_id, datacentre)
    WHERE datacentre <> '';

CREATE TABLE IF NOT EXISTS threat_intel_imports (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id uuid NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    created_by uuid REFERENCES users(id) ON DELETE SET NULL,
    ingestion_key text NOT NULL,
    source_label text NOT NULL,
    file_names text[] NOT NULL DEFAULT '{}',
    expected_records integer NOT NULL CHECK (expected_records > 0),
    received_records integer NOT NULL DEFAULT 0 CHECK (received_records >= 0),
    status text NOT NULL DEFAULT 'uploading' CHECK (status IN ('uploading', 'ready', 'failed')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    finalized_at timestamptz,
    UNIQUE (customer_id, ingestion_key)
);

CREATE TABLE IF NOT EXISTS threat_intel_records (
    import_id uuid NOT NULL REFERENCES threat_intel_imports(id) ON DELETE CASCADE,
    customer_id uuid NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    row_index integer NOT NULL CHECK (row_index >= 0),
    cve text NOT NULL DEFAULT '',
    vulnerability_name text NOT NULL DEFAULT '',
    source_tool text NOT NULL DEFAULT '',
    source_vulnerability_id text NOT NULL DEFAULT '',
    severity text NOT NULL DEFAULT 'Unknown',
    patch_priority text NOT NULL DEFAULT 'P4',
    exploit_available boolean NOT NULL DEFAULT false,
    vulnerability_confidence text NOT NULL DEFAULT '',
    exploit_evidence text NOT NULL DEFAULT '',
    description text NOT NULL DEFAULT '',
    remediation text NOT NULL DEFAULT '',
    kb_links text NOT NULL DEFAULT '',
    product text NOT NULL DEFAULT '',
    platform_details text NOT NULL DEFAULT '',
    first_observed date,
    last_observed date,
    normalized_payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (import_id, row_index)
);

CREATE INDEX IF NOT EXISTS threat_intel_records_customer_cve_idx
    ON threat_intel_records (customer_id, lower(cve));

CREATE INDEX IF NOT EXISTS threat_intel_records_customer_name_idx
    ON threat_intel_records (customer_id, lower(vulnerability_name));

CREATE TABLE IF NOT EXISTS threat_intel_enrichments (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id uuid NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    created_by uuid REFERENCES users(id) ON DELETE SET NULL,
    query text NOT NULL,
    model text NOT NULL,
    evidence_count integer NOT NULL DEFAULT 0 CHECK (evidence_count >= 0),
    response_text text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS threat_intel_enrichments_customer_idx
    ON threat_intel_enrichments (customer_id, created_at DESC);
