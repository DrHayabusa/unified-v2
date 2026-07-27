CREATE TABLE IF NOT EXISTS scan_runs (
    id uuid PRIMARY KEY,
    tenant_key text NOT NULL,
    customer_name text NOT NULL,
    ingestion_key text NOT NULL,
    workflow text NOT NULL CHECK (workflow IN ('adhoc', 'monthly', 'quarterly', 'quarterly-scan')),
    source_tool text NOT NULL,
    source_label text NOT NULL,
    report_period text NOT NULL,
    file_names text[] NOT NULL DEFAULT '{}',
    source_ids text[] NOT NULL DEFAULT '{}',
    expected_findings integer NOT NULL CHECK (expected_findings > 0),
    received_findings integer NOT NULL DEFAULT 0 CHECK (received_findings >= 0),
    weighted_findings bigint NOT NULL DEFAULT 0 CHECK (weighted_findings >= 0),
    expected_chunks integer NOT NULL CHECK (expected_chunks > 0),
    received_chunks integer NOT NULL DEFAULT 0 CHECK (received_chunks >= 0),
    status text NOT NULL DEFAULT 'uploading' CHECK (status IN ('uploading', 'ready', 'failed')),
    dashboard jsonb NOT NULL DEFAULT '{}'::jsonb,
    input_summary jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    finalized_at timestamptz,
    UNIQUE (tenant_key, ingestion_key)
);

CREATE TABLE IF NOT EXISTS ingestion_chunks (
    scan_run_id uuid NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    chunk_index integer NOT NULL CHECK (chunk_index >= 0),
    start_index integer NOT NULL CHECK (start_index >= 0),
    row_count integer NOT NULL CHECK (row_count > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (scan_run_id, chunk_index)
);

CREATE TABLE IF NOT EXISTS finding_observations (
    scan_run_id uuid NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    row_index integer NOT NULL CHECK (row_index >= 0),
    report_period text NOT NULL,
    finding_key text NOT NULL,
    source_tool text NOT NULL,
    source_tools text[] NOT NULL DEFAULT '{}',
    source_display text NOT NULL DEFAULT '',
    source_vulnerability_id text NOT NULL DEFAULT '',
    ip_address text NOT NULL DEFAULT '',
    dns_name text NOT NULL DEFAULT '',
    vulnerability_name text NOT NULL DEFAULT '',
    cve text NOT NULL DEFAULT '',
    severity text NOT NULL CHECK (severity IN ('Critical', 'High', 'Medium', 'Low', 'Info', 'Unknown')),
    exploit_available boolean NOT NULL DEFAULT false,
    exploit_signal text NOT NULL DEFAULT '',
    epss_score double precision CHECK (epss_score IS NULL OR (epss_score >= 0 AND epss_score <= 1)),
    patch_priority text NOT NULL CHECK (patch_priority IN ('P1', 'P2', 'P3', 'P4')),
    asset_exposure smallint NOT NULL DEFAULT 0 CHECK (asset_exposure BETWEEN 0 AND 1000),
    vulnerability_finding text NOT NULL DEFAULT '',
    summary text NOT NULL DEFAULT '',
    description text NOT NULL DEFAULT '',
    remediation text NOT NULL DEFAULT '',
    kb_links text NOT NULL DEFAULT '',
    platform_details text NOT NULL DEFAULT '',
    first_discovered date,
    last_observed date,
    vulnerability_age_days integer CHECK (vulnerability_age_days IS NULL OR vulnerability_age_days >= 0),
    protocol text NOT NULL DEFAULT '',
    port text NOT NULL DEFAULT '',
    record_count integer NOT NULL DEFAULT 1 CHECK (record_count > 0),
    product text NOT NULL DEFAULT '',
    asset_criticality text NOT NULL DEFAULT '',
    internet_exposed boolean NOT NULL DEFAULT false,
    internet_exposure_known boolean NOT NULL DEFAULT false,
    cisa_kev boolean NOT NULL DEFAULT false,
    normalized_payload jsonb NOT NULL,
    PRIMARY KEY (scan_run_id, row_index)
);

CREATE INDEX IF NOT EXISTS finding_observations_period_idx
    ON finding_observations (report_period, patch_priority, severity);

CREATE INDEX IF NOT EXISTS finding_observations_asset_idx
    ON finding_observations (dns_name, ip_address);

CREATE INDEX IF NOT EXISTS finding_observations_vulnerability_idx
    ON finding_observations (cve, source_vulnerability_id);

CREATE INDEX IF NOT EXISTS scan_runs_history_idx
    ON scan_runs (tenant_key, created_at DESC);
