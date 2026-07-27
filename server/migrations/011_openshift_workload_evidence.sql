ALTER TABLE finding_observations
    ADD COLUMN IF NOT EXISTS namespace text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS deployment text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS image text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS component text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS fixable boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS fixable_signal text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS fixed_in text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS cvss_score double precision
        CHECK (cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10));

CREATE INDEX IF NOT EXISTS finding_observations_openshift_workload_idx
    ON finding_observations (scan_run_id, namespace, deployment)
    WHERE namespace <> '' OR deployment <> '';

ALTER TABLE threat_intel_records
    ADD COLUMN IF NOT EXISTS namespace text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS deployment text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS image text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS component text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS fixable boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS fixed_in text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS cvss_score double precision
        CHECK (cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10));
