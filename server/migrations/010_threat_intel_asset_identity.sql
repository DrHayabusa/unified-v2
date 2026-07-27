ALTER TABLE threat_intel_records
    ADD COLUMN IF NOT EXISTS ip_address text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS dns_name text NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS threat_intel_records_customer_asset_idx
    ON threat_intel_records (customer_id, lower(ip_address), lower(dns_name));
