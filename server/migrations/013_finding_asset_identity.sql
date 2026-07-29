ALTER TABLE finding_observations
    ADD COLUMN IF NOT EXISTS asset_key text NOT NULL DEFAULT '';

UPDATE finding_observations
SET asset_key = CASE
    WHEN ip_address <> '' THEN ip_address
    WHEN dns_name <> '' THEN dns_name
    WHEN namespace <> '' OR deployment <> '' OR image <> ''
        THEN concat_ws('/', NULLIF(namespace, ''), NULLIF(deployment, ''), NULLIF(image, ''))
    ELSE ''
END
WHERE asset_key = '';

CREATE INDEX IF NOT EXISTS finding_observations_asset_key_idx
    ON finding_observations (scan_run_id, asset_key)
    WHERE asset_key <> '';
