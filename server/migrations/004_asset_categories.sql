ALTER TABLE customer_assets
    ADD COLUMN IF NOT EXISTS asset_type text NOT NULL DEFAULT 'Other';

UPDATE customer_assets
SET asset_type = CASE
    WHEN lower(platform) ~ '(router|switch|wireless|network|load balancer)' THEN 'Network Device'
    WHEN lower(platform) ~ '(firewall|waf|ids|ips|security appliance)' THEN 'Security Appliance'
    WHEN lower(platform) ~ '(linux|ubuntu|debian|red hat|rhel|centos|suse|unix)' THEN 'Linux Server'
    WHEN lower(platform) ~ '(windows server)' THEN 'Windows Server'
    WHEN lower(platform) ~ '(windows 1[01]|macos|desktop|laptop|workstation)' THEN 'Endpoint'
    WHEN lower(platform) ~ '(postgres|mysql|oracle database|sql server|database)' THEN 'Database'
    WHEN lower(platform) ~ '(aws|azure|gcp|cloud)' THEN 'Cloud Asset'
    WHEN lower(platform) ~ '(vmware|esxi|hyper-v|virtualization)' THEN 'Virtualization Host'
    WHEN lower(platform) ~ '(kubernetes|openshift|container)' THEN 'Container Platform'
    WHEN lower(platform) ~ '(scada|plc|industrial|ot device)' THEN 'OT Device'
    ELSE 'Other'
END
WHERE asset_type = 'Other' AND NULLIF(trim(platform), '') IS NOT NULL;

ALTER TABLE customer_assets
    DROP CONSTRAINT IF EXISTS customer_assets_asset_type_check;

ALTER TABLE customer_assets
    ADD CONSTRAINT customer_assets_asset_type_check CHECK (asset_type IN (
        'Network Device', 'Linux Server', 'Windows Server', 'Endpoint', 'Database',
        'Cloud Asset', 'Security Appliance', 'Virtualization Host',
        'Container Platform', 'OT Device', 'Other'
    ));

CREATE INDEX IF NOT EXISTS customer_assets_type_idx
    ON customer_assets (customer_id, asset_type, in_scope);
