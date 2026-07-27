ALTER TABLE customer_memberships
    ADD COLUMN IF NOT EXISTS asset_types text[] NOT NULL DEFAULT ARRAY[]::text[];

ALTER TABLE customer_memberships
    DROP CONSTRAINT IF EXISTS customer_memberships_asset_types_check;

ALTER TABLE customer_memberships
    ADD CONSTRAINT customer_memberships_asset_types_check CHECK (
        asset_types <@ ARRAY[
            'Network Device', 'Linux Server', 'Windows Server', 'Endpoint', 'Database',
            'Cloud Asset', 'Security Appliance', 'Virtualization Host',
            'Container Platform', 'OT Device', 'Other'
        ]::text[]
    );

CREATE INDEX IF NOT EXISTS customer_memberships_asset_types_idx
    ON customer_memberships USING gin (asset_types);
