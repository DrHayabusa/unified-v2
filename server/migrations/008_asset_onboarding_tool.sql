ALTER TABLE customer_assets
    ADD COLUMN IF NOT EXISTS onboarding_tool text NOT NULL DEFAULT 'manual';

ALTER TABLE customer_assets
    DROP CONSTRAINT IF EXISTS customer_assets_onboarding_tool_check;

ALTER TABLE customer_assets
    ADD CONSTRAINT customer_assets_onboarding_tool_check CHECK (onboarding_tool IN (
        'manual', 'tenable-sc', 'tenable-io', 'qualys', 'crowdstrike',
        'mdvm', 'multi-tool', 'other'
    ));

CREATE INDEX IF NOT EXISTS customer_assets_onboarding_tool_idx
    ON customer_assets (customer_id, onboarding_tool, in_scope);
