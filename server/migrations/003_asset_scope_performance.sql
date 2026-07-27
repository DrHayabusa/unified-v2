CREATE INDEX IF NOT EXISTS customer_assets_active_identity_idx
    ON customer_assets (customer_id, asset_key)
    WHERE in_scope;

CREATE INDEX IF NOT EXISTS customer_asset_aliases_asset_idx
    ON customer_asset_aliases (customer_id, asset_id, alias);
