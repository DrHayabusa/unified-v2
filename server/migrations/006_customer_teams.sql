CREATE TABLE IF NOT EXISTS customer_teams (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id uuid NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    name text NOT NULL,
    code text NOT NULL,
    description text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (customer_id, code)
);

CREATE UNIQUE INDEX IF NOT EXISTS customer_teams_name_idx
    ON customer_teams (customer_id, lower(name));

ALTER TABLE customer_assets
    ADD COLUMN IF NOT EXISTS team_id uuid REFERENCES customer_teams(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS customer_assets_team_idx
    ON customer_assets (customer_id, team_id, in_scope);
