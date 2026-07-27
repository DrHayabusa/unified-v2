CREATE TABLE IF NOT EXISTS customers (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL,
    slug text NOT NULL UNIQUE,
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive')),
    asset_scope_mode text NOT NULL DEFAULT 'observed' CHECK (asset_scope_mode IN ('observed', 'inventory')),
    notes text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email text NOT NULL UNIQUE,
    full_name text NOT NULL,
    password_hash text NOT NULL,
    global_role text NOT NULL DEFAULT 'customer_user' CHECK (global_role IN ('system_admin', 'customer_user')),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    last_login_at timestamptz
);

CREATE TABLE IF NOT EXISTS customer_memberships (
    customer_id uuid NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role text NOT NULL DEFAULT 'viewer' CHECK (role IN ('owner', 'analyst', 'viewer')),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (customer_id, user_id)
);

CREATE TABLE IF NOT EXISTS auth_sessions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash text NOT NULL UNIQUE,
    csrf_token text NOT NULL,
    user_agent text NOT NULL DEFAULT '',
    ip_address text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS customer_assets (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id uuid NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    asset_key text NOT NULL,
    ip_address text NOT NULL DEFAULT '',
    dns_name text NOT NULL DEFAULT '',
    host_name text NOT NULL DEFAULT '',
    external_id text NOT NULL DEFAULT '',
    platform text NOT NULL DEFAULT '',
    business_unit text NOT NULL DEFAULT '',
    criticality text NOT NULL DEFAULT '',
    internet_exposed boolean,
    origin text NOT NULL DEFAULT 'manual' CHECK (origin IN ('manual', 'scanner')),
    in_scope boolean NOT NULL DEFAULT true,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (customer_id, asset_key)
);

CREATE TABLE IF NOT EXISTS customer_asset_aliases (
    customer_id uuid NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    asset_id uuid NOT NULL REFERENCES customer_assets(id) ON DELETE CASCADE,
    alias text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (customer_id, alias)
);

CREATE TABLE IF NOT EXISTS audit_events (
    id bigserial PRIMARY KEY,
    actor_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    customer_id uuid REFERENCES customers(id) ON DELETE SET NULL,
    event_type text NOT NULL,
    event_data jsonb NOT NULL DEFAULT '{}'::jsonb,
    ip_address text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO customers (name, slug, asset_scope_mode, notes)
SELECT 'Legacy Local Portfolio', 'legacy-local-portfolio', 'observed', 'Automatically created for analyses saved before multi-customer support.'
WHERE NOT EXISTS (SELECT 1 FROM customers);

ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS customer_id uuid REFERENCES customers(id);
ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS created_by uuid REFERENCES users(id) ON DELETE SET NULL;

UPDATE scan_runs
SET customer_id = (SELECT id FROM customers ORDER BY created_at LIMIT 1)
WHERE customer_id IS NULL;

ALTER TABLE scan_runs ALTER COLUMN customer_id SET NOT NULL;
ALTER TABLE scan_runs DROP CONSTRAINT IF EXISTS scan_runs_tenant_key_ingestion_key_key;
CREATE UNIQUE INDEX IF NOT EXISTS scan_runs_customer_ingestion_key
    ON scan_runs (customer_id, ingestion_key);

ALTER TABLE finding_observations ADD COLUMN IF NOT EXISTS report_period_date date;
UPDATE finding_observations
SET report_period_date = to_date(
    substring(report_period from '(January|February|March|April|May|June|July|August|September|October|November|December)[[:space:]]+[0-9]{4}'),
    'FMMonth YYYY'
)
WHERE report_period_date IS NULL
  AND report_period ~ '(January|February|March|April|May|June|July|August|September|October|November|December)[[:space:]]+[0-9]{4}';

CREATE INDEX IF NOT EXISTS auth_sessions_token_idx ON auth_sessions (token_hash);
CREATE INDEX IF NOT EXISTS auth_sessions_expiry_idx ON auth_sessions (expires_at);
CREATE INDEX IF NOT EXISTS customer_memberships_user_idx ON customer_memberships (user_id, customer_id);
CREATE INDEX IF NOT EXISTS customer_assets_customer_scope_idx ON customer_assets (customer_id, in_scope, origin);
CREATE INDEX IF NOT EXISTS customer_assets_identity_idx ON customer_assets (customer_id, ip_address, dns_name);
CREATE INDEX IF NOT EXISTS finding_observations_period_date_idx
    ON finding_observations (scan_run_id, report_period_date, patch_priority, severity);
CREATE INDEX IF NOT EXISTS scan_runs_customer_history_idx
    ON scan_runs (customer_id, status, finalized_at DESC);
CREATE INDEX IF NOT EXISTS audit_events_customer_idx ON audit_events (customer_id, created_at DESC);
