# PostgreSQL Migration Validation Evidence

**Validation date:** 27 July 2026  
**Platform:** MVA Unified Vulnerability Management Platform  
**Database engine:** PostgreSQL 17.10 (Postgres.app)  
**Migration set:** `001_initial.sql` through `012_repair_report_period_date_capture.sql`

## Executive Result

The database scripts work on a newly created PostgreSQL database and safely
upgrade a representative legacy database. Existing application databases were
not dropped or altered during this validation.

| Validation | Result |
|---|---:|
| Clean application of all 12 migrations | Pass |
| Reapplication/idempotency | Pass |
| Legacy database upgrade and data repair | Pass |
| Two concurrent migration runners | Pass |
| Migration checksum ledger | Pass |
| Real Fastify API persistence | Pass |
| 80,000 finding-observation persistence | Pass |
| Backend tests | 25/25 passed |
| Frontend/data-engine tests | 78/78 passed |
| React production build | Pass |
| Production dependency audits | 0 vulnerabilities |
| Docker Compose production configuration | Pass |

## Safe Test Databases

The following disposable databases were created on the local PostgreSQL 17
instance. This avoided any risk to the existing `mva` databases.

| Database | Purpose |
|---|---|
| `mva_migration_validation_20260727` | Clean migration application and reapplication |
| `mva_legacy_upgrade_validation_20260727` | Legacy-row upgrade and date repair |
| `mva_fresh_concurrent_validation_20260727` | Concurrent startup and real API persistence |

## Defect Found and Repaired

The original month extraction in migrations 002 and 007 used a capturing group
that caused PostgreSQL `substring` to return only the month name. For a legacy
value of `July 2026`, this could produce `0001-07-01 BC`.

The released migrations were left unchanged. Forward-only migration
`012_repair_report_period_date_capture.sql` uses a full capture for the month
and year, repairs affected historical rows, and is safe to rerun.

Verified repair:

```text
report_period | report_period_date
July 2026     | 2026-07-01
```

## Migration Runner Controls

The repository migration runner now:

1. Acquires a PostgreSQL advisory lock so only one application instance migrates
   the schema at a time.
2. Creates and uses `schema_migrations`.
3. Records each migration name, SHA-256 checksum, and application time.
4. Executes each pending migration in its own transaction.
5. Rejects a migration whose contents changed after it was recorded.
6. Releases the advisory lock and pooled connection on success or failure.

Two migration runners were started against the same empty database. Both
completed successfully, and the ledger contained one row per migration.

## Schema Evidence

```text
recorded migrations: 12
tables:              15
indexes:             47
check constraints:   34
foreign keys:        20
primary keys:        15
unique constraints:   6
```

Validated tables:

```text
audit_events
auth_sessions
customer_asset_aliases
customer_assets
customer_memberships
customer_teams
customers
finding_observations
ingestion_chunks
scan_runs
schema_migrations
threat_intel_enrichments
threat_intel_imports
threat_intel_records
users
```

## Real API Persistence Evidence

The actual Fastify API was started against the disposable concurrent-validation
database. Authentication, tenant creation, monthly report persistence,
idempotent repeat upload, metric retrieval, and cleanup were exercised through
HTTP rather than direct table inserts.

```json
{
  "monthly": {
    "periods": 4,
    "observationRows": 455,
    "weightedFindings": 455,
    "duplicateUploadReturnedSameRun": true,
    "metricTotal": 455
  },
  "large": {
    "observationRows": 80000,
    "weightedFindings": 80000,
    "chunks": 160
  }
}
```

## Reproduce on a Disposable Database

Never drop the production database to test migrations. Create a temporary
database, point `DATABASE_URL` to it, and run:

```bash
createdb mva_migration_validation

cd /path/to/unified-v2
DATABASE_URL='postgresql://mva:<password>@127.0.0.1:5432/mva_migration_validation' \
node tools/validate_database_migrations.mjs
```

Expected summary:

```json
{
  "ok": true,
  "postgresVersion": "17.10 (Postgres.app)",
  "migrations": 12,
  "tables": 15,
  "indexes": 47,
  "constraints": {
    "c": 34,
    "f": 20,
    "p": 15,
    "u": 6
  },
  "idempotentSecondRun": true,
  "periodDateRepair": "2026-07-01"
}
```

Remove only the disposable database after review:

```bash
dropdb mva_migration_validation
```

## Production Rollout

1. Take and verify a PostgreSQL backup.
2. Deploy the application version containing migration 012.
3. Start one API instance first; it will apply pending migrations.
4. Confirm the migration ledger and date repair.
5. Start the remaining API replicas.

Verification SQL:

```sql
SELECT name, checksum, applied_at
FROM schema_migrations
ORDER BY name;

SELECT count(*) AS invalid_period_dates
FROM finding_observations
WHERE report_period_date < DATE '2000-01-01';
```

Expected results are 12 ordered migration rows and
`invalid_period_dates = 0`.

## Conclusion

The scripts are validated for clean installation, repeat execution, legacy
upgrade, concurrent application startup, and high-volume persistence on
PostgreSQL 17.10. Production rollout should use backup-first, forward-only
migration procedures; dropping the existing production database is unnecessary
and not recommended.
