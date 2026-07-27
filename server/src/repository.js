import { createHash, randomUUID } from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import pg from "pg";

import { badRequest, normalizeChunkPayload, normalizeThreatIntelChunkPayload } from "./validation.js";

const { Pool } = pg;
const ROOT = path.dirname(fileURLToPath(import.meta.url));

export class PostgresRepository {
  constructor({ connectionString, maxConnections = 10 }) {
    this.pool = new Pool({ connectionString, max: maxConnections, idleTimeoutMillis: 30_000 });
  }

  async migrate() {
    const migrationDirectory = path.resolve(ROOT, "../migrations");
    const migrationFiles = (await fs.readdir(migrationDirectory)).filter((name) => name.endsWith(".sql")).sort();
    const client = await this.pool.connect();
    try {
      await client.query("SELECT pg_advisory_lock(hashtext('mva-schema-migrations'))");
      await client.query(
        `CREATE TABLE IF NOT EXISTS schema_migrations (
           name text PRIMARY KEY,
           checksum text NOT NULL,
           applied_at timestamptz NOT NULL DEFAULT now()
         )`,
      );

      for (const migrationFile of migrationFiles) {
        const sql = await fs.readFile(path.join(migrationDirectory, migrationFile), "utf8");
        const checksum = createHash("sha256").update(sql).digest("hex");
        const existing = await client.query(
          "SELECT checksum FROM schema_migrations WHERE name = $1",
          [migrationFile],
        );
        if (existing.rowCount) {
          if (existing.rows[0].checksum !== checksum) {
            throw new Error(`Applied migration ${migrationFile} does not match its recorded checksum.`);
          }
          continue;
        }

        try {
          await client.query("BEGIN");
          await client.query(sql);
          await client.query(
            "INSERT INTO schema_migrations (name, checksum) VALUES ($1, $2)",
            [migrationFile, checksum],
          );
          await client.query("COMMIT");
        } catch (error) {
          await client.query("ROLLBACK");
          throw new Error(`Database migration ${migrationFile} failed: ${error.message}`, { cause: error });
        }
      }
    } finally {
      await client.query("SELECT pg_advisory_unlock(hashtext('mva-schema-migrations'))").catch(() => {});
      client.release();
    }
  }

  async close() {
    await this.pool.end();
  }

  async health() {
    const result = await this.pool.query("SELECT current_database() AS database, now() AS checked_at");
    return result.rows[0];
  }

  async createScanRun(customerId, createdBy, metadata) {
    const id = randomUUID();
    const inserted = await this.pool.query(
      `INSERT INTO scan_runs (
         id, tenant_key, customer_id, created_by, customer_name, ingestion_key, workflow, source_tool, source_label,
         report_period, file_names, source_ids, expected_findings, expected_chunks, dashboard, input_summary
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15::jsonb, $16::jsonb)
       ON CONFLICT (customer_id, ingestion_key) DO NOTHING
       RETURNING *`,
      [
        id,
        customerId,
        customerId,
        createdBy,
        metadata.customerName,
        metadata.ingestionKey,
        metadata.workflow,
        metadata.sourceTool,
        metadata.sourceLabel,
        metadata.reportPeriod,
        metadata.fileNames,
        metadata.sourceIds,
        metadata.expectedFindings,
        metadata.expectedChunks,
        JSON.stringify(metadata.dashboard),
        JSON.stringify(metadata.inputSummary),
      ],
    );
    if (inserted.rowCount) return { ...serializeRun(inserted.rows[0]), existing: false };
    const existing = await this.pool.query("SELECT * FROM scan_runs WHERE customer_id = $1 AND ingestion_key = $2", [customerId, metadata.ingestionKey]);
    return { ...serializeRun(existing.rows[0]), existing: true };
  }

  async ingestChunk(customerId, scanRunId, payload, assetTypes = []) {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const runResult = await client.query(
        "SELECT * FROM scan_runs WHERE id = $1 AND customer_id = $2 FOR UPDATE",
        [scanRunId, customerId],
      );
      if (!runResult.rowCount) throw badRequest("Scan run was not found.", 404);
      const run = runResult.rows[0];
      const chunk = normalizeChunkPayload(payload, run.expected_findings);
      if (chunk.chunkIndex >= run.expected_chunks) throw badRequest("Chunk index exceeds the declared chunk count.");
      if (assetTypes.length) await assertFindingsMatchAssetTypes(client, customerId, chunk.findings, assetTypes);

      const marker = await client.query(
        `INSERT INTO ingestion_chunks (scan_run_id, chunk_index, start_index, row_count)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (scan_run_id, chunk_index) DO NOTHING
         RETURNING chunk_index`,
        [scanRunId, chunk.chunkIndex, chunk.startIndex, chunk.findings.length],
      );
      if (!marker.rowCount) {
        await client.query("COMMIT");
        return { duplicate: true, receivedFindings: run.received_findings, receivedChunks: run.received_chunks, status: run.status };
      }
      if (run.status === "ready") throw badRequest("A finalized scan run cannot accept additional chunks.", 409);

      await client.query(
        `INSERT INTO finding_observations (
           scan_run_id, row_index, report_period, report_period_date, finding_key, source_tool, source_tools, source_display,
           source_vulnerability_id, ip_address, dns_name, vulnerability_name, cve, severity,
           exploit_available, exploit_signal, epss_score, patch_priority, asset_exposure,
           vulnerability_finding, summary, description, remediation, kb_links, platform_details,
           first_discovered, last_observed, vulnerability_age_days, protocol, port, record_count,
           datacentre, times_detected, vendor_severity_label, vulnerability_status,
           vulnerability_confidence, exploit_evidence_source, threat, impact,
           product, asset_criticality, internet_exposed, internet_exposure_known, cisa_kev,
           namespace, deployment, image, component, fixable, fixable_signal, fixed_in, cvss_score,
           normalized_payload
         )
         SELECT
           $1::uuid,
           (item->>'rowIndex')::integer,
           item->>'reportPeriod',
           NULLIF(item->>'reportPeriodDate', '')::date,
           item->>'findingKey',
           item->>'sourceTool',
           ARRAY(SELECT jsonb_array_elements_text(item->'sourceTools')),
           item->>'sourceDisplay',
           item->>'sourceVulnerabilityId',
           item->>'ipAddress',
           item->>'dnsName',
           item->>'vulnerabilityName',
           item->>'cve',
           item->>'severity',
           (item->>'exploitAvailable')::boolean,
           item->>'exploitSignal',
           NULLIF(item->>'epssScore', '')::double precision,
           item->>'patchPriority',
           (item->>'assetExposure')::smallint,
           item->>'vulnerabilityFinding',
           item->>'summary',
           item->>'description',
           item->>'remediation',
           item->>'kbLinks',
           item->>'platformDetails',
           NULLIF(item->>'firstDiscovered', '')::date,
           NULLIF(item->>'lastObserved', '')::date,
           NULLIF(item->>'vulnerabilityAgeDays', '')::integer,
           item->>'protocol',
           item->>'port',
           (item->>'recordCount')::integer,
           item->>'datacentre',
           (item->>'timesDetected')::integer,
           item->>'vendorSeverityLabel',
           item->>'vulnerabilityStatus',
           item->>'vulnerabilityConfidence',
           item->>'exploitEvidenceSource',
           item->>'threat',
           item->>'impact',
           item->>'product',
           item->>'assetCriticality',
           (item->>'internetExposed')::boolean,
           (item->>'internetExposureKnown')::boolean,
           (item->>'cisaKev')::boolean,
           item->>'namespace',
           item->>'deployment',
           item->>'image',
           item->>'component',
           (item->>'fixable')::boolean,
           item->>'fixableSignal',
           item->>'fixedIn',
           NULLIF(item->>'cvssScore', '')::double precision,
           item->'payload'
         FROM jsonb_array_elements($2::jsonb) AS item`,
        [scanRunId, JSON.stringify(chunk.findings)],
      );
      const chunkWeight = chunk.findings.reduce((sum, finding) => sum + finding.recordCount, 0);
      const updated = await client.query(
        `UPDATE scan_runs
         SET received_findings = received_findings + $2,
             weighted_findings = weighted_findings + $3,
             received_chunks = received_chunks + 1,
             updated_at = now()
         WHERE id = $1
         RETURNING received_findings, weighted_findings, received_chunks, status`,
        [scanRunId, chunk.findings.length, chunkWeight],
      );
      await client.query("COMMIT");
      const row = updated.rows[0];
      return {
        duplicate: false,
        receivedFindings: row.received_findings,
        weightedFindings: Number(row.weighted_findings),
        receivedChunks: row.received_chunks,
        status: row.status,
      };
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async finalizeScanRun(customerId, scanRunId) {
    const result = await this.pool.query(
      `UPDATE scan_runs
       SET status = 'ready', finalized_at = COALESCE(finalized_at, now()), updated_at = now()
       WHERE id = $1 AND customer_id = $2
         AND received_findings = expected_findings
         AND received_chunks = expected_chunks
       RETURNING *`,
      [scanRunId, customerId],
    );
    if (result.rowCount) {
      await this.syncObservedAssets(customerId, scanRunId);
      return this.getScanRun(customerId, scanRunId);
    }
    const current = await this.pool.query("SELECT * FROM scan_runs WHERE id = $1 AND customer_id = $2", [scanRunId, customerId]);
    if (!current.rowCount) throw badRequest("Scan run was not found.", 404);
    const row = current.rows[0];
    if (row.status === "ready") return this.getScanRun(customerId, scanRunId);
    throw badRequest(
      `Cannot finalize: received ${row.received_findings}/${row.expected_findings} findings and ${row.received_chunks}/${row.expected_chunks} chunks.`,
      409,
    );
  }

  async listScanRuns(customerId, limit = 20, assetTypes = []) {
    const result = await this.pool.query(
      `SELECT run.id, run.customer_name, run.workflow, run.source_label, run.report_period, run.file_names, run.source_ids,
              CASE WHEN cardinality($3::text[]) = 0 THEN run.expected_findings ELSE scoped.finding_count END AS expected_findings,
              CASE WHEN cardinality($3::text[]) = 0 THEN run.received_findings ELSE scoped.finding_count END AS received_findings,
              CASE WHEN cardinality($3::text[]) = 0 THEN run.weighted_findings ELSE scoped.finding_count END AS weighted_findings,
              run.status, run.created_at, run.finalized_at
       FROM scan_runs run
       LEFT JOIN LATERAL (
         SELECT COALESCE(sum(finding.record_count), 0)::bigint AS finding_count
         FROM finding_observations finding
         WHERE finding.scan_run_id = run.id AND ${assetTypeScopeSql("finding", "$3")}
       ) scoped ON true
       WHERE run.customer_id = $1
       ORDER BY run.created_at DESC
       LIMIT $2`,
      [customerId, limit, assetTypes],
    );
    return result.rows.map(serializeRun);
  }

  async getScanRun(customerId, scanRunId, assetTypes = []) {
    const runResult = await this.pool.query("SELECT * FROM scan_runs WHERE id = $1 AND customer_id = $2", [scanRunId, customerId]);
    if (!runResult.rowCount) throw badRequest("Scan run was not found.", 404);
    const metricsResult = await this.pool.query(
      `SELECT severity, patch_priority, sum(record_count)::bigint AS finding_count
       FROM finding_observations finding
       WHERE finding.scan_run_id = $2 AND ${assetTypeScopeSql("finding", "$3")}
       GROUP BY severity, patch_priority
       ORDER BY patch_priority, severity`,
      [customerId, scanRunId, assetTypes],
    );
    const sourceResult = await this.pool.query(
      `SELECT source_tool, sum(record_count)::bigint AS finding_count
       FROM finding_observations finding
       WHERE finding.scan_run_id = $2 AND ${assetTypeScopeSql("finding", "$3")}
       GROUP BY source_tool
       ORDER BY source_tool`,
      [customerId, scanRunId, assetTypes],
    );
    const scopedFindingCount = metricsResult.rows.reduce((sum, row) => sum + Number(row.finding_count), 0);
    const serializedRun = serializeRun(runResult.rows[0]);
    return {
      ...serializedRun,
      ...(assetTypes.length ? { expectedFindings: scopedFindingCount, receivedFindings: scopedFindingCount, weightedFindings: scopedFindingCount } : {}),
      metrics: metricsResult.rows.map((row) => ({ ...row, finding_count: Number(row.finding_count) })),
      sources: sourceResult.rows.map((row) => ({ ...row, finding_count: Number(row.finding_count) })),
    };
  }

  async getCustomerScanAssetCoverage(customerId, assetTypes = []) {
    const latestRunResult = await this.pool.query(
      `SELECT run.*
       FROM scan_runs run
       WHERE run.customer_id = $1
         AND run.status = 'ready'
         AND EXISTS (
           SELECT 1 FROM finding_observations finding
           WHERE finding.scan_run_id = run.id AND ${assetTypeScopeSql("finding", "$2")}
         )
       ORDER BY COALESCE(run.finalized_at, run.created_at) DESC, run.created_at DESC
       LIMIT 1`,
      [customerId, assetTypes],
    );
    if (!latestRunResult.rowCount) {
      return {
        available: false,
        runId: null,
        reportPeriod: "",
        sourceLabel: "",
        observedScanIdentities: 0,
        matchedInventoryAssets: 0,
        unmatchedScanIdentities: 0,
        ambiguousScanIdentities: 0,
        assetIds: [],
      };
    }

    const latestRun = latestRunResult.rows[0];
    const periodResult = await this.pool.query(
      `SELECT max(finding.report_period_date) AS report_period_date
       FROM finding_observations finding
       WHERE finding.scan_run_id = $2 AND ${assetTypeScopeSql("finding", "$3")}`,
      [customerId, latestRun.id, assetTypes],
    );
    const reportPeriodDate = periodResult.rows[0]?.report_period_date ?? null;
    const matchesResult = await this.pool.query(
      `WITH observations AS (
         SELECT DISTINCT
                lower(NULLIF(trim(finding.ip_address), '')) AS ip_address,
                lower(NULLIF(trim(finding.dns_name), '')) AS dns_name
         FROM finding_observations finding
         WHERE finding.scan_run_id = $2
           AND ($4::date IS NULL OR finding.report_period_date = $4::date)
           AND ${assetTypeScopeSql("finding", "$3")}
           AND COALESCE(NULLIF(trim(finding.ip_address), ''), NULLIF(trim(finding.dns_name), '')) IS NOT NULL
       ), candidate_matches AS (
         SELECT observation.ip_address, observation.dns_name,
                COALESCE(
                  array_agg(DISTINCT asset.id) FILTER (WHERE asset.id IS NOT NULL),
                  ARRAY[]::uuid[]
                ) AS asset_ids
         FROM observations observation
         LEFT JOIN customer_assets asset
           ON asset.customer_id = $1
          AND asset.in_scope
          AND (cardinality($3::text[]) = 0 OR asset.asset_type = ANY($3::text[]))
          AND (
            asset.asset_key IN (observation.ip_address, observation.dns_name)
            OR lower(NULLIF(trim(asset.ip_address), '')) IN (observation.ip_address, observation.dns_name)
            OR lower(NULLIF(trim(asset.dns_name), '')) IN (observation.ip_address, observation.dns_name)
            OR EXISTS (
              SELECT 1 FROM customer_asset_aliases alias
              WHERE alias.customer_id = $1
                AND alias.asset_id = asset.id
                AND alias.alias IN (observation.ip_address, observation.dns_name)
            )
          )
         GROUP BY observation.ip_address, observation.dns_name
       )
       SELECT ip_address, dns_name, asset_ids FROM candidate_matches`,
      [customerId, latestRun.id, assetTypes, reportPeriodDate],
    );

    const matchedAssetIds = new Set();
    let unmatchedScanIdentities = 0;
    let ambiguousScanIdentities = 0;
    for (const row of matchesResult.rows) {
      if (row.asset_ids.length === 1) matchedAssetIds.add(row.asset_ids[0]);
      else if (row.asset_ids.length > 1) ambiguousScanIdentities += 1;
      else unmatchedScanIdentities += 1;
    }
    return {
      available: true,
      runId: latestRun.id,
      workflow: latestRun.workflow,
      sourceTool: latestRun.source_tool,
      sourceLabel: latestRun.source_label,
      reportPeriod: reportPeriodDate ? calendarDate(reportPeriodDate) : latestRun.report_period,
      finalizedAt: latestRun.finalized_at,
      observedScanIdentities: matchesResult.rowCount,
      matchedInventoryAssets: matchedAssetIds.size,
      unmatchedScanIdentities,
      ambiguousScanIdentities,
      assetIds: [...matchedAssetIds],
    };
  }

  async setupStatus() {
    const result = await this.pool.query("SELECT count(*)::integer AS user_count FROM users");
    return { setupRequired: result.rows[0].user_count === 0 };
  }

  async bootstrapAdmin({ email, fullName, passwordHash, ipAddress = "" }) {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("SELECT pg_advisory_xact_lock(741852963)");
      const count = await client.query("SELECT count(*)::integer AS user_count FROM users");
      if (count.rows[0].user_count > 0) throw badRequest("Initial administrator setup has already been completed.", 409);
      const inserted = await client.query(
        `INSERT INTO users (email, full_name, password_hash, global_role)
         VALUES ($1, $2, $3, 'system_admin')
         RETURNING id, email, full_name, global_role, status, created_at, last_login_at`,
        [email, fullName, passwordHash],
      );
      await client.query(
        `INSERT INTO audit_events (actor_user_id, event_type, event_data, ip_address)
         VALUES ($1, 'auth.bootstrap_admin', $2::jsonb, $3)`,
        [inserted.rows[0].id, JSON.stringify({ email }), ipAddress],
      );
      await client.query("COMMIT");
      return serializeUser(inserted.rows[0]);
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async getUserForLogin(email) {
    const result = await this.pool.query(
      `SELECT id, email, full_name, password_hash, global_role, status, created_at, last_login_at
       FROM users WHERE email = $1`,
      [email],
    );
    return result.rows[0] ?? null;
  }

  async markLogin(userId) {
    await this.pool.query("UPDATE users SET last_login_at = now(), updated_at = now() WHERE id = $1", [userId]);
  }

  async createSession({ userId, tokenHash, csrfToken, userAgent = "", ipAddress = "", expiresAt }) {
    await this.pool.query("DELETE FROM auth_sessions WHERE expires_at <= now()");
    await this.pool.query(
      `INSERT INTO auth_sessions (user_id, token_hash, csrf_token, user_agent, ip_address, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [userId, tokenHash, csrfToken, userAgent.slice(0, 1000), ipAddress.slice(0, 200), expiresAt],
    );
  }

  async getSession(tokenHash) {
    const result = await this.pool.query(
      `UPDATE auth_sessions session
       SET last_seen_at = now()
       FROM users user_account
       WHERE session.token_hash = $1
         AND session.user_id = user_account.id
         AND session.expires_at > now()
         AND user_account.status = 'active'
       RETURNING session.id AS session_id, session.csrf_token, session.expires_at,
                 user_account.id, user_account.email, user_account.full_name,
                 user_account.global_role, user_account.status, user_account.created_at,
                 user_account.last_login_at`,
      [tokenHash],
    );
    if (!result.rowCount) return null;
    const row = result.rows[0];
    return {
      sessionId: row.session_id,
      csrfToken: row.csrf_token,
      expiresAt: row.expires_at,
      user: serializeUser(row),
    };
  }

  async deleteSession(tokenHash) {
    await this.pool.query("DELETE FROM auth_sessions WHERE token_hash = $1", [tokenHash]);
  }

  async listCustomersForUser(user) {
    const result = user.globalRole === "system_admin"
      ? await this.pool.query(
        `SELECT customer.*, 'system_admin'::text AS membership_role, ARRAY[]::text[] AS asset_type_scope,
                (SELECT count(*)::integer FROM customer_assets asset WHERE asset.customer_id = customer.id AND asset.in_scope) AS asset_count,
                (SELECT count(*)::integer FROM scan_runs run WHERE run.customer_id = customer.id AND run.status = 'ready') AS scan_count
         FROM customers customer
         ORDER BY customer.status, customer.name`,
      )
      : await this.pool.query(
        `SELECT customer.*, membership.role AS membership_role, membership.asset_types AS asset_type_scope,
                (SELECT count(*)::integer FROM customer_assets asset WHERE asset.customer_id = customer.id AND asset.in_scope
                  AND (cardinality(membership.asset_types) = 0 OR asset.asset_type = ANY(membership.asset_types))) AS asset_count,
                (SELECT count(*)::integer FROM scan_runs run WHERE run.customer_id = customer.id AND run.status = 'ready') AS scan_count
         FROM customer_memberships membership
         JOIN customers customer ON customer.id = membership.customer_id
         WHERE membership.user_id = $1
         ORDER BY customer.status, customer.name`,
        [user.id],
      );
    return result.rows.map(serializeCustomer);
  }

  async assertCustomerAccess(user, customerId, allowedRoles = ["owner", "analyst", "viewer"]) {
    const customerResult = await this.pool.query("SELECT * FROM customers WHERE id = $1 AND status = 'active'", [customerId]);
    if (!customerResult.rowCount) throw badRequest("Customer was not found or is inactive.", 404);
    if (user.globalRole === "system_admin") return { customer: serializeCustomer(customerResult.rows[0]), role: "system_admin", assetTypes: [] };
    const membership = await this.pool.query(
      "SELECT role, asset_types FROM customer_memberships WHERE customer_id = $1 AND user_id = $2",
      [customerId, user.id],
    );
    if (!membership.rowCount || !allowedRoles.includes(membership.rows[0].role)) throw badRequest("You do not have access to this customer.", 403);
    return { customer: serializeCustomer({ ...customerResult.rows[0], membership_role: membership.rows[0].role, asset_type_scope: membership.rows[0].asset_types }), role: membership.rows[0].role, assetTypes: membership.rows[0].asset_types ?? [] };
  }

  async createCustomer(actorUserId, payload, ipAddress = "") {
    try {
      const result = await this.pool.query(
        `INSERT INTO customers (name, slug, asset_scope_mode, notes)
         VALUES ($1, $2, $3, $4)
         RETURNING *`,
        [payload.name, payload.slug, payload.assetScopeMode, payload.notes],
      );
      await this.audit(actorUserId, result.rows[0].id, "customer.created", { name: payload.name, assetScopeMode: payload.assetScopeMode }, ipAddress);
      return serializeCustomer(result.rows[0]);
    } catch (error) {
      if (error.code === "23505") throw badRequest("A customer with this identifier already exists.", 409);
      throw error;
    }
  }

  async updateCustomer(actorUserId, customerId, payload, ipAddress = "") {
    try {
      const result = await this.pool.query(
        `UPDATE customers
         SET name = $2, slug = $3, asset_scope_mode = $4, notes = $5, status = $6, updated_at = now()
         WHERE id = $1
         RETURNING *`,
        [customerId, payload.name, payload.slug, payload.assetScopeMode, payload.notes, payload.status],
      );
      if (!result.rowCount) throw badRequest("Customer was not found.", 404);
      await this.audit(actorUserId, customerId, "customer.updated", { name: payload.name, assetScopeMode: payload.assetScopeMode, status: payload.status }, ipAddress);
      return serializeCustomer(result.rows[0]);
    } catch (error) {
      if (error.code === "23505") throw badRequest("A customer with this identifier already exists.", 409);
      throw error;
    }
  }

  async deleteCustomer(actorUserId, customerId, confirmation, ipAddress = "") {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const customerResult = await client.query("SELECT id, name, slug FROM customers WHERE id = $1 FOR UPDATE", [customerId]);
      if (!customerResult.rowCount) throw badRequest("Tenant was not found.", 404);
      const customer = customerResult.rows[0];
      if (String(confirmation ?? "") !== customer.name) throw badRequest("Type the exact tenant name to confirm deletion.", 409);

      const countsResult = await client.query(
        `SELECT
           (SELECT count(*)::integer FROM scan_runs WHERE customer_id = $1) AS reports,
           (SELECT count(*)::integer FROM customer_assets WHERE customer_id = $1) AS assets,
           (SELECT count(*)::integer FROM customer_memberships WHERE customer_id = $1) AS memberships`,
        [customerId],
      );
      const counts = countsResult.rows[0];
      await client.query(
        `INSERT INTO audit_events (actor_user_id, customer_id, event_type, event_data, ip_address)
         VALUES ($1, $2, 'customer.deleted', $3::jsonb, $4)`,
        [actorUserId, customerId, JSON.stringify({ customerId, name: customer.name, slug: customer.slug, ...counts }), ipAddress],
      );
      // scan_runs predates the tenant schema and does not cascade from customers.
      await client.query("DELETE FROM scan_runs WHERE customer_id = $1", [customerId]);
      await client.query("DELETE FROM customers WHERE id = $1", [customerId]);
      await client.query("COMMIT");
      return { id: customerId, name: customer.name, slug: customer.slug, ...counts };
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async listUsers() {
    const result = await this.pool.query(
      `SELECT user_account.id, user_account.email, user_account.full_name, user_account.global_role,
              user_account.status, user_account.created_at, user_account.last_login_at,
              COALESCE(jsonb_agg(jsonb_build_object('customerId', membership.customer_id, 'role', membership.role, 'assetTypes', membership.asset_types))
                FILTER (WHERE membership.customer_id IS NOT NULL), '[]'::jsonb) AS memberships
       FROM users user_account
       LEFT JOIN customer_memberships membership ON membership.user_id = user_account.id
       GROUP BY user_account.id
       ORDER BY user_account.created_at DESC`,
    );
    return result.rows.map((row) => ({ ...serializeUser(row), memberships: row.memberships ?? [] }));
  }

  async createUser(actorUserId, { email, fullName, passwordHash, globalRole, memberships }, ipAddress = "") {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const inserted = await client.query(
        `INSERT INTO users (email, full_name, password_hash, global_role)
         VALUES ($1, $2, $3, $4)
         RETURNING id, email, full_name, global_role, status, created_at, last_login_at`,
        [email, fullName, passwordHash, globalRole],
      );
      for (const membership of memberships) {
        await client.query(
          `INSERT INTO customer_memberships (customer_id, user_id, role, asset_types)
           VALUES ($1, $2, $3, $4::text[])
           ON CONFLICT (customer_id, user_id) DO UPDATE SET role = EXCLUDED.role, asset_types = EXCLUDED.asset_types`,
          [membership.customerId, inserted.rows[0].id, membership.role, membership.assetTypes ?? []],
        );
      }
      await client.query(
        `INSERT INTO audit_events (actor_user_id, event_type, event_data, ip_address)
         VALUES ($1, 'user.created', $2::jsonb, $3)`,
        [actorUserId, JSON.stringify({ userId: inserted.rows[0].id, email, globalRole }), ipAddress],
      );
      await client.query("COMMIT");
      return serializeUser(inserted.rows[0]);
    } catch (error) {
      await client.query("ROLLBACK");
      if (error.code === "23505") throw badRequest("A user with this email already exists.", 409);
      if (error.code === "23503") throw badRequest("One or more selected customers do not exist.");
      throw error;
    } finally {
      client.release();
    }
  }

  async listCustomerTeams(customerId) {
    const result = await this.pool.query(
      `SELECT team.id, team.customer_id, team.name, team.code, team.description,
              team.created_at, team.updated_at,
              count(asset.id)::integer AS asset_count,
              count(asset.id) FILTER (WHERE asset.in_scope)::integer AS in_scope_asset_count
       FROM customer_teams team
       LEFT JOIN customer_assets asset ON asset.team_id = team.id AND asset.customer_id = team.customer_id
       WHERE team.customer_id = $1
       GROUP BY team.id
       ORDER BY team.name`,
      [customerId],
    );
    return result.rows.map(serializeTeam);
  }

  async createCustomerTeam(actorUserId, customerId, payload, ipAddress = "") {
    try {
      const result = await this.pool.query(
        `INSERT INTO customer_teams (customer_id, name, code, description)
         VALUES ($1, $2, $3, $4)
         RETURNING *`,
        [customerId, payload.name, payload.code, payload.description],
      );
      await this.audit(actorUserId, customerId, "team.created", { teamId: result.rows[0].id, name: payload.name }, ipAddress);
      return serializeTeam(result.rows[0]);
    } catch (error) {
      if (error.code === "23505") throw badRequest("A team with this name or code already exists for the customer.", 409);
      throw error;
    }
  }

  async updateCustomerTeam(actorUserId, customerId, teamId, payload, ipAddress = "") {
    try {
      const result = await this.pool.query(
        `UPDATE customer_teams SET name = $3, code = $4, description = $5, updated_at = now()
         WHERE customer_id = $1 AND id = $2 RETURNING *`,
        [customerId, teamId, payload.name, payload.code, payload.description],
      );
      if (!result.rowCount) throw badRequest("Team was not found.", 404);
      await this.audit(actorUserId, customerId, "team.updated", { teamId, name: payload.name }, ipAddress);
      return serializeTeam(result.rows[0]);
    } catch (error) {
      if (error.code === "23505") throw badRequest("A team with this name or code already exists for the customer.", 409);
      throw error;
    }
  }

  async listCustomerAssets(customerId, limit = 500, assetTypes = []) {
    const result = await this.pool.query(
      `SELECT asset.id, asset.asset_key, asset.ip_address, asset.dns_name, asset.host_name, asset.external_id,
              asset.asset_type, asset.onboarding_tool, asset.team_id, team.name AS team_name, asset.platform,
              asset.business_unit, asset.criticality, asset.internet_exposed, asset.origin, asset.in_scope,
              asset.first_seen_at, asset.last_seen_at, asset.updated_at
       FROM customer_assets asset
       LEFT JOIN customer_teams team ON team.id = asset.team_id AND team.customer_id = asset.customer_id
       WHERE asset.customer_id = $1 AND (cardinality($3::text[]) = 0 OR asset.asset_type = ANY($3::text[]))
       ORDER BY asset.in_scope DESC, asset.origin, COALESCE(NULLIF(asset.dns_name, ''), NULLIF(asset.host_name, ''), asset.ip_address, asset.asset_key)
       LIMIT $2`,
      [customerId, limit, assetTypes],
    );
    return result.rows.map(serializeAsset);
  }

  async upsertCustomerAssets(actorUserId, customerId, assets, ipAddress = "") {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const payload = JSON.stringify(assets);
      const invalidTeam = await client.query(
        `SELECT item->>'teamId' AS team_id
         FROM jsonb_array_elements($2::jsonb) item
         WHERE NULLIF(item->>'teamId', '') IS NOT NULL
           AND NOT EXISTS (SELECT 1 FROM customer_teams team WHERE team.id = (item->>'teamId')::uuid AND team.customer_id = $1)
         LIMIT 1`,
        [customerId, payload],
      );
      if (invalidTeam.rowCount) throw badRequest("One or more assets reference a team outside this customer.");
      const inserted = await client.query(
        `INSERT INTO customer_assets (
           customer_id, asset_key, ip_address, dns_name, host_name, external_id,
           asset_type, onboarding_tool, team_id, platform, business_unit, criticality, internet_exposed, origin, in_scope
         )
         SELECT $1::uuid, item->>'assetKey', item->>'ipAddress', item->>'dnsName', item->>'hostName',
                item->>'externalId', item->>'assetType', item->>'onboardingTool', NULLIF(item->>'teamId', '')::uuid,
                item->>'platform', item->>'businessUnit', item->>'criticality',
                CASE WHEN item->>'internetExposed' IS NULL THEN NULL ELSE (item->>'internetExposed')::boolean END,
                'manual', (item->>'inScope')::boolean
         FROM jsonb_array_elements($2::jsonb) item
         ON CONFLICT (customer_id, asset_key) DO UPDATE SET
           ip_address = EXCLUDED.ip_address,
           dns_name = EXCLUDED.dns_name,
           host_name = EXCLUDED.host_name,
           external_id = EXCLUDED.external_id,
           asset_type = EXCLUDED.asset_type,
           onboarding_tool = EXCLUDED.onboarding_tool,
           team_id = EXCLUDED.team_id,
           platform = EXCLUDED.platform,
           business_unit = EXCLUDED.business_unit,
           criticality = EXCLUDED.criticality,
           internet_exposed = EXCLUDED.internet_exposed,
           origin = 'manual',
           in_scope = EXCLUDED.in_scope,
           last_seen_at = now(),
           updated_at = now()
         RETURNING id`,
        [customerId, payload],
      );
      await client.query(
        `WITH unique_aliases AS (
           SELECT DISTINCT ON (lower(alias.value))
                  $1::uuid AS customer_id, asset.id AS asset_id, lower(alias.value) AS alias
           FROM jsonb_array_elements($2::jsonb) item
           JOIN customer_assets asset ON asset.customer_id = $1 AND asset.asset_key = item->>'assetKey'
           CROSS JOIN LATERAL (
             SELECT value
             FROM unnest(ARRAY[item->>'assetKey', item->>'ipAddress', item->>'dnsName', item->>'hostName', item->>'externalId']) value
             WHERE NULLIF(trim(value), '') IS NOT NULL
           ) alias
           ORDER BY lower(alias.value), asset.id
         )
         INSERT INTO customer_asset_aliases (customer_id, asset_id, alias)
         SELECT customer_id, asset_id, alias FROM unique_aliases
         ON CONFLICT (customer_id, alias) DO UPDATE SET asset_id = EXCLUDED.asset_id`,
        [customerId, payload],
      );
      await client.query(
        `INSERT INTO audit_events (actor_user_id, customer_id, event_type, event_data, ip_address)
         VALUES ($1, $2, 'assets.upserted', $3::jsonb, $4)`,
        [actorUserId, customerId, JSON.stringify({ count: inserted.rowCount }), ipAddress],
      );
      await client.query("COMMIT");
      return { count: inserted.rowCount };
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async deleteCustomerAssets(actorUserId, customerId, assetIds, ipAddress = "") {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const deleted = await client.query(
        `DELETE FROM customer_assets
         WHERE customer_id = $1 AND id = ANY($2::uuid[])
         RETURNING id`,
        [customerId, assetIds],
      );
      if (deleted.rowCount !== assetIds.length) throw badRequest("One or more selected assets were not found in this tenant.", 404);
      await client.query(
        `INSERT INTO audit_events (actor_user_id, customer_id, event_type, event_data, ip_address)
         VALUES ($1, $2, 'assets.deleted', $3::jsonb, $4)`,
        [actorUserId, customerId, JSON.stringify({ count: deleted.rowCount, assetIds }), ipAddress],
      );
      await client.query("COMMIT");
      return { count: deleted.rowCount };
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async setAssetScope(actorUserId, customerId, assetId, inScope, ipAddress = "") {
    const result = await this.pool.query(
      `UPDATE customer_assets SET in_scope = $3, updated_at = now()
       WHERE id = $1 AND customer_id = $2
       RETURNING *`,
      [assetId, customerId, Boolean(inScope)],
    );
    if (!result.rowCount) throw badRequest("Asset was not found.", 404);
    await this.audit(actorUserId, customerId, "asset.scope_changed", { assetId, inScope: Boolean(inScope) }, ipAddress);
    return serializeAsset(result.rows[0]);
  }

  async updateCustomerAsset(actorUserId, customerId, assetId, changes, ipAddress = "") {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const currentResult = await client.query("SELECT * FROM customer_assets WHERE id = $1 AND customer_id = $2 FOR UPDATE", [assetId, customerId]);
      if (!currentResult.rowCount) throw badRequest("Asset was not found.", 404);
      const current = currentResult.rows[0];
      if (changes.hasTeamId && changes.teamId) {
        const team = await client.query("SELECT id FROM customer_teams WHERE id = $1 AND customer_id = $2", [changes.teamId, customerId]);
        if (!team.rowCount) throw badRequest("Responsible team was not found in this tenant.", 404);
      }
      const ip = changes.hasIpAddress ? changes.ipAddress : current.ip_address;
      const dns = changes.hasDnsName ? changes.dnsName : current.dns_name;
      const host = changes.hasHostName ? changes.hostName : current.host_name;
      const assetKey = String(ip || dns || host || current.external_id).trim().toLowerCase();
      if (!assetKey) throw badRequest("An asset needs an IP address or host name.");
      const aliases = [...new Set([assetKey, ip, dns, host, current.external_id].map((value) => String(value ?? "").trim().toLowerCase()).filter(Boolean))];
      const collision = await client.query(
        `SELECT alias FROM customer_asset_aliases
         WHERE customer_id = $1 AND asset_id <> $2 AND alias = ANY($3::text[])
         LIMIT 1`,
        [customerId, assetId, aliases],
      );
      if (collision.rowCount) throw badRequest(`Asset identity '${collision.rows[0].alias}' already belongs to another asset.`, 409);
      const result = await client.query(
         `UPDATE customer_assets asset
         SET asset_key = $3,
             ip_address = $4,
             dns_name = $5,
             host_name = $6,
             in_scope = COALESCE($7::boolean, asset.in_scope),
             asset_type = COALESCE($8::text, asset.asset_type),
             team_id = CASE WHEN $10::boolean THEN $9::uuid ELSE asset.team_id END,
             onboarding_tool = CASE WHEN $12::boolean THEN $11::text ELSE asset.onboarding_tool END,
             platform = CASE WHEN $14::boolean THEN $13::text ELSE asset.platform END,
             updated_at = now()
         WHERE asset.id = $1 AND asset.customer_id = $2
         RETURNING asset.*`,
        [assetId, customerId, assetKey, ip, dns, host, typeof changes.inScope === "boolean" ? changes.inScope : null,
          changes.assetType || null, changes.teamId || null, Boolean(changes.hasTeamId),
          changes.onboardingTool || "manual", Boolean(changes.hasOnboardingTool),
          changes.platform ?? "", Boolean(changes.hasPlatform)],
      );
      await client.query("DELETE FROM customer_asset_aliases WHERE customer_id = $1 AND asset_id = $2", [customerId, assetId]);
      await client.query(
        `INSERT INTO customer_asset_aliases (customer_id, asset_id, alias)
         SELECT $1, $2, unnest($3::text[])`,
        [customerId, assetId, aliases],
      );
      await client.query(
        `INSERT INTO audit_events (actor_user_id, customer_id, event_type, event_data, ip_address)
         VALUES ($1, $2, 'asset.updated', $3::jsonb, $4)`,
        [actorUserId, customerId, JSON.stringify({ assetId, ...changes }), ipAddress],
      );
      await client.query("COMMIT");
      const selectedTeamId = result.rows[0].team_id;
      const teamResult = selectedTeamId ? await this.pool.query("SELECT name FROM customer_teams WHERE id = $1", [selectedTeamId]) : { rows: [] };
      return serializeAsset({ ...result.rows[0], team_name: teamResult.rows[0]?.name ?? "" });
    } catch (error) {
      await client.query("ROLLBACK");
      if (error.code === "23505") throw badRequest("Another asset already uses this IP address or host name.", 409);
      throw error;
    } finally {
      client.release();
    }
  }

  async syncObservedAssets(customerId, scanRunId) {
    const customerResult = await this.pool.query("SELECT asset_scope_mode FROM customers WHERE id = $1", [customerId]);
    if (!customerResult.rowCount) return;
    const observedInScope = customerResult.rows[0].asset_scope_mode === "observed";
    await this.pool.query(
      `INSERT INTO customer_assets (
         customer_id, asset_key, ip_address, dns_name, host_name, asset_type, onboarding_tool, platform, criticality,
         internet_exposed, origin, in_scope, first_seen_at, last_seen_at
       )
       SELECT $1::uuid,
              lower(COALESCE(NULLIF(trim(ip_address), ''), NULLIF(trim(dns_name), ''))) AS asset_key,
              max(ip_address), max(dns_name), max(dns_name),
              CASE
                WHEN lower(max(platform_details)) ~ '(router|switch|wireless|network|load balancer)' THEN 'Network Device'
                WHEN lower(max(platform_details)) ~ '(firewall|waf|ids|ips|security appliance)' THEN 'Security Appliance'
                WHEN lower(max(platform_details)) ~ '(linux|ubuntu|debian|red hat|rhel|centos|suse|unix)' THEN 'Linux Server'
                WHEN lower(max(platform_details)) ~ '(windows server)' THEN 'Windows Server'
                WHEN lower(max(platform_details)) ~ '(windows 1[01]|macos|desktop|laptop|workstation)' THEN 'Endpoint'
                WHEN lower(max(platform_details)) ~ '(postgres|mysql|oracle database|sql server|database)' THEN 'Database'
                WHEN lower(max(platform_details)) ~ '(aws|azure|gcp|cloud)' THEN 'Cloud Asset'
                WHEN lower(max(platform_details)) ~ '(vmware|esxi|hyper-v|virtualization)' THEN 'Virtualization Host'
                WHEN lower(max(platform_details)) ~ '(kubernetes|openshift|container)' THEN 'Container Platform'
                WHEN lower(max(platform_details)) ~ '(scada|plc|industrial|ot device)' THEN 'OT Device'
                ELSE 'Other'
              END,
              CASE
                WHEN (SELECT source_tool FROM scan_runs WHERE id = $2) IN ('tenable-sc', 'tenable-io', 'qualys', 'crowdstrike', 'mdvm')
                  THEN (SELECT source_tool FROM scan_runs WHERE id = $2)
                WHEN (SELECT source_tool FROM scan_runs WHERE id = $2) = 'unified' THEN 'multi-tool'
                ELSE 'other'
              END,
              max(platform_details), max(asset_criticality),
              bool_or(internet_exposed), 'scanner', $3::boolean,
              COALESCE(min(first_discovered)::timestamptz, now()),
              COALESCE(max(last_observed)::timestamptz, now())
       FROM finding_observations
       WHERE scan_run_id = $2
         AND COALESCE(NULLIF(trim(ip_address), ''), NULLIF(trim(dns_name), '')) IS NOT NULL
       GROUP BY lower(COALESCE(NULLIF(trim(ip_address), ''), NULLIF(trim(dns_name), '')))
       ON CONFLICT (customer_id, asset_key) DO UPDATE SET
         ip_address = COALESCE(NULLIF(EXCLUDED.ip_address, ''), customer_assets.ip_address),
         dns_name = COALESCE(NULLIF(EXCLUDED.dns_name, ''), customer_assets.dns_name),
         host_name = COALESCE(NULLIF(customer_assets.host_name, ''), EXCLUDED.host_name),
         asset_type = CASE WHEN customer_assets.origin = 'manual' THEN customer_assets.asset_type ELSE EXCLUDED.asset_type END,
         onboarding_tool = CASE
           WHEN customer_assets.onboarding_tool IN ('manual', 'other') THEN EXCLUDED.onboarding_tool
           WHEN customer_assets.onboarding_tool = EXCLUDED.onboarding_tool THEN customer_assets.onboarding_tool
           ELSE 'multi-tool'
         END,
         platform = COALESCE(NULLIF(customer_assets.platform, ''), EXCLUDED.platform),
         criticality = COALESCE(NULLIF(customer_assets.criticality, ''), EXCLUDED.criticality),
         internet_exposed = COALESCE(customer_assets.internet_exposed, EXCLUDED.internet_exposed),
         in_scope = customer_assets.in_scope OR $3::boolean,
         last_seen_at = GREATEST(customer_assets.last_seen_at, EXCLUDED.last_seen_at),
         updated_at = now()`,
      [customerId, scanRunId, observedInScope],
    );
  }

  async getCustomerDashboard(customerId, assetTypes = [], teamId = null, assetId = null) {
    const customerResult = await this.pool.query("SELECT * FROM customers WHERE id = $1", [customerId]);
    if (!customerResult.rowCount) throw badRequest("Customer was not found.", 404);
    const customer = serializeCustomer(customerResult.rows[0]);
    const inventory = await this.pool.query(
      `WITH typed AS (
         SELECT asset_type, count(*)::integer AS total,
                count(*) FILTER (WHERE in_scope)::integer AS in_scope,
                count(*) FILTER (WHERE origin = 'manual')::integer AS manual,
                count(*) FILTER (WHERE origin = 'scanner')::integer AS discovered
         FROM customer_assets
         WHERE customer_id = $1
           AND (cardinality($2::text[]) = 0 OR asset_type = ANY($2::text[]))
           AND ($3::uuid IS NULL OR team_id = $3::uuid)
           AND ($4::uuid IS NULL OR id = $4::uuid)
         GROUP BY asset_type
       )
       SELECT COALESCE(sum(total), 0)::integer AS total_assets,
              COALESCE(sum(in_scope), 0)::integer AS in_scope_assets,
              COALESCE(sum(manual), 0)::integer AS manual_assets,
              COALESCE(sum(discovered), 0)::integer AS discovered_assets,
              COALESCE(jsonb_object_agg(asset_type, total), '{}'::jsonb) AS asset_types
       FROM typed`,
      [customerId, assetTypes, teamId, assetId],
    );
    const inventorySummary = serializeInventory(inventory.rows[0]);
    const latestResult = await this.pool.query(
      `SELECT * FROM scan_runs
       WHERE customer_id = $1 AND status = 'ready'
       ORDER BY finalized_at DESC NULLS LAST, created_at DESC
       LIMIT 1`,
      [customerId],
    );
    if (!latestResult.rowCount) return emptyDashboard(customer, inventorySummary);
    const latestRun = latestResult.rows[0];
    const periodsResult = await this.pool.query(
      `SELECT report_period_date, min(report_period) AS report_period
       FROM finding_observations
       WHERE scan_run_id = $1
       GROUP BY report_period_date
       ORDER BY report_period_date DESC NULLS LAST`,
      [latestRun.id],
    );
    const datedPeriods = periodsResult.rows.filter((row) => row.report_period_date);
    const currentPeriod = datedPeriods[0] ?? periodsResult.rows[0];
    const currentDate = currentPeriod?.report_period_date ?? null;
    let previousRunId = latestRun.id;
    let previousPeriod = datedPeriods[1] ?? null;
    if (!previousPeriod) {
      const previousResult = await this.pool.query(
        `SELECT run.id, period.report_period_date, period.report_period
         FROM scan_runs run
         JOIN LATERAL (
           SELECT report_period_date, min(report_period) AS report_period
           FROM finding_observations
           WHERE scan_run_id = run.id
             AND ($4::date IS NULL OR report_period_date < $4::date)
           GROUP BY report_period_date
           ORDER BY report_period_date DESC NULLS LAST
           LIMIT 1
         ) period ON true
         WHERE run.customer_id = $1 AND run.status = 'ready' AND run.id <> $2
           AND run.source_tool = $3
         ORDER BY period.report_period_date DESC NULLS LAST,
                  run.finalized_at DESC NULLS LAST, run.created_at DESC
         LIMIT 1`,
        [customerId, latestRun.id, latestRun.source_tool, currentDate],
      );
      if (previousResult.rowCount) {
        previousRunId = previousResult.rows[0].id;
        previousPeriod = previousResult.rows[0];
      }
    }
    if (!previousPeriod) previousRunId = null;

    const previousDate = previousPeriod?.report_period_date ?? null;
    // Active posture always follows the tenant's current inventory. Observed-mode
    // scans populate that inventory automatically, but deleting an asset removes its
    // findings from live dashboards and exports without destroying audit evidence.
    const baseScope = inventoryScopeSql("finding");
    const currentScope = `${baseScope} AND ${assetTypeScopeSql("finding", "$4")} AND ${teamScopeSql("finding", "$5")} AND ${assetScopeSql("finding", "$6")}`;
    const currentWhere = `finding.scan_run_id = $2 AND ($3::date IS NULL OR finding.report_period_date = $3::date) AND ${currentScope}`;
    const metrics = await this.pool.query(
      `SELECT COALESCE(sum(finding.record_count), 0)::bigint AS total_open,
              count(DISTINCT lower(COALESCE(NULLIF(finding.dns_name, ''), NULLIF(finding.ip_address, ''))))::integer AS affected_assets,
              COALESCE(sum(finding.record_count) FILTER (WHERE finding.patch_priority IN ('P1', 'P2')), 0)::bigint AS immediate_patch,
              COALESCE(sum(finding.record_count) FILTER (WHERE finding.exploit_available), 0)::bigint AS exploitable
       FROM finding_observations finding
       WHERE ${currentWhere}`,
      [customerId, latestRun.id, currentDate, assetTypes, teamId, assetId],
    );
    const distributions = await this.pool.query(
      `SELECT 'severity' AS dimension, finding.severity AS label, sum(finding.record_count)::bigint AS count
       FROM finding_observations finding WHERE ${currentWhere} GROUP BY finding.severity
       UNION ALL
       SELECT 'priority', finding.patch_priority, sum(finding.record_count)::bigint
       FROM finding_observations finding WHERE ${currentWhere} GROUP BY finding.patch_priority
       UNION ALL
       SELECT 'source', finding.source_tool, sum(finding.record_count)::bigint
       FROM finding_observations finding WHERE ${currentWhere} GROUP BY finding.source_tool`,
      [customerId, latestRun.id, currentDate, assetTypes, teamId, assetId],
    );
    const lifecycle = await this.pool.query(
      `WITH current_set AS (
         SELECT finding.finding_key, sum(finding.record_count)::bigint AS count,
                max(finding.vulnerability_name) AS vulnerability_name, max(finding.cve) AS cve,
                max(finding.patch_priority) AS patch_priority
         FROM finding_observations finding
         WHERE finding.scan_run_id = $2
           AND ($3::date IS NULL OR finding.report_period_date = $3::date)
           AND ${baseScope} AND ${assetTypeScopeSql("finding", "$6")} AND ${teamScopeSql("finding", "$7")} AND ${assetScopeSql("finding", "$8")}
         GROUP BY finding.finding_key
       ), previous_set AS (
         SELECT finding.finding_key, sum(finding.record_count)::bigint AS count,
                max(finding.vulnerability_name) AS vulnerability_name, max(finding.cve) AS cve,
                max(finding.patch_priority) AS patch_priority
         FROM finding_observations finding
         WHERE $4::uuid IS NOT NULL AND finding.scan_run_id = $4
           AND ($5::date IS NULL OR finding.report_period_date = $5::date)
           AND ${baseScope} AND ${assetTypeScopeSql("finding", "$6")} AND ${teamScopeSql("finding", "$7")} AND ${assetScopeSql("finding", "$8")}
         GROUP BY finding.finding_key
       )
       SELECT CASE WHEN $4::uuid IS NULL THEN 0 ELSE COALESCE(sum(current_set.count) FILTER (WHERE previous_set.finding_key IS NULL), 0) END::bigint AS new_count,
              CASE WHEN $4::uuid IS NULL THEN 0 ELSE COALESCE(sum(previous_set.count) FILTER (WHERE current_set.finding_key IS NULL), 0) END::bigint AS fixed_count,
              CASE WHEN $4::uuid IS NULL THEN 0 ELSE COALESCE(sum(current_set.count) FILTER (WHERE previous_set.finding_key IS NOT NULL), 0) END::bigint AS repeated_count
       FROM current_set FULL OUTER JOIN previous_set USING (finding_key)`,
      [customerId, latestRun.id, currentDate, previousRunId, previousDate, assetTypes, teamId, assetId],
    );
    const age = await this.pool.query(
      `SELECT finding.patch_priority,
              CASE WHEN COALESCE(finding.vulnerability_age_days, 0) <= 7 THEN '0-7 days'
                   WHEN finding.vulnerability_age_days <= 30 THEN '8-30 days'
                   WHEN finding.vulnerability_age_days <= 60 THEN '31-60 days'
                   WHEN finding.vulnerability_age_days <= 180 THEN '61-180 days'
                   ELSE 'Over 180 days' END AS age_bucket,
              sum(finding.record_count)::bigint AS count
       FROM finding_observations finding
       WHERE ${currentWhere}
       GROUP BY finding.patch_priority, age_bucket`,
      [customerId, latestRun.id, currentDate, assetTypes, teamId, assetId],
    );
    const topAssets = await this.pool.query(
      `SELECT COALESCE(NULLIF(finding.dns_name, ''), NULLIF(finding.ip_address, ''), 'Unknown asset') AS asset,
              max(finding.ip_address) AS ip_address,
              sum(finding.record_count)::bigint AS total,
              sum(finding.record_count) FILTER (WHERE finding.patch_priority = 'P1')::bigint AS p1,
              sum(finding.record_count) FILTER (WHERE finding.patch_priority = 'P2')::bigint AS p2
       FROM finding_observations finding
       WHERE ${currentWhere}
       GROUP BY COALESCE(NULLIF(finding.dns_name, ''), NULLIF(finding.ip_address, ''), 'Unknown asset')
       ORDER BY total DESC, asset
       LIMIT 10`,
      [customerId, latestRun.id, currentDate, assetTypes, teamId, assetId],
    );
    const trend = await this.pool.query(
      `WITH candidate_periods AS (
         SELECT run.id AS scan_run_id, finding.report_period_date, min(finding.report_period) AS report_period,
                run.finalized_at,
                row_number() OVER (PARTITION BY finding.report_period_date ORDER BY run.finalized_at DESC NULLS LAST, run.created_at DESC) AS rank
         FROM scan_runs run
         JOIN finding_observations finding ON finding.scan_run_id = run.id
         WHERE run.customer_id = $1 AND run.status = 'ready' AND finding.report_period_date IS NOT NULL
         GROUP BY run.id, finding.report_period_date, run.finalized_at, run.created_at
       ), selected_periods AS (
         SELECT * FROM candidate_periods WHERE rank = 1 ORDER BY report_period_date DESC LIMIT 6
       )
       SELECT selected.report_period_date, selected.report_period, sum(finding.record_count)::bigint AS total_open
       FROM selected_periods selected
       JOIN finding_observations finding ON finding.scan_run_id = selected.scan_run_id AND finding.report_period_date = selected.report_period_date
       WHERE ${inventoryScopeSql("finding")}
         AND ${assetTypeScopeSql("finding", "$2")}
         AND ${teamScopeSql("finding", "$3")}
         AND ${assetScopeSql("finding", "$4")}
       GROUP BY selected.report_period_date, selected.report_period
       ORDER BY selected.report_period_date`,
      [customerId, assetTypes, teamId, assetId],
    );
    const unfiltered = await this.pool.query(
      `SELECT COALESCE(sum(record_count), 0)::bigint AS count
       FROM finding_observations finding
       WHERE finding.scan_run_id = $2 AND ($3::date IS NULL OR finding.report_period_date = $3::date)
         AND ${assetTypeScopeSql("finding", "$4")}
         AND ${teamScopeSql("finding", "$5")}
         AND ${assetScopeSql("finding", "$6")}`,
      [customerId, latestRun.id, currentDate, assetTypes, teamId, assetId],
    );
    const teamBreakdown = await this.pool.query(
      `WITH team_assets AS (
         SELECT team_id, count(*)::integer AS asset_count,
                count(*) FILTER (WHERE in_scope)::integer AS in_scope_asset_count
         FROM customer_assets
         WHERE customer_id = $1 AND team_id IS NOT NULL
           AND (cardinality($4::text[]) = 0 OR asset_type = ANY($4::text[]))
           AND ($5::uuid IS NULL OR id = $5::uuid)
         GROUP BY team_id
       ), finding_owners AS (
         SELECT owner.team_id,
                sum(finding.record_count)::bigint AS total_open,
                COALESCE(sum(finding.record_count) FILTER (WHERE finding.patch_priority = 'P1'), 0)::bigint AS p1,
                COALESCE(sum(finding.record_count) FILTER (WHERE finding.patch_priority = 'P2'), 0)::bigint AS p2
         FROM finding_observations finding
         JOIN LATERAL (
           SELECT owned_asset.team_id
           FROM customer_assets owned_asset
           WHERE owned_asset.customer_id = $1 AND owned_asset.in_scope AND owned_asset.team_id IS NOT NULL
             AND (cardinality($4::text[]) = 0 OR owned_asset.asset_type = ANY($4::text[]))
             AND ($5::uuid IS NULL OR owned_asset.id = $5::uuid)
             AND ${findingAssetMatchSql("finding", "owned_asset")}
           ORDER BY owned_asset.origin = 'manual' DESC, owned_asset.updated_at DESC
           LIMIT 1
         ) owner ON true
         WHERE finding.scan_run_id = $2
           AND ($3::date IS NULL OR finding.report_period_date = $3::date)
           AND ${baseScope}
         GROUP BY owner.team_id
       )
       SELECT team.id, team.name, team.code,
              COALESCE(team_assets.asset_count, 0)::integer AS asset_count,
              COALESCE(team_assets.in_scope_asset_count, 0)::integer AS in_scope_asset_count,
              COALESCE(finding_owners.total_open, 0)::bigint AS total_open,
              COALESCE(finding_owners.p1, 0)::bigint AS p1,
              COALESCE(finding_owners.p2, 0)::bigint AS p2
       FROM customer_teams team
       LEFT JOIN team_assets ON team_assets.team_id = team.id
       LEFT JOIN finding_owners ON finding_owners.team_id = team.id
       WHERE team.customer_id = $1 AND ($6::uuid IS NULL OR team.id = $6::uuid)
       ORDER BY total_open DESC, team.name`,
      [customerId, latestRun.id, currentDate, assetTypes, assetId, teamId],
    );
    const row = metrics.rows[0];
    const lifecycleRow = lifecycle.rows[0];
    const distribution = (dimension) => Object.fromEntries(distributions.rows.filter((item) => item.dimension === dimension).map((item) => [item.label, Number(item.count)]));
    return {
      customer,
      latestRun: serializeRun(latestRun),
      currentPeriod: currentPeriod?.report_period ?? latestRun.report_period,
      previousPeriod: previousPeriod?.report_period ?? null,
      comparisonAvailable: Boolean(previousRunId),
      metrics: {
        totalOpen: Number(row.total_open),
        affectedAssets: Number(row.affected_assets),
        immediatePatch: Number(row.immediate_patch),
        exploitable: Number(row.exploitable),
        newFindings: Number(lifecycleRow.new_count),
        fixedFindings: Number(lifecycleRow.fixed_count),
        repeatedFindings: Number(lifecycleRow.repeated_count),
        excludedByScope: Math.max(0, Number(unfiltered.rows[0].count) - Number(row.total_open)),
      },
      severity: distribution("severity"),
      priority: distribution("priority"),
      sources: distribution("source"),
      ageByPriority: age.rows.map((item) => ({ priority: item.patch_priority, bucket: item.age_bucket, count: Number(item.count) })),
      topAssets: topAssets.rows.map((item) => ({ asset: item.asset, ipAddress: item.ip_address, total: Number(item.total), p1: Number(item.p1 ?? 0), p2: Number(item.p2 ?? 0) })),
      teamBreakdown: teamBreakdown.rows.map((item) => ({ id: item.id, name: item.name, code: item.code, assetCount: Number(item.asset_count), inScopeAssetCount: Number(item.in_scope_asset_count), totalOpen: Number(item.total_open), p1: Number(item.p1), p2: Number(item.p2) })),
      selectedTeamId: teamId,
      selectedAssetId: assetId,
      trend: trend.rows.map((item) => ({ period: item.report_period, date: calendarDate(item.report_period_date), totalOpen: Number(item.total_open) })),
      inventory: inventorySummary,
      recentRuns: await this.listScanRuns(customerId, 6, assetTypes),
    };
  }

  async getCustomerFindingExport(customerId, assetTypes = [], teamId = null, assetId = null) {
    const customerResult = await this.pool.query("SELECT * FROM customers WHERE id = $1", [customerId]);
    if (!customerResult.rowCount) throw badRequest("Customer was not found.", 404);
    const customer = serializeCustomer(customerResult.rows[0]);
    const latestResult = await this.pool.query(
      `SELECT * FROM scan_runs
       WHERE customer_id = $1 AND status = 'ready'
       ORDER BY finalized_at DESC NULLS LAST, created_at DESC
       LIMIT 1`,
      [customerId],
    );
    if (!latestResult.rowCount) return { customer, reportPeriod: "current", rows: [] };

    const latestRun = latestResult.rows[0];
    const periodResult = await this.pool.query(
      `SELECT report_period_date, min(report_period) AS report_period
       FROM finding_observations
       WHERE scan_run_id = $1
       GROUP BY report_period_date
       ORDER BY report_period_date DESC NULLS LAST
       LIMIT 1`,
      [latestRun.id],
    );
    const period = periodResult.rows[0] ?? { report_period_date: null, report_period: latestRun.report_period };
    const baseScope = inventoryScopeSql("finding");
    const result = await this.pool.query(
      `SELECT finding.ip_address, finding.dns_name,
              COALESCE(owner.team_name, 'Unassigned') AS asset_owner,
              finding.vulnerability_name, finding.cve, finding.severity,
              finding.exploit_available, finding.patch_priority, finding.asset_exposure,
              finding.vulnerability_finding, finding.summary, finding.description,
              finding.remediation, finding.kb_links, finding.platform_details,
              finding.namespace, finding.deployment, finding.image, finding.component,
              finding.fixable, finding.fixed_in, finding.cvss_score,
              finding.first_discovered, finding.last_observed
       FROM finding_observations finding
       LEFT JOIN LATERAL (
         SELECT team.name AS team_name
         FROM customer_assets owned_asset
         LEFT JOIN customer_teams team ON team.id = owned_asset.team_id AND team.customer_id = owned_asset.customer_id
         WHERE owned_asset.customer_id = $1
           AND ${findingAssetMatchSql("finding", "owned_asset")}
         ORDER BY owned_asset.origin = 'manual' DESC, owned_asset.updated_at DESC
         LIMIT 1
       ) owner ON true
       WHERE finding.scan_run_id = $2
         AND ($3::date IS NULL OR finding.report_period_date = $3::date)
         AND ${baseScope}
         AND ${assetTypeScopeSql("finding", "$4")}
         AND ${teamScopeSql("finding", "$5")}
         AND ${assetScopeSql("finding", "$6")}
       ORDER BY CASE finding.patch_priority WHEN 'P1' THEN 1 WHEN 'P2' THEN 2 WHEN 'P3' THEN 3 ELSE 4 END,
                CASE finding.severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 ELSE 5 END,
                finding.ip_address, finding.dns_name, finding.vulnerability_name, finding.row_index`,
      [customerId, latestRun.id, period.report_period_date, assetTypes, teamId, assetId],
    );
    return {
      customer,
      reportPeriod: period.report_period ?? latestRun.report_period,
      rows: result.rows.map((row) => ({
        ipAddress: row.ip_address,
        dnsName: row.dns_name,
        assetOwner: row.asset_owner,
        vulnerabilityName: row.vulnerability_name,
        cve: row.cve,
        severity: row.severity,
        exploitAvailable: row.exploit_available,
        patchPriority: row.patch_priority,
        assetExposure: Number(row.asset_exposure ?? 0),
        vulnerabilityFinding: row.vulnerability_finding,
        summary: row.summary,
        description: row.description,
        remediation: row.remediation,
        kbLinks: row.kb_links,
        platformDetails: row.platform_details,
        namespace: row.namespace,
        deployment: row.deployment,
        image: row.image,
        component: row.component,
        fixable: row.fixable,
        fixedIn: row.fixed_in,
        cvssScore: row.cvss_score == null ? null : Number(row.cvss_score),
        firstDiscovered: calendarDate(row.first_discovered),
        lastObserved: calendarDate(row.last_observed),
      })),
    };
  }

  async createThreatIntelImport(customerId, createdBy, payload) {
    const id = randomUUID();
    const inserted = await this.pool.query(
      `INSERT INTO threat_intel_imports (
         id, customer_id, created_by, ingestion_key, source_label, file_names, expected_records
       ) VALUES ($1, $2, $3, $4, $5, $6, $7)
       ON CONFLICT (customer_id, ingestion_key) DO NOTHING
       RETURNING *`,
      [id, customerId, createdBy, payload.ingestionKey, payload.sourceLabel, payload.fileNames, payload.expectedRecords],
    );
    if (inserted.rowCount) return { ...serializeThreatIntelImport(inserted.rows[0]), existing: false };
    const existing = await this.pool.query(
      "SELECT * FROM threat_intel_imports WHERE customer_id = $1 AND ingestion_key = $2",
      [customerId, payload.ingestionKey],
    );
    return { ...serializeThreatIntelImport(existing.rows[0]), existing: true };
  }

  async ingestThreatIntelChunk(customerId, importId, payload) {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const importResult = await client.query(
        "SELECT * FROM threat_intel_imports WHERE id = $1 AND customer_id = $2 FOR UPDATE",
        [importId, customerId],
      );
      if (!importResult.rowCount) throw badRequest("Threat-intelligence import was not found.", 404);
      const imported = importResult.rows[0];
      if (imported.status === "ready") throw badRequest("A finalized threat-intelligence import cannot accept records.", 409);
      const chunk = normalizeThreatIntelChunkPayload(payload, imported.expected_records);
      const inserted = await client.query(
        `INSERT INTO threat_intel_records (
           import_id, customer_id, row_index, cve, vulnerability_name, source_tool,
           source_vulnerability_id, ip_address, dns_name, severity, patch_priority, exploit_available,
           vulnerability_confidence, exploit_evidence, description, remediation,
           kb_links, product, platform_details, namespace, deployment, image, component,
           fixable, fixed_in, cvss_score, first_observed, last_observed, normalized_payload
         )
         SELECT $1::uuid, $2::uuid, (item->>'rowIndex')::integer, item->>'cve',
                item->>'vulnerabilityName', item->>'sourceTool', item->>'sourceVulnerabilityId',
                item->>'ipAddress', item->>'dnsName',
                item->>'severity', item->>'patchPriority', (item->>'exploitAvailable')::boolean,
                item->>'vulnerabilityConfidence', item->>'exploitEvidence', item->>'description',
                item->>'remediation', item->>'kbLinks', item->>'product', item->>'platformDetails',
                item->>'namespace', item->>'deployment', item->>'image', item->>'component',
                (item->>'fixable')::boolean, item->>'fixedIn', NULLIF(item->>'cvssScore', '')::double precision,
                NULLIF(item->>'firstObserved', '')::date, NULLIF(item->>'lastObserved', '')::date,
                item->'payload'
         FROM jsonb_array_elements($3::jsonb) AS item
         ON CONFLICT (import_id, row_index) DO NOTHING
         RETURNING row_index`,
        [importId, customerId, JSON.stringify(chunk.records)],
      );
      const updated = await client.query(
        `UPDATE threat_intel_imports
         SET received_records = received_records + $2, updated_at = now()
         WHERE id = $1
         RETURNING *`,
        [importId, inserted.rowCount],
      );
      await client.query("COMMIT");
      return { inserted: inserted.rowCount, import: serializeThreatIntelImport(updated.rows[0]) };
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async finalizeThreatIntelImport(customerId, importId) {
    const result = await this.pool.query(
      `UPDATE threat_intel_imports
       SET status = 'ready', finalized_at = COALESCE(finalized_at, now()), updated_at = now()
       WHERE id = $1 AND customer_id = $2 AND received_records = expected_records
       RETURNING *`,
      [importId, customerId],
    );
    if (result.rowCount) return serializeThreatIntelImport(result.rows[0]);
    const current = await this.pool.query(
      "SELECT * FROM threat_intel_imports WHERE id = $1 AND customer_id = $2",
      [importId, customerId],
    );
    if (!current.rowCount) throw badRequest("Threat-intelligence import was not found.", 404);
    if (current.rows[0].status === "ready") return serializeThreatIntelImport(current.rows[0]);
    throw badRequest(
      `Cannot finalize threat intelligence: received ${current.rows[0].received_records}/${current.rows[0].expected_records} records.`,
      409,
    );
  }

  async searchThreatIntel(customerId, query = "", limit = 100) {
    const needle = String(query || "").trim().toLowerCase();
    const result = await this.pool.query(
      `SELECT record.*, imported.source_label, imported.file_names, imported.finalized_at
       FROM threat_intel_records record
       JOIN threat_intel_imports imported ON imported.id = record.import_id
       WHERE record.customer_id = $1
         AND imported.status = 'ready'
         AND (
           $2 = ''
           OR lower(record.cve) LIKE $3
           OR lower(record.vulnerability_name) LIKE $3
           OR lower(record.source_vulnerability_id) LIKE $3
           OR lower(record.product) LIKE $3
           OR lower(record.component) LIKE $3
           OR lower(record.image) LIKE $3
         )
       ORDER BY
         CASE record.patch_priority WHEN 'P1' THEN 1 WHEN 'P2' THEN 2 WHEN 'P3' THEN 3 ELSE 4 END,
         CASE record.severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 ELSE 5 END,
         record.last_observed DESC NULLS LAST, record.vulnerability_name
       LIMIT $4`,
      [customerId, needle, `%${needle}%`, Math.min(500, Math.max(1, Number(limit) || 100))],
    );
    return result.rows.map(serializeThreatIntelRecord);
  }

  async saveThreatIntelEnrichment(actorUserId, customerId, { query, model, evidenceCount, responseText }) {
    const result = await this.pool.query(
      `INSERT INTO threat_intel_enrichments (
         customer_id, created_by, query, model, evidence_count, response_text
       ) VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, created_at`,
      [customerId, actorUserId, query, model, evidenceCount, responseText],
    );
    return { id: result.rows[0].id, createdAt: result.rows[0].created_at };
  }

  async audit(actorUserId, customerId, eventType, eventData = {}, ipAddress = "") {
    await this.pool.query(
      `INSERT INTO audit_events (actor_user_id, customer_id, event_type, event_data, ip_address)
       VALUES ($1, $2, $3, $4::jsonb, $5)`,
      [actorUserId || null, customerId || null, eventType, JSON.stringify(eventData), ipAddress.slice(0, 200)],
    );
  }
}

function serializeRun(row) {
  if (!row) return null;
  return {
    id: row.id,
    customerId: row.customer_id,
    customerName: row.customer_name,
    ingestionKey: row.ingestion_key,
    workflow: row.workflow,
    sourceTool: row.source_tool,
    sourceLabel: row.source_label,
    reportPeriod: row.report_period,
    fileNames: row.file_names ?? [],
    sourceIds: row.source_ids ?? [],
    expectedFindings: row.expected_findings,
    receivedFindings: row.received_findings,
    weightedFindings: Number(row.weighted_findings ?? 0),
    expectedChunks: row.expected_chunks,
    receivedChunks: row.received_chunks,
    status: row.status,
    dashboard: row.dashboard,
    inputSummary: row.input_summary,
    createdAt: row.created_at,
    finalizedAt: row.finalized_at,
  };
}

function serializeUser(row) {
  return {
    id: row.id,
    email: row.email,
    fullName: row.full_name,
    globalRole: row.global_role,
    status: row.status,
    createdAt: row.created_at,
    lastLoginAt: row.last_login_at,
  };
}

function serializeCustomer(row) {
  return {
    id: row.id,
    name: row.name,
    slug: row.slug,
    status: row.status,
    assetScopeMode: row.asset_scope_mode,
    notes: row.notes ?? "",
    membershipRole: row.membership_role,
    assetTypeScope: row.asset_type_scope ?? [],
    assetCount: Number(row.asset_count ?? 0),
    scanCount: Number(row.scan_count ?? 0),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function serializeAsset(row) {
  return {
    id: row.id,
    assetKey: row.asset_key,
    ipAddress: row.ip_address,
    dnsName: row.dns_name,
    hostName: row.host_name,
    externalId: row.external_id,
    assetType: row.asset_type,
    onboardingTool: row.onboarding_tool ?? "manual",
    teamId: row.team_id,
    teamName: row.team_name ?? "",
    platform: row.platform,
    businessUnit: row.business_unit,
    criticality: row.criticality,
    internetExposed: row.internet_exposed,
    origin: row.origin,
    inScope: row.in_scope,
    firstSeenAt: row.first_seen_at,
    lastSeenAt: row.last_seen_at,
    updatedAt: row.updated_at,
  };
}

function serializeTeam(row) {
  return {
    id: row.id,
    customerId: row.customer_id,
    name: row.name,
    code: row.code,
    description: row.description ?? "",
    assetCount: Number(row.asset_count ?? 0),
    inScopeAssetCount: Number(row.in_scope_asset_count ?? 0),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function serializeThreatIntelImport(row) {
  if (!row) return null;
  return {
    id: row.id,
    customerId: row.customer_id,
    ingestionKey: row.ingestion_key,
    sourceLabel: row.source_label,
    fileNames: row.file_names ?? [],
    expectedRecords: Number(row.expected_records ?? 0),
    receivedRecords: Number(row.received_records ?? 0),
    status: row.status,
    createdAt: row.created_at,
    finalizedAt: row.finalized_at,
  };
}

function serializeThreatIntelRecord(row) {
  return {
    importId: row.import_id,
    cve: row.cve,
    vulnerabilityName: row.vulnerability_name,
    sourceTool: row.source_tool,
    sourceVulnerabilityId: row.source_vulnerability_id,
    ipAddress: row.ip_address,
    dnsName: row.dns_name,
    sourceLabel: row.source_label,
    severity: row.severity,
    patchPriority: row.patch_priority,
    exploitAvailable: row.exploit_available,
    vulnerabilityConfidence: row.vulnerability_confidence,
    exploitEvidence: row.exploit_evidence,
    description: row.description,
    remediation: row.remediation,
    kbLinks: row.kb_links,
    product: row.product,
    platformDetails: row.platform_details,
    namespace: row.namespace,
    deployment: row.deployment,
    image: row.image,
    component: row.component,
    fixable: row.fixable,
    fixedIn: row.fixed_in,
    cvssScore: row.cvss_score == null ? null : Number(row.cvss_score),
    firstObserved: calendarDate(row.first_observed),
    lastObserved: calendarDate(row.last_observed),
    fileNames: row.file_names ?? [],
    finalizedAt: row.finalized_at,
  };
}

function serializeInventory(row = {}) {
  const assetTypes = Object.fromEntries(Object.entries(row.asset_types ?? {}).map(([assetType, count]) => [assetType, Number(count)]));
  return {
    totalAssets: Number(row.total_assets ?? 0),
    inScopeAssets: Number(row.in_scope_assets ?? 0),
    manualAssets: Number(row.manual_assets ?? 0),
    discoveredAssets: Number(row.discovered_assets ?? 0),
    assetTypes,
  };
}

function calendarDate(value) {
  if (!value) return "";
  if (!(value instanceof Date)) return String(value).slice(0, 10);
  const pad = (part) => String(part).padStart(2, "0");
  return `${value.getFullYear()}-${pad(value.getMonth() + 1)}-${pad(value.getDate())}`;
}

function inventoryScopeSql(alias) {
  return `EXISTS (
    SELECT 1 FROM customer_assets scope_asset
    WHERE scope_asset.customer_id = $1
      AND scope_asset.in_scope
      AND (
        scope_asset.asset_key IN (
          lower(NULLIF(trim(${alias}.ip_address), '')),
          lower(NULLIF(trim(${alias}.dns_name), ''))
        )
        OR EXISTS (
          SELECT 1 FROM customer_asset_aliases scope_alias
          WHERE scope_alias.customer_id = $1
            AND scope_alias.asset_id = scope_asset.id
            AND scope_alias.alias IN (
              lower(NULLIF(trim(${alias}.ip_address), '')),
              lower(NULLIF(trim(${alias}.dns_name), ''))
            )
        )
      )
  )`;
}

function assetTypeScopeSql(alias, parameter) {
  return `(cardinality(${parameter}::text[]) = 0 OR EXISTS (
    SELECT 1 FROM customer_assets access_asset
    WHERE access_asset.customer_id = $1
      AND access_asset.in_scope
      AND access_asset.asset_type = ANY(${parameter}::text[])
      AND (
        access_asset.asset_key IN (
          lower(NULLIF(trim(${alias}.ip_address), '')),
          lower(NULLIF(trim(${alias}.dns_name), ''))
        )
        OR EXISTS (
          SELECT 1 FROM customer_asset_aliases access_alias
          WHERE access_alias.customer_id = $1
            AND access_alias.asset_id = access_asset.id
            AND access_alias.alias IN (
              lower(NULLIF(trim(${alias}.ip_address), '')),
              lower(NULLIF(trim(${alias}.dns_name), ''))
            )
        )
      )
  ))`;
}

function teamScopeSql(alias, parameter) {
  return `(${parameter}::uuid IS NULL OR EXISTS (
    SELECT 1 FROM customer_assets team_asset
    WHERE team_asset.customer_id = $1
      AND team_asset.team_id = ${parameter}::uuid
      AND team_asset.in_scope
      AND ${findingAssetMatchSql(alias, "team_asset")}
  ))`;
}

function assetScopeSql(alias, parameter) {
  return `(${parameter}::uuid IS NULL OR EXISTS (
    SELECT 1 FROM customer_assets selected_asset
    WHERE selected_asset.customer_id = $1
      AND selected_asset.id = ${parameter}::uuid
      AND selected_asset.in_scope
      AND ${findingAssetMatchSql(alias, "selected_asset")}
  ))`;
}

function findingAssetMatchSql(findingAlias, assetAlias) {
  return `(
    ${assetAlias}.asset_key IN (
      lower(NULLIF(trim(${findingAlias}.ip_address), '')),
      lower(NULLIF(trim(${findingAlias}.dns_name), ''))
    )
    OR lower(NULLIF(trim(${assetAlias}.ip_address), '')) IN (
      lower(NULLIF(trim(${findingAlias}.ip_address), '')),
      lower(NULLIF(trim(${findingAlias}.dns_name), ''))
    )
    OR lower(NULLIF(trim(${assetAlias}.dns_name), '')) IN (
      lower(NULLIF(trim(${findingAlias}.ip_address), '')),
      lower(NULLIF(trim(${findingAlias}.dns_name), ''))
    )
    OR EXISTS (
      SELECT 1 FROM customer_asset_aliases ownership_alias
      WHERE ownership_alias.customer_id = $1
        AND ownership_alias.asset_id = ${assetAlias}.id
        AND ownership_alias.alias IN (
          lower(NULLIF(trim(${findingAlias}.ip_address), '')),
          lower(NULLIF(trim(${findingAlias}.dns_name), ''))
        )
    )
  )`;
}

async function assertFindingsMatchAssetTypes(client, customerId, findings, assetTypes) {
  const violation = await client.query(
    `SELECT item->>'findingKey' AS finding_key,
            COALESCE(NULLIF(item->>'dnsName', ''), NULLIF(item->>'ipAddress', ''), 'Unknown asset') AS asset
     FROM jsonb_array_elements($2::jsonb) item
     WHERE NOT EXISTS (
       SELECT 1 FROM customer_assets allowed_asset
       WHERE allowed_asset.customer_id = $1
         AND allowed_asset.in_scope
         AND allowed_asset.asset_type = ANY($3::text[])
         AND (
           allowed_asset.asset_key IN (lower(NULLIF(item->>'ipAddress', '')), lower(NULLIF(item->>'dnsName', '')))
           OR lower(NULLIF(allowed_asset.ip_address, '')) IN (lower(NULLIF(item->>'ipAddress', '')), lower(NULLIF(item->>'dnsName', '')))
           OR lower(NULLIF(allowed_asset.dns_name, '')) IN (lower(NULLIF(item->>'ipAddress', '')), lower(NULLIF(item->>'dnsName', '')))
           OR EXISTS (
             SELECT 1 FROM customer_asset_aliases allowed_alias
             WHERE allowed_alias.customer_id = $1
               AND allowed_alias.asset_id = allowed_asset.id
               AND allowed_alias.alias IN (lower(NULLIF(item->>'ipAddress', '')), lower(NULLIF(item->>'dnsName', '')))
           )
         )
     )
     LIMIT 1`,
    [customerId, JSON.stringify(findings), assetTypes],
  );
  if (violation.rowCount) {
    throw badRequest(`Finding '${violation.rows[0].finding_key}' belongs to ${violation.rows[0].asset}, which is outside this account's ${assetTypes.join(", ")} asset scope.`, 403);
  }
}

function emptyDashboard(customer, inventory = { totalAssets: 0, inScopeAssets: 0, manualAssets: 0, discoveredAssets: 0, assetTypes: {} }) {
  return {
    customer,
    latestRun: null,
    currentPeriod: null,
    previousPeriod: null,
    comparisonAvailable: false,
    metrics: { totalOpen: 0, affectedAssets: 0, immediatePatch: 0, exploitable: 0, newFindings: 0, fixedFindings: 0, repeatedFindings: 0, excludedByScope: 0 },
    severity: {},
    priority: {},
    sources: {},
    ageByPriority: [],
    topAssets: [],
    teamBreakdown: [],
    selectedTeamId: null,
    selectedAssetId: null,
    trend: [],
    inventory,
    recentRuns: [],
  };
}
