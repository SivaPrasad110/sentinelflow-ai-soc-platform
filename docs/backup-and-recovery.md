# SentinelFlow — Backup & Recovery Runbook

> **Status:** Operational documentation  
> **Applies to:** All production PostgreSQL instances (managed or self-hosted)  
> **Last updated:** Phase 7

---

## 1. Backup Procedures

### 1.1 — Full Database Backup (pg_dump)

```bash
# Standard pg_dump — produces a portable SQL dump
pg_dump \
  --dbname="$DATABASE_URL" \
  --format=custom \
  --compress=9 \
  --no-password \
  --verbose \
  --file="sentinelflow-backup-$(date +%Y%m%d-%H%M%S).dump"
```

**Format guide:**
- `--format=custom` — compressed binary; fastest restore, smaller file  
- `--format=plain` — plain SQL; human-readable, portable  
- `--format=directory` — parallel-capable for very large databases  

### 1.2 — Schema-Only Backup

```bash
pg_dump "$DATABASE_URL" \
  --schema-only \
  --format=plain \
  --file="sentinelflow-schema-$(date +%Y%m%d).sql"
```

### 1.3 — Data-Only Backup (preserves existing schema)

```bash
pg_dump "$DATABASE_URL" \
  --data-only \
  --format=custom \
  --file="sentinelflow-data-$(date +%Y%m%d-%H%M%S).dump"
```

### 1.4 — Managed Provider Automated Backups

| Provider | Backup Retention | Point-in-Time Recovery |
|---|---|---|
| Supabase (free) | 7 days | No (paid plans only) |
| Supabase (Pro) | 30 days | Yes (daily) |
| Railway | 7 days | No |
| Neon | 7 days | Yes (branch-based) |
| Render | 7 days (paid) | No |
| AWS RDS | 1–35 days | Yes (5-minute intervals) |

**Recommendation:** Enable automated backups at the provider level AND run weekly `pg_dump` backups stored externally (S3, Google Cloud Storage).

---

## 2. Scheduled Backup Script

```bash
#!/bin/bash
# scripts/backup.sh
# Cron: 0 2 * * * /path/to/scripts/backup.sh
# Schedule: Daily at 2:00 AM

set -euo pipefail

BACKUP_DIR="/var/backups/sentinelflow"
RETENTION_DAYS=30
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_FILE="$BACKUP_DIR/sentinelflow-$TIMESTAMP.dump"

mkdir -p "$BACKUP_DIR"

echo "[$(date -Iseconds)] Starting backup..."

pg_dump \
  --dbname="$DATABASE_URL" \
  --format=custom \
  --compress=9 \
  --no-password \
  --file="$BACKUP_FILE"

echo "[$(date -Iseconds)] Backup written to: $BACKUP_FILE ($(du -sh "$BACKUP_FILE" | cut -f1))"

# Remove backups older than RETENTION_DAYS
find "$BACKUP_DIR" -name "*.dump" -mtime "+$RETENTION_DAYS" -delete
echo "[$(date -Iseconds)] Pruned backups older than $RETENTION_DAYS days."

# Optional: upload to cloud storage
# aws s3 cp "$BACKUP_FILE" "s3://your-bucket/sentinelflow-backups/"
```

---

## 3. Restoration Procedures

### 3.1 — Full Restore

```bash
# ⚠️ WARNING: This will REPLACE the target database entirely.
# Always restore to a FRESH or TEST database first to verify integrity.

# Step 1: Create a fresh database
createdb sentinelflow_restore --owner=sentinelflow_user

# Step 2: Restore the backup
pg_restore \
  --dbname="postgresql://user:pass@host:5432/sentinelflow_restore" \
  --no-password \
  --verbose \
  --clean \
  --if-exists \
  sentinelflow-backup-YYYYMMDD-HHMMSS.dump

# Step 3: Verify row counts
psql "$RESTORE_DATABASE_URL" -c "
  SELECT 
    'organizations' as table_name, COUNT(*) FROM organizations
  UNION ALL SELECT 'users', COUNT(*) FROM users
  UNION ALL SELECT 'incidents', COUNT(*) FROM incidents
  UNION ALL SELECT 'security_alerts', COUNT(*) FROM security_alerts
  UNION ALL SELECT 'audit_logs', COUNT(*) FROM audit_logs
  ORDER BY 1;
"
```

### 3.2 — Backup Integrity Verification

```bash
# Verify backup file is readable without restoring
pg_restore --list sentinelflow-backup-YYYYMMDD-HHMMSS.dump | head -50

# Check backup file size (should be non-zero)
ls -lh sentinelflow-backup-*.dump
```

### 3.3 — Partial Restore (Single Table)

```bash
# Restore only the audit_logs table from backup
pg_restore \
  --dbname="$DATABASE_URL" \
  --table=audit_logs \
  --data-only \
  sentinelflow-backup-YYYYMMDD-HHMMSS.dump
```

---

## 4. Prisma Migration Rollback

### Understanding Prisma Migration State

Prisma tracks all applied migrations in the `_prisma_migrations` table:

```sql
SELECT id, migration_name, started_at, finished_at, applied_steps_count, rolled_back_at
FROM _prisma_migrations
ORDER BY started_at DESC
LIMIT 10;
```

### Safe Migration Process (Production)

```bash
# Step 1: Take a point-in-time backup BEFORE any migration
pg_dump "$DATABASE_URL" -Fc -f "pre-migration-$(date +%Y%m%d-%H%M%S).dump"

# Step 2: Check current migration status
npx prisma migrate status

# Step 3: Apply only pending migrations (never use migrate dev or db push)
npx prisma migrate deploy

# Step 4: Verify application starts correctly
curl https://api.yourdomain.com/api/v1/health

# Step 5: If failure — restore pre-migration backup
# pg_restore --dbname="$DATABASE_URL" --clean pre-migration-TIMESTAMP.dump
```

### Marking a Failed Migration as Rolled Back

```bash
# If a migration partially applied and must be re-applied after fixing:
npx prisma migrate resolve --rolled-back "20241201000000_migration_name"

# Then re-deploy after fixing the migration SQL
npx prisma migrate deploy
```

---

## 5. Data Preservation Rules

> These rules MUST be followed for all Phase 7+ operations.

| Rule | Rationale |
|---|---|
| Never run `prisma migrate reset` on production | Drops and recreates the entire database |
| Never run `prisma db push` on production | Bypasses migration history, can cause data loss |
| Never run `DROP TABLE` or `TRUNCATE` without a backup | Unrecoverable in most managed environments |
| Always use `prisma migrate deploy` in production | Safe, additive-only migration application |
| Always verify backup integrity before performing migrations | Prevention > recovery |
| Keep 30-day rolling backups + monthly archival snapshots | Satisfies common compliance requirements |

---

## 6. Recovery Time Objectives (Targets)

| Scenario | Target RTO | Procedure |
|---|---|---|
| Application code bug | < 5 minutes | Redeploy previous Docker image |
| Database migration failure | < 30 minutes | Restore pre-migration backup |
| Full database corruption | < 4 hours | Restore latest daily backup to managed DB |
| Data loss (accidental delete) | < 2 hours | Restore table from data-only backup |
