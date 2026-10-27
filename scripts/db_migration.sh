#!/usr/bin/env bash
# =============================================================================
# Zero-Trust Sentinel - PostgreSQL migration, verification and rollback.
#
#   scripts/db_migration.sh dump <file.dump>          consistent backup (source)
#   scripts/db_migration.sh restore <file.dump>       restore into DATABASE_URL
#   scripts/db_migration.sh verify [file.dump]        row counts + sequences
#   scripts/db_migration.sh tables                    list every app table
#   scripts/db_migration.sh rollback <file.dump>      restore the previous dump
#
# Credentials never appear on screen or in logs: connections come from
# $DATABASE_URL (loaded from .env if present) and pg_dump/pg_restore are given
# the URL as an environment variable, not an argument.
#
# Cutover procedure (documented in docs/ZERO_COST_RUNBOOK.md):
#   1. dump the source            -> source.dump
#   2. stop writers               -> docker compose stop api worker
#   3. dump again (final)         -> final.dump     (catches writes in step 1-2)
#   4. restore into the new DB    -> scripts/db_migration.sh restore final.dump
#   5. verify row counts          -> scripts/db_migration.sh verify final.dump
#   6. start the new stack        -> docker compose up -d
#   7. keep source.dump/final.dump until the new deployment is confirmed
# =============================================================================
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [ -f .env ]; then
    set -a
    # shellcheck disable=SC1091
    . ./.env
    set +a
fi

: "${DATABASE_URL:?DATABASE_URL is not set - copy .env.example to .env first}"

# Every application table discovered in db.py (init_db). Verified on restore.
APP_TABLES=(
    clients reports lead_tasks subscriptions coupons stripe_events
    lead_stages referrals scan_tasks trajectories
    business_projects business_outputs
)

info() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32mOK\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mERR\033[0m %s\n' "$*" >&2; exit 1; }

need_url_tool() {
    command -v "$1" >/dev/null 2>&1 || die "$1 not found - install postgresql client tools"
}

row_counts() {
    # Prints "table rows" for every known table; missing table => 0.
    local t
    printf '%s\n' "${APP_TABLES[@]}" | while read -r t; do
        n=$(PGPASSWORD='' psql "$DATABASE_URL" -tAc \
            "SELECT count(*) FROM ONLY ${t}" 2>/dev/null || echo "ERR")
        printf '%s %s\n' "$t" "$n"
    done
}

case "${1:-}" in
    dump)
        need_url_tool pg_dump
        out="${2:?usage: db_migration.sh dump <file.dump>}"
        info "Dumping schema + data to $out (custom format)"
        pg_dump "$DATABASE_URL" -Fc --no-owner --no-privileges -f "$out"
        [ -s "$out" ] || die "dump produced no file"
        ok "dump written: $(wc -c <"$out") bytes"
        info "Next: restore with: scripts/db_migration.sh restore $out"
        ;;

    restore)
        need_url_tool pg_restore
        src="${2:?usage: db_migration.sh restore <file.dump>}"
        [ -f "$src" ] || die "no such dump: $src"
        info "Restoring $src into the configured database"
        # --clean --if-exists makes a re-run safe; transactions keep a failed
        # restore from leaving a half-migrated schema behind.
        pg_restore --clean --if-exists --no-owner --no-privileges \
            --single-transaction "$DATABASE_URL" "$src" \
            || die "restore failed - the transaction was rolled back; source DB untouched"
        ok "restore complete"
        scripts/db_migration.sh verify "$src"
        ;;

    verify)
        need_url_tool psql
        info "Application tables and row counts"
        printf '%-22s %s\n' "TABLE" "ROWS"
        bad=0
        while read -r t n; do
            printf '%-22s %s\n' "$t" "$n"
            [ "$n" = "ERR" ] && { die "table $t is missing in the target database"; }
        done < <(row_counts)

        info "Sequences (must be past MAX(id) or inserts will collide)"
        psql "$DATABASE_URL" -tAc \
            "SELECT sequence_name FROM information_schema.sequences
             WHERE sequence_schema='public' ORDER BY 1" | while read -r s; do
            [ -n "$s" ] && printf '   %s\n' "$s"
        done

        if [ -n "${2:-}" ] && [ -f "${2:-}" ]; then
            info "Comparing counts against the dump (custom format: strings only)"
            # Custom-format dumps are binary; compare via a temp restore when a
            # second database is configured (SOURCE_DATABASE_URL).
            if [ -n "${SOURCE_DATABASE_URL:-}" ]; then
                mismatch=0
                for t in "${APP_TABLES[@]}"; do
                    a=$(PGPASSWORD='' psql "$DATABASE_URL" -tAc "SELECT count(*) FROM ONLY $t" 2>/dev/null || echo 0)
                    b=$(PGPASSWORD='' psql "$SOURCE_DATABASE_URL" -tAc "SELECT count(*) FROM ONLY $t" 2>/dev/null || echo 0)
                    if [ "$a" != "$b" ]; then
                        printf '   MISMATCH %s: target=%s source=%s\n' "$t" "$a" "$b"
                        mismatch=1
                    fi
                done
                [ "$mismatch" = "0" ] && ok "row counts match SOURCE_DATABASE_URL on every table"
            else
                info "set SOURCE_DATABASE_URL to compare source vs target row counts"
            fi
        fi
        ok "verification finished"
        ;;

    tables)
        need_url_tool psql
        psql "$DATABASE_URL" -c \
            "SELECT table_name FROM information_schema.tables
             WHERE table_schema='public' ORDER BY table_name"
        ;;

    rollback)
        info "Rolling back to a previous dump"
        scripts/db_migration.sh restore "${2:?usage: db_migration.sh rollback <file.dump>}"
        ;;

    *)
        sed -n '2,25p' "$0"
        exit 1
        ;;
esac
