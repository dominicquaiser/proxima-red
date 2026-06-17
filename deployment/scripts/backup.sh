#!/bin/sh
# Dump the production Postgres database to ./backups/ (timestamped, gzipped).
# Run from the repo root:  ./deployment/scripts/backup.sh
set -e

COMPOSE="docker compose -f docker-compose.yml -f docker-compose.prod.yml"

if [ -f .env ]; then
    set -a
    . ./.env
    set +a
fi

: "${POSTGRES_DB:?Set POSTGRES_DB in .env}"
: "${POSTGRES_USER:?Set POSTGRES_USER in .env}"

mkdir -p backups
OUT="backups/${POSTGRES_DB}-$(date +%Y%m%d-%H%M%S).sql.gz"

echo "### Backing up database '$POSTGRES_DB' -> $OUT"
$COMPOSE exec -T db pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB" | gzip > "$OUT"
echo "### Done."
