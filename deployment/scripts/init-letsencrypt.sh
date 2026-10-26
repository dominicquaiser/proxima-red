#!/bin/sh
# One-time bootstrap of Let's Encrypt certificates for the nginx + certbot stack.
#
# Run this ONCE from the repo root before the first production `up`, after DNS
# for $DOMAIN points at this host and ports 80/443 are reachable:
#
#     ./deployment/scripts/init-letsencrypt.sh
#
# Reads DOMAIN and CERTBOT_EMAIL from .env. Set STAGING=1 to use Let's Encrypt's
# staging endpoint while testing (avoids hitting rate limits).
set -e

COMPOSE="docker compose -f docker-compose.yml -f docker-compose.prod.yml"

if [ -f .env ]; then
    set -a
    . ./.env
    set +a
fi

: "${DOMAIN:?Set DOMAIN in .env}"
: "${CERTBOT_EMAIL:?Set CERTBOT_EMAIL in .env}"

STAGING_FLAG=""
if [ "${STAGING:-0}" = "1" ]; then
    STAGING_FLAG="--staging"
    echo "### Using Let's Encrypt STAGING environment."
fi

CERT_PATH="/etc/letsencrypt/live/$DOMAIN"

echo "### Creating a temporary self-signed certificate so nginx can start ..."
$COMPOSE run --rm --entrypoint sh certbot -c "\
    mkdir -p '$CERT_PATH' && \
    openssl req -x509 -nodes -newkey rsa:2048 -days 1 \
        -keyout '$CERT_PATH/privkey.pem' \
        -out '$CERT_PATH/fullchain.pem' \
        -subj '/CN=$DOMAIN'"

echo "### Starting nginx (and the app stack) ..."
$COMPOSE up -d nginx

echo "### Removing the temporary certificate ..."
$COMPOSE run --rm --entrypoint sh certbot -c "\
    rm -rf /etc/letsencrypt/live/$DOMAIN \
        /etc/letsencrypt/archive/$DOMAIN \
        /etc/letsencrypt/renewal/$DOMAIN.conf"

echo "### Requesting a real certificate from Let's Encrypt ..."
$COMPOSE run --rm --entrypoint certbot certbot certonly \
    --webroot -w /var/www/certbot \
    -d "$DOMAIN" \
    -d "pass.$DOMAIN" \
    -d "note.$DOMAIN" \
    --email "$CERTBOT_EMAIL" \
    --agree-tos --no-eff-email --non-interactive \
    $STAGING_FLAG

echo "### Reloading nginx with the new certificate ..."
$COMPOSE exec nginx nginx -s reload

echo "### Done. HTTPS is live for https://$DOMAIN"
