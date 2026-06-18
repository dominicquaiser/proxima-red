# Optional per-host deployment overrides (git-ignored). Copy deploy.mk.example
# to deploy.mk to deploy behind a host's own nginx - see docs/deployment.md
# "Deploying behind an existing host nginx". Without it, the default bundled
# nginx + certbot model is used.
-include deploy.mk

# Production compose files. A host-nginx deployment appends
# docker-compose.host.yml via COMPOSE_EXTRA (set in deploy.mk).
COMPOSE = docker compose -f docker-compose.yml -f docker-compose.prod.yml $(COMPOSE_EXTRA)

# Services started by `make up` / tailed by `make logs`. Empty means "every
# service in the compose files" (the bundled model). The host-nginx model sets
# this in deploy.mk to omit the bundled nginx/certbot.
SERVICES ?=

up: ## Build images and start services in the background
	$(COMPOSE) up -d --build $(SERVICES)

down: ## Stop and remove all containers
	$(COMPOSE) down

logs: ## Follow log output from all services
	$(COMPOSE) logs -f $(SERVICES)

ps: ## Show container status
	$(COMPOSE) ps

migrate: ## Apply pending migrations inside the running web container
	$(COMPOSE) exec web python manage.py migrate

shell: ## Open a shell inside the running web container
	$(COMPOSE) exec web sh

help: ## Display this help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "%-10s%s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: up down logs ps migrate shell help
