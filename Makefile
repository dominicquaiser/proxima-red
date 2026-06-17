COMPOSE = docker compose -f docker-compose.yml -f docker-compose.prod.yml

up: ## Build images and start all services in the background
	$(COMPOSE) up -d --build

down: ## Stop and remove all containers
	$(COMPOSE) down

logs: ## Follow log output from all services
	$(COMPOSE) logs -f

migrate: ## Apply pending migrations inside the running web container
	$(COMPOSE) exec web python manage.py migrate

shell: ## Open a shell inside the running web container
	$(COMPOSE) exec web sh

help: ## Display this help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "%-10s%s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: up down logs migrate shell help
