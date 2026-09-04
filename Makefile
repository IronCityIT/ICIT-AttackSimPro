# AttackSimPro — developer entrypoints.
# Everything here runs locally with no GCP credentials and no deploy.
.PHONY: help install lint test smoke serve-ingest serve-dashboard up down check

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n",$$1,$$2}'

install: ## Install Cloud Function dependencies
	cd functions && npm install --no-audit --no-fund

lint: ## Syntax-check the function sources
	cd functions && npm run lint

test: ## Run the deterministic unit tests (node:test, no deps)
	cd functions && npm test

smoke: ## Boot the local ingest server and drive the contract with curl
	bash scripts/smoke.sh

check: lint test smoke ## Lint + unit tests + smoke (the full local gate)

serve-ingest: ## Run storeScanResults locally on :8088 (in-memory Firestore)
	cd functions && npm run start:local

serve-dashboard: ## Serve the dashboard on :8080 (open with ?client=<id>)
	cd public && python3 -m http.server 8080

up: ## Bring up ingest + dashboard via docker compose
	docker compose up --build

down: ## Tear down the docker compose stack
	docker compose down
