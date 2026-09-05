# AttackSimPro — developer entrypoints.
# Everything here runs locally with no GCP credentials and no deploy.
.PHONY: help install lint test smoke serve-ingest serve-dashboard up down check \
        engine-test e2e sim catalog gate

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

check: lint test smoke ## Lint + ingest unit tests + smoke

engine-test: ## Run the simulation engine test suite (unit+integration+security)
	python3 -m unittest discover -s simcore/tests -p 'test_*.py'

e2e: ## End-to-end sandbox simulation (loopback fixtures + ingest)
	bash scripts/e2e/simulation_e2e.sh

catalog: ## Regenerate the dashboard scenario + remediation catalogs
	python3 -m simcore catalog > public/catalog.json
	python3 -m simcore remediation > public/remediation.json

sim: ## Run a sandbox validation against the local vulnerable fixture
	@python3 scripts/attack-sim/targets.py >/tmp/asp-tgt.log 2>&1 & echo $$! > /tmp/asp-tgt.pid; sleep 1; \
	  python3 -m simcore run --targets http://127.0.0.1:9101 --group standard \
	    --client "Demo Client" --scan-id demo-1 --out evidence/demo-1 --audit-log evidence/audit.log; \
	  kill $$(cat /tmp/asp-tgt.pid) 2>/dev/null || true

gate: lint test smoke engine-test e2e ## The full local quality gate (everything)
	@echo "All gates green."

serve-ingest: ## Run storeScanResults locally on :8088 (in-memory Firestore)
	cd functions && npm run start:local

serve-dashboard: ## Serve the dashboard on :8080 (open with ?client=<id>)
	cd public && python3 -m http.server 8080

up: ## Bring up ingest + dashboard via docker compose
	docker compose up --build

down: ## Tear down the docker compose stack
	docker compose down
