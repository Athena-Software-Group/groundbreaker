.PHONY: help db migrate seed user run scheduler poll evidence-import samples test lint scan scan-generic check docker

help:          ## list targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | sed 's/:.*## /\t/'

db:            ## start Postgres in docker
	docker compose up -d db

migrate:       ## apply schema
	alembic upgrade head

seed:          ## load the fixture in AEGIS_FIXTURE_PATH (default: the fictional demo case DEMO-2026-001) and run the first trace
	python -m scripts.seed_case

user:          ## create a user: make user EMAIL=you@example.com NAME="Your Name" ARGS=--system-admin
	python -m scripts.create_user "$(EMAIL)" "$(NAME)" $(ARGS)

run:           ## dev server with reload
	uvicorn app.main:app --reload --port 8000

scheduler:     ## watch poll + overdue-reply checks every 5 min (ARGS="--once" for one pass)
	python -m scripts.run_scheduler $(ARGS)

poll:          ## one watch-list poll for every open case (with notifications)
	python -m scripts.poll_watch

evidence-import: ## index an evidence folder by reference: make evidence-import CASE=REF SOURCE=/abs/dir ARGS=--dry-run
	python -m scripts.import_evidence --case "$(CASE)" --source "$(SOURCE)" $(ARGS)

samples:       ## regenerate docs/samples/stop-orders from the demo case (needs a seeded DATABASE_URL)
	python -m scripts.sample_stop_orders

test:          ## pytest (SQLite, offline fixture)
	pytest -q

lint:          ## ruff
	ruff check app tests scripts

scan:          ## PII/secret scan of everything that would be committed; uses AEGIS_DENYLIST (kept outside the repo) when set
	python scripts/pii_scan.py

scan-generic:  ## PII/secret scan with generic rules only (what CI runs)
	env -u AEGIS_DENYLIST python scripts/pii_scan.py

check: lint test scan  ## everything to run before a commit

docker:        ## full stack in docker
	docker compose up --build
