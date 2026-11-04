.PHONY: help install dev-api dev-web test test-all lint build up down openapi

help:            ## list targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-10s %s\n", $$1, $$2}'

install:         ## install backend (editable) and frontend dependencies
	cd backend && python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
	cd frontend && npm install

dev-api:         ## run the API with auto-reload on :8000
	cd backend && .venv/bin/uvicorn hunterintel.api.app:app_factory --factory --reload

dev-web:         ## run the SPA dev server on :5173 (proxies /api)
	cd frontend && npm run dev

test:            ## backend tests (no network, SQLite)
	cd backend && .venv/bin/pytest -q

test-all:        ## backend + frontend tests, lint, type-check, build
	cd backend && .venv/bin/ruff check hunterintel tests alembic && .venv/bin/pytest -q
	cd frontend && npm run typecheck && npm test && npm run build

lint:            ## ruff
	cd backend && .venv/bin/ruff check hunterintel tests alembic

openapi:         ## regenerate docs/openapi.json
	cd backend && .venv/bin/python scripts/export_openapi.py

up:              ## docker compose up --build (needs .env)
	docker compose up --build

down:            ## docker compose down
	docker compose down
