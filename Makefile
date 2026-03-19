SHELL := /usr/bin/env bash

.DEFAULT_GOAL := dev

.PHONY: dev dev-bg stop logs status postgres-up postgres-down

dev:
	./scripts/dev.sh

dev-bg:
	./scripts/dev.sh --detach

stop:
	./scripts/dev.sh --stop

logs:
	./scripts/dev.sh --logs

status:
	./scripts/dev.sh --status

postgres-up:
	docker compose -f deploy/compose/postgres.yaml up -d

postgres-down:
	docker compose -f deploy/compose/postgres.yaml down
