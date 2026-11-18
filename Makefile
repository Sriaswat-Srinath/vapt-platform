SHELL := /bin/bash
COMPOSE_LAB := docker compose -f docker-compose.lab.yml
.PHONY: help lab-subnet-check lab-up lab-down lab-check lab-reset lab-logs lab-zap-restart \
        zap-state zap-reset lab-prove-failure test-lab test-invariants

help:
	@grep -E '^[a-z-]+:.*?##' $(MAKEFILE_LIST) | sed 's/:.*##/\t/' | expand -t28

lab-subnet-check:            ## refuse to start if LAB_SUBNET conflicts
	@./scripts/lab_subnet_check.sh

lab-up: lab-subnet-check     ## bring up the isolated lab (subnet-checked first)
	@$(COMPOSE_LAB) up -d
	@echo "waiting for health..."; \
	for i in $$(seq 1 60); do \
	  js=$$(docker inspect vapt_juiceshop --format '{{.State.Health.Status}}' 2>/dev/null); \
	  zp=$$(docker inspect vapt_zap --format '{{.State.Health.Status}}' 2>/dev/null); \
	  [ "$$js" = healthy ] && [ "$$zp" = healthy ] && { echo "lab healthy"; exit 0; }; sleep 5; done; \
	echo "lab did not become healthy: juiceshop=$$js zap=$$zp"; exit 1

lab-down: lab-unpublish      ## stop the lab (keeps nothing; lab is disposable)
	@$(COMPOSE_LAB) down

lab-check:                   ## isolation verification (strict: containment + access + host hygiene)
	@./scripts/lab_isolation_check.sh

lab-check-containment:       ## isolation verification, containment only (ignores foreign host listeners)
	@./scripts/lab_isolation_check.sh --require containment

lab-reset:                   ## recreate the lab clean. Scoped to project `vapt` ONLY.
	@$(COMPOSE_LAB) down -v --remove-orphans
	@$(MAKE) --no-print-directory lab-up

lab-logs:                    ## tail lab logs
	@$(COMPOSE_LAB) logs -f --tail=100

lab-zap-restart:             ## OPERATOR action: restart the ZAP container (the app cannot)
	@echo "operator-performed container restart (the platform has no Docker socket)"
	@$(COMPOSE_LAB) restart zap
	@for i in $$(seq 1 24); do 	  [ "$$(docker inspect vapt_zap --format '{{.State.Health.Status}}')" = healthy ] && break; sleep 5; done
	@./scripts/zap_daemon_state.sh ack-restart
	@./scripts/lab_isolation_check.sh --require containment

zap-state:                   ## show the scanner daemon dirty state
	@./scripts/zap_daemon_state.sh status

zap-reset:                   ## verification-gated reset; clears dirty ONLY on full pass
	@./scripts/zap_daemon_state.sh reset

lab-prove-failure:           ## prove the isolation check can FAIL, then revert
	@./scripts/prove_isolation_failure.sh

test-lab:                    ## pytest wrappers over the probes
	@python3 -m pytest tests/lab -v

test-invariants:             ## security invariants + manifest
	@python3 -m pytest backend/tests/invariants -v

lab-publish:                 ## OPT-IN: loopback forwarder 127.0.0.1:3000 -> lab target (deviation D19)
	@if [ -f .lab-state/publish.pid ] && kill -0 $$(cat .lab-state/publish.pid) 2>/dev/null; then \
	  echo "forwarder already running (pid $$(cat .lab-state/publish.pid))"; else \
	  set -a; [ -f .env ] && . ./.env; set +a; \
	  nohup ./scripts/lab_publish.py >> .lab-state/publish.log 2>&1 & \
	  sleep 1; echo "started: $$(tail -n1 .lab-state/publish.log)"; fi

lab-unpublish:               ## stop the loopback forwarder
	@if [ -f .lab-state/publish.pid ]; then kill $$(cat .lab-state/publish.pid) 2>/dev/null; \
	  rm -f .lab-state/publish.pid; echo "forwarder stopped"; else echo "not running"; fi

net-subnet-check:            ## refuse app-plane bring-up on a subnet conflict
	@./scripts/net_subnet_check.sh

net-up: net-subnet-check     ## bring up the M1.5 placeholder app plane
	@docker compose -f docker-compose.yml up -d
	@sleep 3; docker compose -f docker-compose.yml ps --format '{{.Name}} {{.State}}'

net-down:                    ## tear down the app plane (incl. the test stand-in)
	@docker compose -f docker-compose.yml down

net-verify:                  ## run the network architecture verification
	@./scripts/net_verify.sh

net-prove-failure:           ## prove net_verify FAILS under induced egress, then reverts
	@./scripts/prove_net_failure.sh

test-net:                    ## pytest wrappers over the network probes
	@python3 -m pytest tests/net -v

api-up:                      ## build + start the real API (phase 2)
	@docker compose -f docker-compose.yml up -d --build api
	@for i in $$(seq 1 24); do \
	  [ "$$(docker inspect vapt_api --format '{{.State.Health.Status}}')" = healthy ] && { echo "api healthy"; exit 0; }; sleep 5; done; \
	echo "api did not become healthy"; exit 1

db-migrate:                  ## run alembic migrations
	@set -a; . ./.env; set +a; docker run --rm --network vapt_core \
	  -e DATABASE_URL="postgresql+psycopg://$$POSTGRES_USER:$$POSTGRES_PASSWORD@172.30.21.40:5432/$$POSTGRES_DB" \
	  -e SECRET_KEY="$$SECRET_KEY" vapt-api:dev alembic upgrade head

db-seed:                     ## seed accounts, profiles and MOCK-WEB-001 (no grant, no signature)
	@set -a; . ./.env; set +a; docker run --rm --network vapt_core \
	  -e DATABASE_URL="postgresql+psycopg://$$POSTGRES_USER:$$POSTGRES_PASSWORD@172.30.21.40:5432/$$POSTGRES_DB" \
	  -e SECRET_KEY="$$SECRET_KEY" vapt-api:dev python -m app.seed

api-publish:                 ## OPT-IN loopback forwarder 127.0.0.1:8000 -> api (deviation D19)
	@if [ -f .lab-state/publish-api.pid ] && kill -0 $$(cat .lab-state/publish-api.pid) 2>/dev/null; then \
	  echo "already running (pid $$(cat .lab-state/publish-api.pid))"; else \
	  nohup ./scripts/app_publish.py api >> .lab-state/publish-api.log 2>&1 & \
	  sleep 1; echo "$$(tail -n1 .lab-state/publish-api.log)"; fi

api-unpublish:               ## stop the api forwarder
	@if [ -f .lab-state/publish-api.pid ]; then kill $$(cat .lab-state/publish-api.pid) 2>/dev/null; \
	  rm -f .lab-state/publish-api.pid; echo "stopped"; else echo "not running"; fi

isolation-report:            ## run lab-check and report the result to the API (admin)
	@./scripts/report_isolation.sh
