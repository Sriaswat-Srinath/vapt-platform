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

lab-check:                   ## run the isolation verification suite
	@./scripts/lab_isolation_check.sh

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
	@$(MAKE) --no-print-directory lab-check

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
