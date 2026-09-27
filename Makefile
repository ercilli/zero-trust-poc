.PHONY: all setup build up down test clean

all: setup build up

setup:
	@echo "Generando certificados criptográficos..."
	chmod +x scripts/*.sh
	./scripts/generate-certs.sh

build:
	docker compose build

up:
	docker compose up -d
	@echo "Servicios activos."
	@echo "Dashboard: http://localhost:3000"
	@echo "Keycloak:  http://localhost:8081 (admin/admin)"

down:
	docker compose down -v

test:
	./scripts/run-scenarios.sh

clean: down
	rm -rf certs/*.key certs/*.crt certs/*.csr certs/*.srl certs/*.cnf