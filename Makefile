GO = go
GOFMT = gofmt

CURRENT_DIR = $(shell pwd -P)
DEPLOY_DIR = ./deploy
DIST_DIR = ./dist

CONNECT_TOKEN := $(shell GATEWAY_ADDRESS=127.0.0.1:40000 GATEWAY_PUBLIC_KEY=vnIjsJWZzgq+nS9t3KU7ch5BFhgDkm2U2bm7/2W6eRs= AUTH_PRIVATE_KEY=VmmdIRwxUb7vmzupzHbBHqJF3WPpLrp0Y0EzepAzny0= ./dist/connect_token)

.PHONY: help
help:
	@echo "$$(grep -hE '^\S+:.*##' $(MAKEFILE_LIST) | sed -e 's/:.*##\s*/:/' -e 's/^\(.\+\):\(.*\)/\\033[36m\1\\033[m:\2/' | column -c2 -t -s :)"

.PHONY: dist
dist:
	mkdir -p $(DIST_DIR)

.PHONY: build-client
build-client: dist
	@printf "Building client... "
	@$(GO) build -o ${DIST_DIR}/client ./cmd/client/client.go
	@printf "done\n"

.PHONY: build-gateway
build-gateway: dist
	@printf "Building gateway... "
	@$(GO) build -o ${DIST_DIR}/gateway ./cmd/gateway/gateway.go
	@printf "done\n"

.PHONY: build-server
build-server: dist
	@printf "Building server... "
	@$(GO) build -o ${DIST_DIR}/server ./cmd/server/server.go
	@printf "done\n"

.PHONY: build-auth
build-auth: dist
	@printf "Building auth... "
	@$(GO) build -o ${DIST_DIR}/auth ./cmd/auth/auth.go
	@printf "done\n"

.PHONY: build-connect-token
build-connect-token: dist
	@printf "Building connect token... "
	@$(GO) build -o ${DIST_DIR}/connect_token ./cmd/connect_token/connect_token.go
	@printf "done\n"

.PHONY: build-keygen
build-keygen: dist
	@printf "Building kegen... "
	@$(GO) build -o ${DIST_DIR}/keygen ./cmd/keygen/keygen.go
	@printf "done\n"

.PHONY: build-soak
build-soak: dist build-client build-server build-gateway
	@printf "Building soak... "
	@$(GO) build -o ${DIST_DIR}/soak ./cmd/soak/soak.go
	@printf "done\n"

.PHONY: dev-client
dev-client: build-connect-token build-client ## runs a local client
	UDP_PORT=30000 CLIENT_ADDRESS=127.0.0.1:30000 CONNECT_TOKEN=$(CONNECT_TOKEN) ./dist/client

.PHONY: dev-gateway
dev-gateway: build-gateway ## runs a local gateway
	HTTP_PORT=40000 UDP_PORT=40000 GATEWAY_ADDRESS=127.0.0.1:40000 GATEWAY_INTERNAL_ADDRESS=127.0.0.1:40001 GATEWAY_PRIVATE_KEY=qmnxBZs2UElVT4SXCdDuX4td+qtPkuXLL5VdOE0vvcA= AUTH_PUBLIC_KEY=i9XuIDN5ePgWiRGZZoxNKjQv3ZC9JAfMjXGTIr4peQM= SERVER_ADDRESS=127.0.0.1:50000 ./dist/gateway

.PHONY: dev-server
dev-server: build-server ## runs a local server
	HTTP_PORT=50000 UDP_PORT=50000 ./dist/server

.PHONY: dev-auth
dev-auth: build-auth ## runs a local auth
	HTTP_PORT=60000 GATEWAY_PUBLIC_KEY=vnIjsJWZzgq+nS9t3KU7ch5BFhgDkm2U2bm7/2W6eRs= AUTH_PRIVATE_KEY=VmmdIRwxUb7vmzupzHbBHqJF3WPpLrp0Y0EzepAzny0= ./dist/auth

.PHONY: connect-token
connect-token: build-connect-token ## generate connect token
	GATEWAY_ADDRESS=127.0.0.1:40000 GATEWAY_PUBLIC_KEY=vnIjsJWZzgq+nS9t3KU7ch5BFhgDkm2U2bm7/2W6eRs= AUTH_PRIVATE_KEY=VmmdIRwxUb7vmzupzHbBHqJF3WPpLrp0Y0EzepAzny0= ./dist/connect_token

.PHONY: keygen
keygen: build-keygen ## generate keypair
	./dist/keygen

.PHONY: soak test
soak: build-soak ## run soak test
	./dist/soak

.PHONY: test
test: ## runs unit tests
	go test ./... -coverprofile ./cover.out -timeout 30s

.PHONY: format
format:
	@$(GOFMT) -s -w .

.PHONY: build-all
build-all: build-client build-gateway build-server build-auth build-soak build-keygen build-connect-token ## builds everything

.PHONY: rebuild-all
rebuild-all: clean build-all ## rebuilds everything

.PHONY: clean
clean: ## cleans everything
	@rm -fr $(DIST_DIR)
	@mkdir $(DIST_DIR)
