GO = go
GOFMT = gofmt

CURRENT_DIR = $(shell pwd -P)
DEPLOY_DIR = ./deploy
DIST_DIR = ./dist

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

.PHONY: build-keygen
build-keygen: dist
	@printf "Building kegen... "
	@$(GO) build -o ${DIST_DIR}/keygen ./cmd/keygen/keygen.go
	@printf "done\n"

.PHONY: dev-client
dev-client: build-client ## runs a local client
	UDP_PORT=30000 CLIENT_ADDRESS=127.0.0.1:30000 GATEWAY_ADDRESS=127.0.0.1:40000 GATEWAY_PUBLIC_KEY=vnIjsJWZzgq+nS9t3KU7ch5BFhgDkm2U2bm7/2W6eRs= ./dist/client

.PHONY: dev-gateway
dev-gateway: build-gateway ## runs a local gateway
	HTTP_PORT=40000 UDP_PORT=40000 CLIENT_ADDRESS=127.0.0.1:30000 GATEWAY_ADDRESS=127.0.0.1:40000 GATEWAY_PRIVATE_KEY=qmnxBZs2UElVT4SXCdDuX4td+qtPkuXLL5VdOE0vvcA= SERVER_ADDRESS=127.0.0.1:50000 ./dist/gateway

.PHONY: dev-server
dev-server: build-server ## runs a local server
	HTTP_PORT=50000 UDP_PORT=50000 ./dist/server

.PHONY: keygen
keygen: build-keygen ## generate keypair
	./dist/keygen

.PHONY: test
test: ## runs unit tests
	go test ./... -coverprofile ./cover.out -timeout 30s

.PHONY: format
format:
	@$(GOFMT) -s -w .

.PHONY: build-all
build-all: build-client build-gateway build-server ## builds everything

.PHONY: rebuild-all
rebuild-all: clean build-all ## rebuilds everything

.PHONY: clean
clean: ## cleans everything
	@rm -fr $(DIST_DIR)
	@mkdir $(DIST_DIR)
