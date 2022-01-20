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

.PHONY: build-gateway
build-gateway: dist
	@printf "Building gateway... "
	@$(GO) build -o ${DIST_DIR}/gateway ./cmd/gateway/gateway.go
	@printf "done\n"

.PHONY: build-client
build-client: dist
	@printf "Building client... "
	@$(GO) build -o ${DIST_DIR}/client ./cmd/client/client.go
	@printf "done\n"

.PHONY: dev-gateway
dev-gateway: build-gateway ## runs a local gateway
	@HTTP_PORT=40000 UDP_PORT=40000 ./dist/gateway

.PHONY: dev-client
dev-client: build-client ## runs a local client
	UDP_PORT=30000 SERVER_ADDRESS=127.0.0.1:40000 ./dist/client

.PHONY: format
format:
	@$(GOFMT) -s -w .

.PHONY: build-all
build-all: build-gateway ## builds everything

.PHONY: rebuild-all
rebuild-all: clean build-all ## rebuilds everything

.PHONY: clean
clean: ## cleans everything
	@rm -fr $(DIST_DIR)
	@mkdir $(DIST_DIR)
