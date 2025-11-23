GOPATH?=$(shell go env GOPATH)
MARKDOWN_LINT_VER?=v0.19.1
STATICCHECK_VER?=v0.6.1
VER_BUMP?=$(shell command -v version-bump 2>/dev/null)
VER_BUMP_CONTAINER?=sudobmitch/version-bump:edge
ifeq "$(strip $(VER_BUMP))" ''
	VER_BUMP=docker run --rm \
		-v "$(shell pwd)/:$(shell pwd)/" -w "$(shell pwd)" \
		-u "$(shell id -u):$(shell id -g)" \
		$(VER_BUMP_CONTAINER)
endif

.PHONY: all
all: fmt goimports vet test lint ## Full test of the package

.PHONY: .FORCE
.FORCE:

.PHONY: fmt
fmt: ## go fmt
	go fmt ./...

goimports: $(GOPATH)/bin/goimports
	$(GOPATH)/bin/goimports -w -format-only -local github.com/sudo-bmitch/oci-digest .

.PHONY: vet
vet: ## go vet
	go vet ./...

.PHONY: test
test: ## go test
	go test -cover -race ./...

.PHONY: test-benchmark
test-benchmark: go.work ## run benchmark tests
	go test -bench=. -benchmem ./testing/

.PHONY: test-fuzz
test-fuzz: go.work ## run fuzz tests
	go test -fuzz=. -fuzztime=5m ./testing/

.PHONY: lint
lint: lint-go lint-goimports lint-md ## Run all linting

.PHONY: lint-go
lint-go: $(GOPATH)/bin/staticcheck .FORCE ## Run linting for Go
	$(GOPATH)/bin/staticcheck -checks all ./...

lint-goimports: $(GOPATH)/bin/goimports
	@if [ -n "$$($(GOPATH)/bin/goimports -l -format-only -local github.com/sudo-bmitch/oci-digest .)" ]; then \
		echo $(GOPATH)/bin/goimports -d -format-only -local github.com/sudo-bmitch/oci-digest .; \
		$(GOPATH)/bin/goimports -d -format-only -local github.com/sudo-bmitch/oci-digest .; \
		exit 1; \
	fi

.PHONY: lint-md
lint-md: .FORCE ## Run linting for markdown
	docker run --rm -v "$(PWD):/workdir:ro" davidanson/markdownlint-cli2:$(MARKDOWN_LINT_VER) \
	  "**/*.md" "#vendor"

.PHONY: clean
clean:
	[ ! -f go.work ] || rm go.work

go.work:
	go work init . ./testing

$(GOPATH)/bin/goimports: .FORCE
	@[ -f "$(GOPATH)/bin/goimports" ] \
	||	go install golang.org/x/tools/cmd/goimports@latest

$(GOPATH)/bin/staticcheck: .FORCE
	@[ -f $(GOPATH)/bin/staticcheck ] \
	&& [ "$$($(GOPATH)/bin/staticcheck -version | cut -f 3 -d ' ' | tr -d '()')" = "$(STATICCHECK_VER)" ] \
	|| go install "honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VER)"

.PHONY: util-version-check
util-version-check: ## check all dependencies for updates
	$(VER_BUMP) check

.PHONY: util-version-update
util-version-update: ## update versions on all dependencies
	$(VER_BUMP) update

.PHONY: help
help: # Display help
	@awk -F ':|##' '/^[^\t].+?:.*?##/ { printf "\033[36m%-30s\033[0m %s\n", $$1, $$NF }' $(MAKEFILE_LIST)
