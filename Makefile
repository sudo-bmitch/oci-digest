# Copyright the oci-digest contributors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

GOPATH?=$(shell go env GOPATH)
GOFUMPT_VER?=v0.10.0
MARKDOWN_LINT_VER?=v0.22.1
STATICCHECK_VER?=v0.7.0
VER_BUMP?=$(shell command -v version-bump 2>/dev/null)
VER_BUMP_CONTAINER?=sudobmitch/version-bump:edge
ifeq "$(strip $(VER_BUMP))" ''
	VER_BUMP=docker run --rm \
		-v "$(shell pwd)/:$(shell pwd)/" -w "$(shell pwd)" \
		-u "$(shell id -u):$(shell id -g)" \
		$(VER_BUMP_CONTAINER)
endif

.PHONY: all
all: fmt gofumpt gofix goimports vet test lint ## Full test of the package

.PHONY: .FORCE
.FORCE:

.PHONY: fmt
fmt: ## go fmt
	go fmt ./...

.PHONY: gofumpt
gofumpt: $(GOPATH)/bin/gofumpt ## gofumpt is a stricter alternative to go fmt
	gofumpt -l -w .

.PHONY: gofix
gofix: ## go fix
	go fix ./...

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
lint: lint-go lint-goimports lint-md lint-copyright ## Run all linting

.PHONY: lint-copyright
lint-copyright: ## Verify copyright headers in code files
	./scripts/lint-copyright.sh

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

$(GOPATH)/bin/gofumpt: .FORCE
	@[ -f "$(GOPATH)/bin/gofumpt" ] \
	&& [ "$$($(GOPATH)/bin/gofumpt -version | cut -f 1 -d ' ')" = "$(GOFUMPT_VER)" ] \
	|| go install mvdan.cc/gofumpt@$(GOFUMPT_VER)

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
