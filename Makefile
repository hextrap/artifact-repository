check-go: ## Check if the Go toolchain is available
	@which go > /dev/null || (echo "$(RED)Error: Go not found. Please install Go.$(NC)" && exit 1)
	@echo "$(GREEN)[INFO]$(NC) Go found"


# Self-hosted release tarball, as linked from /products/artifact-repository/.
# The name and layout must match ARTIFACT_REPOSITORY_RELEASE in
# hextrap_project/settings/base.py and the page's quick start.
ARTIFACTS_DIR = .
ARTIFACTS_RELEASE_NAME = hextrap-artifacts_$(VERSION)_linux_amd64
ARTIFACTS_RELEASE_DIR = dist/hextrap-artifacts_$(VERSION)
ARTIFACTS_RELEASE_FILES = LICENSE NOTICE README.md config.example.yaml config.full.example.yaml

artifact-repo-release: check-go ## Build the self-hosted Linux x64 release tarball (VERSION=x.y.z)
	@echo "$(VERSION)" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$$' || \
		(echo "$(RED)Error: set VERSION=x.y.z (no leading v)$(NC)" && exit 1)
	@test ! -e "$(ARTIFACTS_DIR)/dist/$(ARTIFACTS_RELEASE_NAME).tar.gz" || \
		(echo "$(RED)Error: $(ARTIFACTS_DIR)/dist/$(ARTIFACTS_RELEASE_NAME).tar.gz already exists; releases are immutable$(NC)" && exit 1)
	@echo "$(GREEN)[INFO]$(NC) Running artifact repository tests"
	@cd $(ARTIFACTS_DIR) && go test ./...
	@echo "$(GREEN)[INFO]$(NC) Building $(ARTIFACTS_RELEASE_NAME)"
	@cd $(ARTIFACTS_DIR) && rm -rf "$(ARTIFACTS_RELEASE_DIR)" && mkdir -p "$(ARTIFACTS_RELEASE_DIR)"
	@cd $(ARTIFACTS_DIR) && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
		-ldflags "-s -w -X main.version=$(VERSION)" \
		-o "$(ARTIFACTS_RELEASE_DIR)/hextrap-artifacts" ./cmd/hextrap-artifacts
	@cd $(ARTIFACTS_DIR) && test "$$($(ARTIFACTS_RELEASE_DIR)/hextrap-artifacts -version)" = "hextrap-artifacts $(VERSION) (self-hosted)" || \
		(echo "$(RED)Error: built binary doesn't report version $(VERSION)$(NC)" && exit 1)
	@cd $(ARTIFACTS_DIR) && cp $(ARTIFACTS_RELEASE_FILES) "$(ARTIFACTS_RELEASE_DIR)/"
	@cd $(ARTIFACTS_DIR) && scripts/third-party-notices.sh "$(ARTIFACTS_RELEASE_DIR)/hextrap-artifacts" > "$(ARTIFACTS_RELEASE_DIR)/THIRD_PARTY_NOTICES"
	@cd $(ARTIFACTS_DIR)/dist && tar --sort=name --owner=0 --group=0 --numeric-owner --mtime='1970-01-01 00:00Z' \
		-czf "$(ARTIFACTS_RELEASE_NAME).tar.gz" "hextrap-artifacts_$(VERSION)"
	@cd $(ARTIFACTS_DIR)/dist && sha256sum "$(ARTIFACTS_RELEASE_NAME).tar.gz" > "$(ARTIFACTS_RELEASE_NAME).tar.gz.sha256"
	@cd $(ARTIFACTS_DIR)/dist && rm -rf "hextrap-artifacts_$(VERSION)"
	@echo "$(GREEN)[SUCCESS]$(NC) $(ARTIFACTS_DIR)/dist/$(ARTIFACTS_RELEASE_NAME).tar.gz (+ .sha256)"
	@echo "Upload both to the GitHub release v$(VERSION), then set ARTIFACT_REPOSITORY_VERSION=$(VERSION) for the website."

