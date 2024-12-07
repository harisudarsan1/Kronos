# ------------------------------------------------------------------------------
# Build Variables
# ------------------------------------------------------------------------------
#

KRONOS_IMAGE ?= harisudarsan/kronos
KRONOS_OPERATOR_IMAGE ?= harisudarsan/kronos-operator



# Dockerfile paths for each service
KRONOS_DOCKERFILE ?= build/Containerfile.kronos
KRONOS_OPERATOR_DOCKERFILE ?= build/Containerfile.kronos_operator

# Image URL to use all building/pushing image targets
TAG ?= latest
ifeq ($(shell uname -m),$(filter $(shell uname -m),arm64 aarch64))
BUILD_PLATFORMS ?= linux/arm64
else
BUILD_PLATFORMS ?= linux/amd64
endif


## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/build/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)
	
## Tool Binaries
KUSTOMIZE ?= $(LOCALBIN)/kustomize
ENVTEST ?= $(LOCALBIN)/setup-envtest
KIND ?= $(LOCALBIN)/kind
KTF ?= $(LOCALBIN)/ktf
	
KUSTOMIZE_INSTALL_SCRIPT ?= "https://raw.githubusercontent.com/kubernetes-sigs/kustomize/master/hack/install_kustomize.sh"



# ------------------------------------------------------------------------------
# Build Dependencies
# ------------------------------------------------------------------------------

.PHONY: kustomize
kustomize: $(KUSTOMIZE) ## Download kustomize locally if necessary.
$(KUSTOMIZE): $(LOCALBIN)
	test -s $(LOCALBIN)/kustomize || { curl -s $(KUSTOMIZE_INSTALL_SCRIPT) | bash -s -- $(subst v,,$(KUSTOMIZE_VERSION)) $(LOCALBIN); }

.PHONY: kind
kind: $(KIND)
$(KIND): $(LOCALBIN)
	test -s $(LOCALBIN)/setup-envtest || GOBIN=$(LOCALBIN) go install sigs.k8s.io/kind@$(KIND_VERSION)

.PHONY: ktf
ktf: $(KTF) $(KIND)
$(KTF): $(LOCALBIN)
	test -s $(LOCALBIN)/ktf || GOBIN=$(LOCALBIN) go install github.com/kong/kubernetes-testing-framework/cmd/ktf@latest


# ------------------------------------------------------------------------------
# Build
# ------------------------------------------------------------------------------

.PHONY: all
all: build

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

.PHONY: clean
clean: ## Cargo clean
	cargo clean

.PHONY: build.local.kronos
build.local.kronos:
	@echo "Building Kronos for musl target..."
	RUSTFLAGS=-Ctarget-feature=+crt-static cargo xtask build  --release --target x86_64-unknown-linux-musl
    

.PHONY: build.release
build.release: ## Build kronos
	cargo xtask build-ebpf --release
	cargo build --release

# ------------------------------------------------------------------------------
# Build Images
# ------------------------------------------------------------------------------

.PHONY: build.image.kronos
build.image.kronos:
	DOCKER_BUILDKIT=1 docker buildx build --platform $(BUILD_PLATFORMS) --file=$(KRONOS_DOCKERFILE) -t $(KRONOS_IMAGE):$(TAG) ./
	
.PHONY: build.image.kronos_operator
build.image.kronos_operator:
	DOCKER_BUILDKIT=1 docker buildx build --platform=$(BUILD_PLATFORMS) --file=$(KRONOS_OPERATOR_DOCKERFILE) -t $(KRONOS_OPERATOR_IMAGE):$(TAG) .


.PHONY: build.all.images
build.all.images: 
	$(MAKE) build.image.kronos
	$(MAKE) build.image.kronos_operator


# ------------------------------------------------------------------------------
# Development
# ------------------------------------------------------------------------------

.PHONY: fix.format
fix.format.rust: ## Autofix Rust code formatting
	cargo fmt --manifest-path Cargo.toml --all

.PHONY: check.format
check.format.rust: ## Check Rust code formatting
	cargo fmt --manifest-path Cargo.toml --all -- --check

.PHONY: lint
lint: ## Lint Rust code
	cargo clippy --all -- -D warnings

