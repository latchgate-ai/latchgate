.PHONY: fmt fmt-sdk fmt-all check test audit audit-js audit-py ci test-all setup quickstart clean clean-all \
        dev dev-down dev-status dev-clean serve build build-release build-static \
        test-standalone test-integration test-conformance test-opa \
        providers providers-rehash providers-verify \
        test-sdk test-sdk-python test-sdk-typescript test-fixtures \
        test-smoke release-build release-docker release-docker-push release-docker-multiarch \
        squid-allowlist pin-digests \
        fuzz fuzz-build fuzz-smoke

# ── One-time setup ────────────────────────────────────────────────────────────

setup:
	git config core.hooksPath .githooks
	@command -v sccache >/dev/null 2>&1 || { echo "  Installing sccache (compilation cache)..."; cargo install sccache --locked; }
	@echo "  ✓ Setup complete"

# ── Quickstart ───────────────────────────────────────────────────────────────

quickstart:
	@echo ""
	@echo "  LatchGate quickstart"
	@echo ""
	cargo build --locked --bin latchgate
	@echo "  ✓ Binary built"
	cargo run --locked --bin latchgate --quiet -- init --preset dev --non-interactive --force
	@echo "  ✓ Dev config generated (latchgate.toml)"
	$(MAKE) --no-print-directory dev
	@echo "  ✓ Dependencies started (Redis + Prometheus)"
	$(MAKE) --no-print-directory providers
	@echo ""
	@echo "  Ready. Run: make serve"
	@echo "  Prometheus: http://localhost:9090"
	@echo ""

# ── Pre-commit ────────────────────────────────────────────────────────────────

fmt:
	cargo fmt --all
	cargo clippy --workspace --all-targets --fix --allow-dirty --allow-staged -- -D warnings

fmt-sdk:
	@echo "── SDK / Python ──────────────────────────────────────────────────────"
	@command -v uv >/dev/null 2>&1 || { echo "uv not found — see https://docs.astral.sh/uv/"; exit 1; }
	cd $(SDK_PYTHON) && uv sync --quiet && uv run python -m black .
	@echo "── SDK / TypeScript ──────────────────────────────────────────────────"
	@if [ -f sdk/typescript/package.json ]; then \
		cd sdk/typescript && npm run lint:fix; \
	else \
		echo "  TypeScript SDK not yet present, skipping"; \
	fi

fmt-all: fmt fmt-sdk

check:
	cargo fmt --all -- --check
	cargo clippy --locked --workspace --all-targets -- -D warnings

# Fast, no-infrastructure tests: inline crate unit tests (--lib --bins) plus
# the cross-crate standalone invariants. No Docker, no Redis, no OPA. This is
# the loop developers run constantly. WASM conformance is excluded here — it
# needs built provider modules (see test-conformance).
test:
	LATCHGATE_REDIS_URL="redis://:$(REDIS_PASSWORD)@127.0.0.1:6379" \
		cargo test --locked --workspace --lib --bins
	cargo test --locked -p latchgate-tests --test standalone -- --skip wasm_conformance

audit:
	cargo audit
	cargo deny check
	$(MAKE) --no-print-directory audit-freshness
	$(MAKE) --no-print-directory audit-js
	$(MAKE) --no-print-directory audit-py

audit-freshness:
	@bash deploy/audit-freshness.sh

audit-js:
	@echo "── SDK / TypeScript dependency scan ──────────────────────────────────"
	cd sdk/typescript && npx cve-lite-cli . --verbose --fail-on high

audit-py:
	@echo "── SDK / Python dependency scan ──────────────────────────────────────"
	@command -v uv >/dev/null 2>&1 || { echo "uv not found — see https://docs.astral.sh/uv/"; exit 1; }
	cd sdk/python && uv export --no-hashes --frozen -o /tmp/_latchgate_py_reqs.txt \
		&& uvx pip-audit -r /tmp/_latchgate_py_reqs.txt

ci:
	RUSTFLAGS="-Dwarnings" $(MAKE) --no-print-directory check test audit

# Everything, with infrastructure. Brings the dev stack up (Redis + OPA +
# Squid), runs every suite including integration and WASM conformance, then
# tears the stack down. `test` already covers inline + standalone, so it is
# not repeated via test-standalone here.
test-all: dev test test-integration test-conformance test-opa test-sdk
	@$(COMPOSE) --profile dev down 2>/dev/null || true

# ── Dev stack ─────────────────────────────────────────────────────────────────

COMPOSE := docker compose

REDIS_PASSWORD ?= $(or $(LATCHGATE_REDIS_PASSWORD),changeme)

squid-allowlist:
	@mkdir -p deploy/squid
	@printf '# Auto-generated from action manifests. Do not edit.\n' > deploy/squid/allowlist.txt
	@awk '/allowed_domains:/{c=1;next} c&&/^[[:space:]]*- /{sub(/^[[:space:]]*- */,"");gsub(/"/,"");print;next} c{c=0}' \
		definitions/manifests/*.yaml \
		| sed 's/^\*\./\./' \
		| awk '!/^\./{$$0="."$$0} {print tolower($$0)}' \
		| sort -u >> deploy/squid/allowlist.txt
	@echo "  $$(grep -c '^[^#]' deploy/squid/allowlist.txt) domains => deploy/squid/allowlist.txt"


dev: squid-allowlist
	@test -f deploy/squid/squid.conf || { echo "  ✗ deploy/squid/squid.conf not found. Re-copy from repo."; exit 1; }
	LATCHGATE_REDIS_PASSWORD=$(REDIS_PASSWORD) $(COMPOSE) --profile dev up -d --wait

dev-down:
	LATCHGATE_REDIS_PASSWORD=$(REDIS_PASSWORD) $(COMPOSE) --profile dev down

dev-status:
	LATCHGATE_REDIS_PASSWORD=$(REDIS_PASSWORD) $(COMPOSE) --profile dev ps

dev-clean:
	LATCHGATE_REDIS_PASSWORD=$(REDIS_PASSWORD) $(COMPOSE) exec redis redis-cli -a $(REDIS_PASSWORD) --no-auth-warning FLUSHALL
	@echo "Redis flushed. Stale approvals, replay cache, and budget state cleared."

# ── Gate server ──────────────────────────────────────────────────────────────
#
# `make serve` runs the binary in from-source dev-mode. UDS sockets must live
# on a real Linux filesystem — DrvFs/9P mounts (e.g. /mnt/c, /mnt/d under WSL)
# return ENOTSUP on bind. Production defaults (/run/latchgate/*) require root.
# Use a per-user runtime dir on tmpfs: $XDG_RUNTIME_DIR if available, else /tmp.

DEV_USER     := $(or $(USER),$(shell id -un))
DEV_RUN_BASE := $(or $(XDG_RUNTIME_DIR),/tmp)
DEV_RUN_DIR  := $(DEV_RUN_BASE)/latchgate-$(DEV_USER)

DEV_CLIENT_SOCKET := $(DEV_RUN_DIR)/gate.sock
DEV_ADMIN_SOCKET  := $(DEV_RUN_DIR)/gate-admin.sock

serve:
	@printf "  Checking dependencies...\n"
	@redis-cli -h 127.0.0.1 -p 6379 -a $(REDIS_PASSWORD) --no-auth-warning ping \
		| grep -q PONG || { echo "  ✗ Redis not reachable. Run 'make dev' first."; exit 1; }
	@curl -sf http://127.0.0.1:8181/health >/dev/null 2>&1 \
		|| { echo "  ✗ OPA not reachable. Run 'make dev' first."; exit 1; }
	@echo "  ✓ Redis: ok"
	@echo "  ✓ OPA:   ok"
	@mkdir -p $(DEV_RUN_DIR)
	@chmod 700 $(DEV_RUN_DIR)
	@rm -f $(DEV_CLIENT_SOCKET) $(DEV_ADMIN_SOCKET)
	@echo "  ✓ Sockets: $(DEV_RUN_DIR)/"
	@echo ""
	LATCHGATE_DEV_MODE=true \
	LATCHGATE_REDIS_URL="redis://:$(REDIS_PASSWORD)@127.0.0.1:6379" \
	LATCHGATE_OPA_URL="http://127.0.0.1:8181" \
	LATCHGATE_LISTEN_UDS_PATH="$(DEV_CLIENT_SOCKET)" \
	LATCHGATE_LISTEN_ADMIN_UDS_PATH="$(DEV_ADMIN_SOCKET)" \
	LATCHGATE_LISTEN_HTTP_ADDR="127.0.0.1:3000" \
	LATCHGATE_UNSAFE_EXPOSE_HTTP=true \
		cargo run --locked --bin latchgate -- serve

test-smoke:
	@cd sdk/python && uv sync --quiet 2>/dev/null
	@echo ""
	@echo "  LatchGate smoke test"
	@echo ""
	@cd sdk/python && uv run examples/smoke_test.py
	@echo ""

# ── Targeted builds ──────────────────────────────────────────────────────────

build:
	cargo build --locked --workspace

build-release:
	cargo build --locked --workspace --release

MUSL_TARGET := x86_64-unknown-linux-musl
STATIC_BIN  := target/$(MUSL_TARGET)/release/latchgate

build-static:
	@rustup target list --installed | grep -q $(MUSL_TARGET) || \
		{ echo "  Installing musl target..."; rustup target add $(MUSL_TARGET); }
	CARGO_BUILD_TARGET=$(MUSL_TARGET) \
	RUSTFLAGS="-C target-feature=+crt-static" \
		cargo build --locked --release -p latchgate-bin

# Layer 2 filesystem watcher (Linux only, requires CAP_SYS_ADMIN at runtime).
build-fs-watch:
	cargo build --locked --release -p latchgate-bin --features fs-watch

# ── Test suites ──────────────────────────────────────────────────────────────

test-standalone:
	cargo test --locked -p latchgate-tests --test standalone -- --skip wasm_conformance

test-conformance: providers test-fixtures
	cargo test --locked -p latchgate-tests --test standalone wasm_conformance

test-integration: dev test-fixtures
	cargo test --locked -p latchgate-tests --test integration

test-opa:
	docker run --rm -v $(CURDIR)/definitions/policies/opa:/policies:ro \
		openpolicyagent/opa:0.70.0 test /policies -v

# ── WASM provider modules ─────────────────────────────────────────────────────
#
# Provider .wasm bytes are part of the trust chain: the kernel refuses
# to load a module whose SHA-256 doesn't match the manifest. To keep digests
# stable across hosts, every build runs in a pinned container image. Host
# builds are opt-in and not digest-stable.

CARGO_HOME_VAL := $(or $(CARGO_HOME),$(HOME)/.cargo)
WASM_RUSTFLAGS := --remap-path-prefix=$(CARGO_HOME_VAL)=/cargo \
                  --remap-path-prefix=$(CURDIR)=/build

PROVIDERS         := $(shell sed -n '/^members/,/^\]/{ s/.*"\([^"]*\)".*/\1/p }' providers/Cargo.toml)
PROVIDER_WASM_DIR := target/providers
# Digest-pinned image for reproducible WASM provider builds.
# Updated by: make pin-digests (resolves via docker buildx imagetools).
# Ongoing:    Dependabot opens PRs when upstream publishes new digests.
REHASH_IMAGE      := rust:1.93-slim

# Canonical container build, shared by `providers` and `providers-rehash`.
define CANONICAL_PROVIDER_BUILD
	docker run --rm \
		-v "$(CURDIR):/build" \
		-w /build \
		$(REHASH_IMAGE) bash -c '\
			set -euo pipefail && \
			apt-get update -qq && apt-get install -y -qq clang >/dev/null 2>&1 && \
			rustup target add wasm32-wasip2 >/dev/null 2>&1 && \
			mkdir -p $(PROVIDER_WASM_DIR) && \
			RUSTFLAGS="--remap-path-prefix=$$CARGO_HOME=/cargo --remap-path-prefix=/build=/build" \
			cargo build --locked --manifest-path providers/Cargo.toml \
				--workspace --target wasm32-wasip2 --release && \
			for p in $(PROVIDERS); do \
				cp providers/target/wasm32-wasip2/release/latchgate_provider_$${p}.wasm \
					$(PROVIDER_WASM_DIR)/$${p}.wasm; \
			done && \
			echo "  $(words $(PROVIDERS)) provider modules => $(PROVIDER_WASM_DIR)/"'
endef

# Host-toolchain fallback. NOT digest-stable. Never enable in CI/release.
define HOST_PROVIDER_BUILD
	@echo "  ⚠  LATCHGATE_ALLOW_HOST_WASM=1 — host toolchain build, digests will drift"
	@mkdir -p $(PROVIDER_WASM_DIR)
	RUSTFLAGS="$(WASM_RUSTFLAGS)" \
		cargo build --locked --manifest-path providers/Cargo.toml \
			--workspace --target wasm32-wasip2 --release
	@for p in $(PROVIDERS); do \
		cp providers/target/wasm32-wasip2/release/latchgate_provider_$$(echo $$p | tr '-' '_').wasm \
			$(PROVIDER_WASM_DIR)/$$p.wasm; \
	done
	@echo "  $(words $(PROVIDERS)) provider modules => $(PROVIDER_WASM_DIR)/"
endef

# Build + verify. Fails if committed digests don't match produced bytes.
providers:
ifeq ($(LATCHGATE_ALLOW_HOST_WASM),1)
	$(HOST_PROVIDER_BUILD)
else
	@command -v docker >/dev/null 2>&1 || { \
		echo "  ✗ Docker is required to build providers reproducibly."; \
		echo "  ✗ Install Docker, or set LATCHGATE_ALLOW_HOST_WASM=1 (dev-only)."; \
		exit 1; }
	@$(CANONICAL_PROVIDER_BUILD)
endif
	@$(MAKE) --no-print-directory providers-verify

providers-verify:
	@echo "  Verifying manifest digests..."
	@pip install --disable-pip-version-check --quiet pyyaml 2>/dev/null || true
	@python3 deploy/verify-manifest-digests.py \
		--manifests-dir definitions/manifests --providers-dir $(PROVIDER_WASM_DIR)

# Rebuild and rewrite manifest digests. Run only after intentional source
# changes; review + commit the resulting diff.
providers-rehash:
	@$(CANONICAL_PROVIDER_BUILD)
	@pip install --disable-pip-version-check --quiet pyyaml 2>/dev/null || true
	@python3 deploy/rehash-manifest-digests.py \
		--manifests-dir definitions/manifests --providers-dir $(PROVIDER_WASM_DIR)
	@echo ""
	@echo "  Review: git diff definitions/manifests/"

# ── SDK tests ────────────────────────────────────────────────────────────────

SDK_PYTHON := sdk/python

test-sdk: test-sdk-python test-sdk-typescript

test-sdk-python:
	@echo "── SDK / Python ──────────────────────────────────────────────────────"
	@command -v uv >/dev/null 2>&1 || { echo "uv not found — see https://docs.astral.sh/uv/"; exit 1; }
	cd $(SDK_PYTHON) && uv sync --python-preference only-managed && uv run python -m pytest tests/ -v

test-sdk-typescript:
	@if [ -f sdk/typescript/package.json ]; then \
		echo "── SDK / TypeScript ──────────────────────────────────────────────────"; \
		cd sdk/typescript && npm ci --silent && npm test; \
	else \
		echo "── SDK / TypeScript — not yet present, skipping ─────────────────────"; \
	fi

# ── Test fixtures ─────────────────────────────────────────────────────────────

FIXTURE_WASM_DIR := tests/providers/target/wasm32-wasip2/release
FIXTURE_OUT_DIR  := target/test-fixtures

test-fixtures:
	@mkdir -p $(FIXTURE_OUT_DIR)
	RUSTFLAGS="$(WASM_RUSTFLAGS)" \
		cargo build --locked --manifest-path tests/providers/Cargo.toml \
			--workspace --target wasm32-wasip2 --release
	cp $(FIXTURE_WASM_DIR)/latchgate_fixture_memory_hog.wasm \
		$(FIXTURE_OUT_DIR)/fixture_memory_hog.wasm
	cp $(FIXTURE_WASM_DIR)/latchgate_fixture_infinite_loop.wasm \
		$(FIXTURE_OUT_DIR)/fixture_infinite_loop.wasm
	cp $(FIXTURE_WASM_DIR)/latchgate_fixture_evidence_probe.wasm \
		$(FIXTURE_OUT_DIR)/fixture_evidence_probe.wasm
	@echo "  3 WASM fixtures => $(FIXTURE_OUT_DIR)/"

# ── Release build ─────────────────────────────────────────────────────────────

release-build: build-static providers
	@echo ""
	@file $(STATIC_BIN) | grep -qE "statically linked|static-pie linked" && \
		echo "  ✓ Binary is statically linked" || \
		{ echo "  ✗ Binary is NOT statically linked"; exit 1; }
	@echo ""
	@echo "  Release artifacts ready:"
	@echo "    binary:    $(STATIC_BIN)"
	@echo "    providers: $(PROVIDER_WASM_DIR)/ (digests verified)"
	@echo "    manifests: definitions/manifests/"
	@echo ""

# ── Docker release image ─────────────────────────────────────────────────────

REGISTRY := ghcr.io/latchgate-ai/latchgate

release-docker: release-build
ifndef VERSION
	$(error VERSION is required. Usage: make release-docker VERSION=0.1.0)
endif
	docker build \
		--target local-release \
		--build-arg VERSION=$(VERSION) \
		-t $(REGISTRY):v$(VERSION) .
	docker tag $(REGISTRY):v$(VERSION) $(REGISTRY):latest
	@echo ""
	@echo "  ✓ Image built:"
	@echo "    $(REGISTRY):v$(VERSION)"
	@echo "    $(REGISTRY):latest"
	@echo ""
	@echo "  Push:  make release-docker-push VERSION=$(VERSION)"
	@echo ""

release-docker-push:
ifndef VERSION
	$(error VERSION is required. Usage: make release-docker-push VERSION=0.1.0)
endif
	docker push $(REGISTRY):v$(VERSION)
	docker push $(REGISTRY):latest
	@echo "  ✓ Pushed: $(REGISTRY):v$(VERSION) + latest"

# Full in-Docker multi-arch build + push via BuildKit. No host toolchain
# required — the Dockerfile compiles everything from source. Produces both
# amd64 and arm64. Requires: docker login ghcr.io, docker buildx.
release-docker-multiarch:
ifndef VERSION
	$(error VERSION is required. Usage: make release-docker-multiarch VERSION=0.1.0)
endif
	docker buildx create --use --name latchgate-builder 2>/dev/null || true
	docker buildx build \
		--platform linux/amd64,linux/arm64 \
		--target ci-release \
		--build-arg VERSION=$(VERSION) \
		-t $(REGISTRY):v$(VERSION) \
		-t $(REGISTRY):$(VERSION) \
		-t $(REGISTRY):latest \
		--push \
		.
	@echo "  ✓ Multi-arch pushed: $(REGISTRY):v$(VERSION) (amd64 + arm64)"

# ── Supply chain: pin base image digests ──────────────────────────────────

pin-digests:
	@./deploy/pin-digests.sh

# ── Fuzzing ───────────────────────────────────────────────────────────────────

FUZZ_TARGETS := canonical_hash manifest_domain_entry parse_host_from_url \
                path_glob_match ip_classification domain_allowlist_match

fuzz-build:
	cd fuzz && cargo +nightly fuzz build --target x86_64-unknown-linux-gnu

fuzz-smoke: fuzz-build
	@for target in $(FUZZ_TARGETS); do \
		echo "  fuzz  $$target (60s)"; \
		cd $(CURDIR)/fuzz && cargo +nightly fuzz run $$target --target x86_64-unknown-linux-gnu -- -max_total_time=60 || exit 1; \
	done

fuzz: fuzz-build
	@for target in $(FUZZ_TARGETS); do \
		echo "  fuzz  $$target (300s)"; \
		cd $(CURDIR)/fuzz && cargo +nightly fuzz run $$target --target x86_64-unknown-linux-gnu -- -max_total_time=300 || exit 1; \
	done

# ── Cleanup ──────────────────────────────────────────────────────────────────

clean:
	cargo clean

clean-all: clean
	cargo clean --manifest-path providers/Cargo.toml
	cargo clean --manifest-path tests/providers/Cargo.toml
	rm -rf $(PROVIDER_WASM_DIR) $(FIXTURE_OUT_DIR) $(DEV_RUN_DIR)
	@echo "  ✓ All build artifacts removed"
