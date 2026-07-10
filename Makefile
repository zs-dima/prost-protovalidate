.PHONY: fmt fmt-check lint test test-no-cel bench check doc doc-all pre-commit publish-dry publish clean \
       conformance-build conformance-harness conformance conformance-verbose \
       sync-schema sync-schema-check

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

lint:
	cargo clippy --all-targets --all-features -- -D warnings
	cargo clippy --all-targets -p prost-protovalidate --no-default-features -- -D warnings
	cargo clippy --all-targets -p prost-protovalidate --no-default-features --features reflect -- -D warnings
	cargo clippy --all-targets -p prost-protovalidate --no-default-features --features tonic -- -D warnings
	cargo deny check

test:
	cargo test --all-features

test-no-cel:
	cargo test -p prost-protovalidate --no-default-features
	cargo test -p prost-protovalidate --no-default-features --features reflect
	cargo test -p prost-protovalidate-tests --no-default-features
	cargo test -p prost-protovalidate --no-default-features --features tonic

bench:
	cargo bench --all-features -p prost-protovalidate

check:
	cargo check --all-targets --all-features

doc:
	RUSTDOCFLAGS=-Dwarnings cargo doc --no-deps --all-features

doc-all:
	cargo doc --no-deps --all-features --document-private-items

pre-commit: fmt-check lint test test-no-cel doc
	@echo "All checks passed"

# Workspace publish (cargo >= 1.90). Cargo topologically sorts publishable
# crates and treats internal workspace siblings as virtually published during
# verification, so dry-run works correctly even on a bumped workspace.
publish-dry:
	cargo publish --workspace --dry-run

publish:
	cargo publish --workspace

# Pinned upstream version for the conformance tools and the buf.validate schema. Bump together unless a deliberate split is required.
PROTOVALIDATE_TOOLS_VERSION ?= v1.2.2
PROTOVALIDATE_SCHEMA_REF ?= v1.2.2

SCHEMA_DEST = crates/prost-protovalidate-types/proto/buf/validate/validate.proto
SCHEMA_URL  = https://raw.githubusercontent.com/bufbuild/protovalidate/$(PROTOVALIDATE_SCHEMA_REF)/proto/protovalidate/buf/validate/validate.proto

# Re-vendor validate.proto from the pinned upstream tag.
# Override the ref ad-hoc: `make sync-schema PROTOVALIDATE_SCHEMA_REF=v1.2.0`.
sync-schema:
	curl -fsSL "$(SCHEMA_URL)" -o "$(SCHEMA_DEST)"

# Used by CI: re-vendor into a temp file and fail if it differs from the
# committed copy. Does not touch the working tree.
sync-schema-check:
	@tmp="$$(mktemp)"; \
	curl -fsSL "$(SCHEMA_URL)" -o "$$tmp"; \
	diff -u "$(SCHEMA_DEST)" "$$tmp" || { rm -f "$$tmp"; echo "drift: $(SCHEMA_DEST) is out of sync with $(PROTOVALIDATE_SCHEMA_REF)"; exit 1; }; \
	rm -f "$$tmp"

# Conformance tests use a pinned upstream protovalidate harness binary.
CONFORMANCE_HARNESS = target/protovalidate-conformance$(shell go env GOEXE)
CONFORMANCE_EXECUTOR = target/release/prost-protovalidate-conformance
EXPECTED_FAILURES = crates/prost-protovalidate-conformance/expected_failures.yaml

ifeq ($(OS),Windows_NT)
GO_INSTALL_CONFORMANCE = set "GOBIN=$(abspath target)" && go install github.com/bufbuild/protovalidate/tools/protovalidate-conformance@$(PROTOVALIDATE_TOOLS_VERSION)
else
GO_INSTALL_CONFORMANCE = GOBIN=$(abspath target) go install github.com/bufbuild/protovalidate/tools/protovalidate-conformance@$(PROTOVALIDATE_TOOLS_VERSION)
endif

conformance-build:
	cargo build --release -p prost-protovalidate-conformance

conformance-harness:
	$(GO_INSTALL_CONFORMANCE)

conformance: conformance-build conformance-harness
	$(CONFORMANCE_HARNESS) --expected_failures $(EXPECTED_FAILURES) $(CONFORMANCE_EXECUTOR)

conformance-verbose: conformance-build conformance-harness
	$(CONFORMANCE_HARNESS) --expected_failures $(EXPECTED_FAILURES) -v $(CONFORMANCE_EXECUTOR)

clean:
	cargo clean
