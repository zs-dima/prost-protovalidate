.PHONY: fmt fmt-check lint test check doc pre-commit publish-dry publish clean \
       conformance-build conformance-harness conformance conformance-verbose

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

lint:
	cargo clippy --all-targets --all-features -- -D warnings
	@command -v cargo-deny >/dev/null 2>&1 && cargo deny check || echo "cargo-deny not installed, skipping (cargo install cargo-deny)"

test:
	cargo test --all-features

check:
	cargo check --all-targets --all-features

doc:
	cargo doc --no-deps --all-features --document-private-items

pre-commit: fmt-check lint test doc
	@echo "All checks passed"

# Publish in dependency order (types first, then main crate)
publish-dry:
	cargo publish --dry-run -p prost-protovalidate-types
	cargo publish --dry-run -p prost-protovalidate

publish:
	cargo publish -p prost-protovalidate-types
	@echo "Waiting for crates.io index to update..."
	@sleep 30
	cargo publish -p prost-protovalidate

# Pinned upstream versions for conformance tooling and schema sync docs.
PROTOVALIDATE_TOOLS_VERSION ?= v1.1.1
PROTOVALIDATE_SCHEMA_REF ?= v1.1.1

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
