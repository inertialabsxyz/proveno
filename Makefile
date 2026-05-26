.PHONY: check lint test test-prove fix build dev act help

help:
	@echo "Usage: make <target>"
	@echo ""
	@echo "  check          CI gate: lint then test (must pass before merging)"
	@echo "  act            run CI workflow locally via act"
	@echo "  lint           cargo fmt --check + clippy -D warnings"
	@echo "  test           all tests: unit + integration"
	@echo "  test-unit      unit tests only (cargo test --lib)"
	@echo "  test-int       integration tests only (cargo test --tests)"
	@echo "  test-prove     Noir nargo+bb prove/verify pipeline (slow; pre-PR gate)"
	@echo "  fix            auto-format + apply safe clippy fixes"
	@echo "  build          cargo build"

# CI target — must pass before merging
check: lint test

# Format check + clippy (warnings are errors)
lint:
	cargo fmt --check
	cargo clippy -- -D warnings

# All tests: unit (within modules) + integration (tests/)
test:
	cargo test

# Unit tests only
test-unit:
	cargo test --lib

# Integration tests only
test-integration:
	cargo test --tests

# Noir prove/verify pipeline (nargo execute + bb write_vk/prove/verify).
# Slow (~30 s); not part of `make test`. Required pre-PR gate when touching
# the Noir circuit, witness writer, oracle tape, or related encoders.
# Prints prove/verify wall-time per test so regressions are visible.
# Requires `nargo` and `bb` on PATH.
test-prove:
	cargo test -p luai-noir --test prove -- --nocapture

# Auto-fix formatting and apply safe clippy suggestions
fix:
	cargo fmt
	cargo clippy --fix --allow-dirty --allow-staged

build:
	cargo build

# Run CI workflow locally via act
act:
	act
