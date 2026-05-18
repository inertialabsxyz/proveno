.PHONY: check lint test fix build dev act help

help:
	@echo "Usage: make <target>"
	@echo ""
	@echo "  check          CI gate: lint then test (must pass before merging)"
	@echo "  act            run CI workflow locally via act"
	@echo "  lint           cargo fmt --check + clippy -D warnings"
	@echo "  test           all tests: unit + integration"
	@echo "  test-unit      unit tests only (cargo test --lib)"
	@echo "  test-int       integration tests only (cargo test --tests)"
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

# Auto-fix formatting and apply safe clippy suggestions
fix:
	cargo fmt
	cargo clippy --fix --allow-dirty --allow-staged

build:
	cargo build

# Run CI workflow locally via act
act:
	act
