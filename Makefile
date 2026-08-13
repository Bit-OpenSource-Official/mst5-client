.DEFAULT_GOAL := help

ifeq ($(firstword $(MAKECMDGOALS)),release-branch)
RELEASE_POSITIONAL := $(word 2,$(MAKECMDGOALS))
.PHONY: $(RELEASE_POSITIONAL)
$(RELEASE_POSITIONAL):
	@:
endif

RELEASE_VERSION := $(if $(VERSION),$(VERSION),$(RELEASE_POSITIONAL))

.PHONY: help test ffi release-branch

help:
	@echo "make test"
	@echo "make ffi"
	@echo "make release-branch 0.4.0"

test:
	@cargo test --locked --lib
	@cargo test --locked --manifest-path ffi/Cargo.toml

ffi:
	@cargo build --locked --release --manifest-path ffi/Cargo.toml

release-branch:
	@./release-branch.sh "$(RELEASE_VERSION)"
