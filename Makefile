# Build pre-compiled static libraries for Go CGO bindings.
#
# Usage:
#   make precompiles          # build all supported platform/arch combos
#   make precompile-linux-amd64  # build a single target
#   make clean-precompiles    # remove all built libs

# ── Target matrix ──────────────────────────────────────────────────
# Maps Go-style os/arch pairs to Rust target triples.
# darwin/riscv64 and windows/riscv64 do not exist as Rust targets.

TARGETS := \
	darwin-amd64:x86_64-apple-darwin \
	darwin-arm64:aarch64-apple-darwin \
	linux-amd64:x86_64-unknown-linux-gnu \
	linux-arm64:aarch64-unknown-linux-gnu \
	linux-riscv64:riscv64gc-unknown-linux-gnu \
	windows-amd64:x86_64-pc-windows-gnu \
	windows-arm64:aarch64-pc-windows-gnullvm

GO_LIB_DIR := go/ntt/lib

# ── Phony targets ──────────────────────────────────────────────────

.PHONY: precompiles clean-precompiles $(foreach t,$(TARGETS),precompile-$(word 1,$(subst :, ,$t)))

precompiles:
	@for entry in $(TARGETS); do \
		pair=$${entry%%:*}; \
		triple=$${entry##*:}; \
		os=$${pair%%-*}; \
		arch=$${pair##*-}; \
		outdir=$(GO_LIB_DIR)/$${os}_$${arch}; \
		echo "── building $$pair ($$triple)"; \
		rustup target add $$triple 2>/dev/null; \
		cargo build --release --target $$triple || { echo "FAILED: $$triple"; continue; }; \
		mkdir -p $$outdir; \
		src=target/$$triple/release/libeth_ntt.a; \
		if [ "$$os" = "windows" ]; then src=target/$$triple/release/libeth_ntt.a; fi; \
		if [ -f "$$src" ]; then \
			rust-strip --strip-debug "$$src" 2>/dev/null || strip -S -x "$$src" 2>/dev/null || true; \
			cp "$$src" $$outdir/libeth_ntt.a; \
			echo "  -> $$outdir/libeth_ntt.a ($$(du -h $$outdir/libeth_ntt.a | cut -f1))"; \
		else \
			echo "  !! $$src not found"; \
		fi; \
	done
	@echo "done."

# Single-target convenience: make precompile-linux-amd64
precompile-%:
	@pair=$*; \
	triple=$$(echo "$(TARGETS)" | tr ' ' '\n' | grep "^$$pair:" | cut -d: -f2); \
	if [ -z "$$triple" ]; then echo "unknown target: $$pair"; exit 1; fi; \
	os=$${pair%%-*}; \
	arch=$${pair##*-}; \
	outdir=$(GO_LIB_DIR)/$${os}_$${arch}; \
	echo "── building $$pair ($$triple)"; \
	rustup target add $$triple 2>/dev/null; \
	cargo build --release --target $$triple; \
	mkdir -p $$outdir; \
	src=target/$$triple/release/libeth_ntt.a; \
	rust-strip --strip-debug "$$src" 2>/dev/null || strip -S -x "$$src" 2>/dev/null || true; \
	cp "$$src" $$outdir/libeth_ntt.a; \
	echo "  -> $$outdir/libeth_ntt.a ($$(du -h $$outdir/libeth_ntt.a | cut -f1))"

clean-precompiles:
	rm -rf $(GO_LIB_DIR)/*/libeth_ntt.a
