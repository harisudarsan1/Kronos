.PHONY: build.local.kronos
build.local.kronos:
	@echo "Building Kronos for musl target..."
	RUSTFLAGS=-Ctarget-feature=+crt-static cargo build --workspace --exclude ebpf --release --target x86_64-unknown-linux-musl
