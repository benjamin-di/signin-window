.PHONY: bootstrap check lock
bootstrap:
	uv sync --locked
check:
	./scripts/test.sh
	@if [ -f publish/config.toml ] && command -v publish-public >/dev/null 2>&1; then publish-public --check-head .; fi
lock:
	uv lock
