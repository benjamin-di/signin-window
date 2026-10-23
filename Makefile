.PHONY: bootstrap check lock
bootstrap:
	uv sync --locked
check:
	./scripts/test.sh
lock:
	uv lock
