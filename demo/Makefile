# =============================================================================
#  MCProtector PoC — Makefile
#
#  Usage:
#    make poc              # run full end-to-end demo  (default)
#    make replay TRACE=xx  # pretty-print one trace from logs/poc.jsonl
#    make server           # start MCP server only
#    make proxy            # start proxy only  (LOG_MODE=console_json_and_file)
#    make test             # run unit tests
#    make clean            # delete generated log files
# =============================================================================

.DEFAULT_GOAL := poc

LOG_FILE ?= logs/poc.jsonl

# ── Full PoC demo ─────────────────────────────────────────────────────────────
.PHONY: poc
poc:
	@bash demo.sh

# ── Replay a single trace (pass TRACE=<uuid>) ─────────────────────────────────
.PHONY: replay
replay:
ifndef TRACE
	$(error Usage: make replay TRACE=<trace_id>)
endif
	@python3 -m poc_logs --trace $(TRACE) --file $(LOG_FILE)

# ── Start MCP upstream server only ───────────────────────────────────────────
.PHONY: server
server:
	python3 -m mcp_server.server --port 9000

# ── Start proxy only (file logging enabled) ───────────────────────────────────
.PHONY: proxy
proxy:
	LOG_MODE=console_json_and_file \
	python3 -m uvicorn proxy.app:app --host 0.0.0.0 --port 8080 --reload

# ── Run client scenarios individually ────────────────────────────────────────
.PHONY: scenario-a
scenario-a:
	python3 -m mcp_client.client scenario allowed

.PHONY: scenario-b
scenario-b:
	python3 -m mcp_client.client scenario denied

# ── Unit tests ────────────────────────────────────────────────────────────────
.PHONY: test
test:
	pytest tests/ -v

# ── Clean generated log files ─────────────────────────────────────────────────
.PHONY: clean
clean:
	rm -f logs/poc.jsonl logs/proxy.log logs/mcp_server.log
	@echo "Log files removed."

# ── Help ──────────────────────────────────────────────────────────────────────
.PHONY: help
help:
	@echo ""
	@echo "MCProtector PoC — available targets:"
	@echo ""
	@echo "  make poc                   Run full end-to-end demo"
	@echo "  make replay TRACE=<id>     Pretty-print one trace"
	@echo "  make server                Start MCP upstream server (port 9000)"
	@echo "  make proxy                 Start proxy only (port 8080)"
	@echo "  make scenario-a            Run Scenario A (allowed requests)"
	@echo "  make scenario-b            Run Scenario B (denied requests)"
	@echo "  make test                  Run unit tests"
	@echo "  make clean                 Remove generated log files"
	@echo ""
