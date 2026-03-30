# =============================================================================
#  MCProtector PoC — root Makefile
#  Run from the project root: make poc
# =============================================================================

.DEFAULT_GOAL := poc

LOG_FILE ?= logs/poc.jsonl

.PHONY: poc
poc:
	@bash demo/demo.sh

.PHONY: replay
replay:
ifndef TRACE
	$(error Usage: make replay TRACE=<trace_id>)
endif
	@python3 -m poc_logs --trace $(TRACE) --file $(LOG_FILE)

.PHONY: server
server:
	python3 -m mcp_server.server --port 9000

.PHONY: proxy
proxy:
	LOG_MODE=console_json_and_file \
	python3 -m uvicorn proxy.app:app --host 0.0.0.0 --port 8080 --reload

.PHONY: scenario-a
scenario-a:
	python3 -m mcp_client.client scenario allowed

.PHONY: scenario-b
scenario-b:
	python3 -m mcp_client.client scenario denied

.PHONY: test
test:
	pytest tests/ -v

.PHONY: clean
clean:
	rm -f logs/poc.jsonl logs/proxy.log logs/mcp_server.log
	@echo "Log files removed."

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
