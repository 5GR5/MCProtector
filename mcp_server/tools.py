"""
MCProtector PoC - MCP Tool Implementations
Deterministic tool handlers for the PoC MCP server.
"""

from typing import Any
from .config import ALLOWED_PATHS, FORBIDDEN_PATHS

# Simulated filesystem for deterministic responses
SIMULATED_FILESYSTEM = {
    "/project/readme.txt": "Welcome to MCProtector PoC!\nThis is a test file.",
    "/project/data/config.json": '{"version": "1.0", "name": "MCProtector"}',
    "/data/sample.txt": "Sample data content for testing.",
    "/tmp/mcprotector/test.log": "2026-01-05 10:00:00 - System started"
}

SIMULATED_TABLES = {
    "users": [
        {"id": 1, "username": "alice", "role": "admin"},
        {"id": 2, "username": "bob", "role": "analyst"},
    ],
    "orders": [
        {"id": 101, "status": "open", "total": 42.5},
        {"id": 102, "status": "closed", "total": 18.0},
    ],
}


def _is_path_allowed(path: str) -> tuple[bool, str]:
    """Check if a path is allowed based on security policy."""
    # Check forbidden paths first
    for forbidden in FORBIDDEN_PATHS:
        if path.startswith(forbidden):
            return False, f"Access denied: path '{path}' is in forbidden zone"

    # Check if path is in allowed paths
    for allowed in ALLOWED_PATHS:
        if path.startswith(allowed):
            return True, ""

    return False, f"Access denied: path '{path}' is not in allowed directories"


def handle_filesystem_read(arguments: dict[str, Any]) -> dict[str, Any]:
    """
    Handle filesystem.read tool invocation.
    Returns deterministic content from simulated filesystem.
    """
    path = arguments.get("path")

    if not path:
        return {
            "ok": False,
            "error": {
                "code": "MISSING_ARGUMENT",
                "message": "Required argument 'path' is missing"
            }
        }

    # Check path security
    allowed, error_msg = _is_path_allowed(path)
    if not allowed:
        return {
            "ok": False,
            "error": {
                "code": "ACCESS_DENIED",
                "message": error_msg
            }
        }

    # Check if file exists in simulated filesystem
    if path in SIMULATED_FILESYSTEM:
        return {
            "ok": True,
            "result": {
                "path": path,
                "content": SIMULATED_FILESYSTEM[path],
                "size": len(SIMULATED_FILESYSTEM[path])
            }
        }

    return {
        "ok": False,
        "error": {
            "code": "FILE_NOT_FOUND",
            "message": f"File not found: {path}"
        }
    }


def handle_filesystem_write(arguments: dict[str, Any]) -> dict[str, Any]:
    """
    Handle filesystem.write tool invocation.
    Simulates writing to filesystem (deterministic, no actual writes).
    """
    path = arguments.get("path")
    content = arguments.get("content")

    if not path:
        return {
            "ok": False,
            "error": {
                "code": "MISSING_ARGUMENT",
                "message": "Required argument 'path' is missing"
            }
        }

    if content is None:
        return {
            "ok": False,
            "error": {
                "code": "MISSING_ARGUMENT",
                "message": "Required argument 'content' is missing"
            }
        }

    # Check path security
    allowed, error_msg = _is_path_allowed(path)
    if not allowed:
        return {
            "ok": False,
            "error": {
                "code": "ACCESS_DENIED",
                "message": error_msg
            }
        }

    # Simulate successful write (deterministic response)
    return {
        "ok": True,
        "result": {
            "path": path,
            "bytes_written": len(content),
            "message": f"Successfully wrote {len(content)} bytes to {path}"
        }
    }


def handle_net_http_get(arguments: dict[str, Any]) -> dict[str, Any]:
    """
    Handle net.http_get tool invocation.
    Returns stubbed/deterministic HTTP response.
    """
    url = arguments.get("url")

    if not url:
        return {
            "ok": False,
            "error": {
                "code": "MISSING_ARGUMENT",
                "message": "Required argument 'url' is missing"
            }
        }

    # Stubbed responses for deterministic behavior
    stubbed_responses = {
        "https://api.example.com/status": {
            "status_code": 200,
            "body": {"status": "healthy", "version": "1.0.0"}
        },
        "https://api.example.com/data": {
            "status_code": 200,
            "body": {"items": ["item1", "item2", "item3"]}
        }
    }

    if url in stubbed_responses:
        return {
            "ok": True,
            "result": {
                "url": url,
                "status_code": stubbed_responses[url]["status_code"],
                "body": stubbed_responses[url]["body"]
            }
        }

    # Default stubbed response for unknown URLs
    return {
        "ok": True,
        "result": {
            "url": url,
            "status_code": 200,
            "body": {"message": "Stubbed response", "requested_url": url}
        }
    }


def handle_query_db(arguments: dict[str, Any]) -> dict[str, Any]:
    """
    Handle query_db tool invocation.
    Simulates a tiny read-only SQL server for proxy policy testing.
    """
    query = arguments.get("query")

    if not query:
        return {
            "ok": False,
            "error": {
                "code": "MISSING_ARGUMENT",
                "message": "Required argument 'query' is missing"
            }
        }

    normalized = " ".join(query.lower().strip().split())
    if normalized == "select id, username, role from users":
        return {
            "ok": True,
            "result": {
                "query": query,
                "rows": SIMULATED_TABLES["users"],
                "row_count": len(SIMULATED_TABLES["users"]),
            }
        }

    if normalized == "select id, status, total from orders":
        return {
            "ok": True,
            "result": {
                "query": query,
                "rows": SIMULATED_TABLES["orders"],
                "row_count": len(SIMULATED_TABLES["orders"]),
            }
        }

    return {
        "ok": False,
        "error": {
            "code": "QUERY_NOT_ALLOWED",
            "message": "Only predefined read-only demo queries are available"
        }
    }


# Tool handler registry
TOOL_HANDLERS = {
    "filesystem.read": handle_filesystem_read,
    "filesystem.write": handle_filesystem_write,
    "net.http_get": handle_net_http_get,
    "query_db": handle_query_db
}


def execute_tool(tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """
    Execute a tool by name with given arguments.
    Returns deterministic response structure.
    """
    if tool_name not in TOOL_HANDLERS:
        return {
            "ok": False,
            "error": {
                "code": "UNKNOWN_TOOL",
                "message": f"Tool '{tool_name}' is not registered"
            }
        }

    handler = TOOL_HANDLERS[tool_name]
    return handler(arguments)
