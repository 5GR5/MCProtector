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


def handle_filesystem_delete(arguments: dict[str, Any]) -> dict[str, Any]:
    """
    Handle filesystem.delete tool invocation.
    Simulates file deletion (dangerous operation for security testing).
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

    allowed, error_msg = _is_path_allowed(path)
    if not allowed:
        return {
            "ok": False,
            "error": {
                "code": "ACCESS_DENIED",
                "message": error_msg
            }
        }

    return {
        "ok": True,
        "result": {
            "path": path,
            "message": f"Successfully deleted {path}"
        }
    }


def handle_filesystem_list(arguments: dict[str, Any]) -> dict[str, Any]:
    """
    Handle filesystem.list tool invocation.
    Lists directory contents from simulated filesystem.
    """
    path = arguments.get("path", "/")

    allowed, error_msg = _is_path_allowed(path)
    if not allowed:
        return {
            "ok": False,
            "error": {
                "code": "ACCESS_DENIED",
                "message": error_msg
            }
        }

    # Find files that match the directory
    entries = []
    for file_path in SIMULATED_FILESYSTEM.keys():
        if file_path.startswith(path.rstrip("/") + "/"):
            relative = file_path[len(path.rstrip("/")) + 1:]
            # Get first component (immediate child)
            first_part = relative.split("/")[0]
            if first_part not in entries:
                entries.append(first_part)

    return {
        "ok": True,
        "result": {
            "path": path,
            "entries": entries,
            "count": len(entries)
        }
    }


def handle_shell_execute(arguments: dict[str, Any]) -> dict[str, Any]:
    """
    Handle shell.execute tool invocation.
    DANGEROUS: Simulates shell command execution for security testing.
    """
    command = arguments.get("command")

    if not command:
        return {
            "ok": False,
            "error": {
                "code": "MISSING_ARGUMENT",
                "message": "Required argument 'command' is missing"
            }
        }

    # Stubbed responses for common commands
    stubbed = {
        "whoami": "mcprotector-user",
        "pwd": "/home/mcprotector",
        "id": "uid=1000(mcprotector-user) gid=1000(mcprotector) groups=1000(mcprotector)",
        "uname -a": "Linux mcprotector-host 5.15.0 #1 SMP x86_64 GNU/Linux",
        "hostname": "mcprotector-host",
        "date": "Sat May 24 12:00:00 UTC 2026",
        "ls": "config.json\ndata\nlogs\nREADME.md",
        "env": "PATH=/usr/local/bin:/usr/bin\nHOME=/home/mcprotector\nUSER=mcprotector-user",
    }

    if command in stubbed:
        return {
            "ok": True,
            "result": {
                "command": command,
                "exit_code": 0,
                "stdout": stubbed[command],
                "stderr": ""
            }
        }

    return {
        "ok": True,
        "result": {
            "command": command,
            "exit_code": 0,
            "stdout": f"[simulated output for: {command}]",
            "stderr": ""
        }
    }


def handle_net_http_post(arguments: dict[str, Any]) -> dict[str, Any]:
    """
    Handle net.http_post tool invocation.
    Simulates HTTP POST requests (potential data exfiltration).
    """
    url = arguments.get("url")
    body = arguments.get("body", {})

    if not url:
        return {
            "ok": False,
            "error": {
                "code": "MISSING_ARGUMENT",
                "message": "Required argument 'url' is missing"
            }
        }

    return {
        "ok": True,
        "result": {
            "url": url,
            "method": "POST",
            "status_code": 200,
            "body_sent_bytes": len(str(body)),
            "response": {"message": "Stubbed POST response", "accepted": True}
        }
    }


def handle_email_send(arguments: dict[str, Any]) -> dict[str, Any]:
    """
    Handle email.send tool invocation.
    Simulates sending email (data exfiltration vector).
    """
    to = arguments.get("to")
    subject = arguments.get("subject", "")
    body = arguments.get("body", "")

    if not to:
        return {
            "ok": False,
            "error": {
                "code": "MISSING_ARGUMENT",
                "message": "Required argument 'to' is missing"
            }
        }

    return {
        "ok": True,
        "result": {
            "to": to,
            "subject": subject,
            "body_length": len(body),
            "message_id": "msg-12345-simulated",
            "status": "sent"
        }
    }


def handle_secrets_get(arguments: dict[str, Any]) -> dict[str, Any]:
    """
    Handle secrets.get tool invocation.
    Simulates fetching secrets/credentials (sensitive operation).
    """
    secret_name = arguments.get("name")

    if not secret_name:
        return {
            "ok": False,
            "error": {
                "code": "MISSING_ARGUMENT",
                "message": "Required argument 'name' is missing"
            }
        }

    # Simulated secrets store
    secrets = {
        "api_key": "sk-demo-xxxx-redacted",
        "db_password": "***REDACTED***",
        "jwt_secret": "***REDACTED***",
    }

    if secret_name in secrets:
        return {
            "ok": True,
            "result": {
                "name": secret_name,
                "value": secrets[secret_name],
                "version": "v1"
            }
        }

    return {
        "ok": False,
        "error": {
            "code": "SECRET_NOT_FOUND",
            "message": f"Secret '{secret_name}' not found"
        }
    }


def handle_process_list(arguments: dict[str, Any]) -> dict[str, Any]:
    """
    Handle process.list tool invocation.
    Lists running processes (reconnaissance).
    """
    return {
        "ok": True,
        "result": {
            "processes": [
                {"pid": 1, "name": "systemd", "user": "root"},
                {"pid": 100, "name": "python3", "user": "mcprotector-user"},
                {"pid": 101, "name": "uvicorn", "user": "mcprotector-user"},
                {"pid": 102, "name": "node", "user": "mcprotector-user"},
            ],
            "count": 4
        }
    }


def handle_env_get(arguments: dict[str, Any]) -> dict[str, Any]:
    """
    Handle env.get tool invocation.
    Gets environment variables (potential credential exposure).
    """
    var_name = arguments.get("name")

    env_vars = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": "/home/mcprotector",
        "USER": "mcprotector-user",
        "AWS_REGION": "us-east-1",
        "DATABASE_URL": "postgres://***:***@localhost/db",
    }

    if var_name:
        if var_name in env_vars:
            return {
                "ok": True,
                "result": {"name": var_name, "value": env_vars[var_name]}
            }
        return {
            "ok": False,
            "error": {"code": "NOT_FOUND", "message": f"Variable '{var_name}' not set"}
        }

    # Return all if no name specified
    return {
        "ok": True,
        "result": {"variables": env_vars, "count": len(env_vars)}
    }


def handle_crypto_encode(arguments: dict[str, Any]) -> dict[str, Any]:
    """
    Handle crypto.encode tool invocation.
    Base64 encodes data (obfuscation for exfiltration).
    """
    import base64
    data = arguments.get("data", "")

    if not data:
        return {
            "ok": False,
            "error": {"code": "MISSING_ARGUMENT", "message": "Required argument 'data' is missing"}
        }

    encoded = base64.b64encode(data.encode()).decode()
    return {
        "ok": True,
        "result": {
            "original_length": len(data),
            "encoded": encoded,
            "encoding": "base64"
        }
    }


def handle_net_dns_lookup(arguments: dict[str, Any]) -> dict[str, Any]:
    """
    Handle net.dns_lookup tool invocation.
    Simulates DNS lookups (reconnaissance).
    """
    hostname = arguments.get("hostname")

    if not hostname:
        return {
            "ok": False,
            "error": {"code": "MISSING_ARGUMENT", "message": "Required argument 'hostname' is missing"}
        }

    # Stubbed DNS responses
    dns_records = {
        "example.com": {"A": ["93.184.216.34"], "AAAA": ["2606:2800:220:1:248:1893:25c8:1946"]},
        "api.example.com": {"A": ["93.184.216.35"], "CNAME": ["api-lb.example.com"]},
        "localhost": {"A": ["127.0.0.1"]},
    }

    if hostname in dns_records:
        return {"ok": True, "result": {"hostname": hostname, "records": dns_records[hostname]}}

    return {"ok": True, "result": {"hostname": hostname, "records": {"A": ["10.0.0.1"]}}}


# Tool handler registry
TOOL_HANDLERS = {
    "filesystem.read": handle_filesystem_read,
    "filesystem.write": handle_filesystem_write,
    "filesystem.delete": handle_filesystem_delete,
    "filesystem.list": handle_filesystem_list,
    "net.http_get": handle_net_http_get,
    "net.http_post": handle_net_http_post,
    "net.dns_lookup": handle_net_dns_lookup,
    "query_db": handle_query_db,
    "shell.execute": handle_shell_execute,
    "email.send": handle_email_send,
    "secrets.get": handle_secrets_get,
    "process.list": handle_process_list,
    "env.get": handle_env_get,
    "crypto.encode": handle_crypto_encode,
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
