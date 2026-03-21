"""
MCProtector PoC - MCP Server Configuration
"""

# Server settings
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9000

# Allowed paths for filesystem operations (for security policy demo)
ALLOWED_PATHS = [
    "/project/",
    "/data/",
    "/tmp/mcprotector/"
]

# Forbidden paths (will trigger policy violations)
FORBIDDEN_PATHS = [
    "/etc/",
    "/root/",
    "/home/",
    "/.ssh/",
    "/var/log/"
]

# Tool definitions with schemas
TOOL_DEFINITIONS = {
    "filesystem.read": {
        "name": "filesystem.read",
        "description": "Read contents of a file at the specified path",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "The file path to read"
                }
            },
            "required": ["path"]
        }
    },
    "filesystem.write": {
        "name": "filesystem.write",
        "description": "Write content to a file at the specified path",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "The file path to write to"
                },
                "content": {
                    "type": "string",
                    "description": "The content to write"
                }
            },
            "required": ["path", "content"]
        }
    },
    "net.http_get": {
        "name": "net.http_get",
        "description": "Perform an HTTP GET request to the specified URL (stubbed)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "The URL to fetch"
                }
            },
            "required": ["url"]
        }
    }
}
