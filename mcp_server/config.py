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
                "path": {"type": "string", "description": "The file path to read"}
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
                "path": {"type": "string", "description": "The file path to write to"},
                "content": {"type": "string", "description": "The content to write"}
            },
            "required": ["path", "content"]
        }
    },
    "filesystem.delete": {
        "name": "filesystem.delete",
        "description": "Delete a file at the specified path",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "The file path to delete"}
            },
            "required": ["path"]
        }
    },
    "filesystem.list": {
        "name": "filesystem.list",
        "description": "List contents of a directory",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "The directory path to list"}
            },
            "required": ["path"]
        }
    },
    "net.http_get": {
        "name": "net.http_get",
        "description": "Perform an HTTP GET request to the specified URL",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "The URL to fetch"}
            },
            "required": ["url"]
        }
    },
    "net.http_post": {
        "name": "net.http_post",
        "description": "Perform an HTTP POST request with a JSON body",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "The URL to post to"},
                "body": {"type": "object", "description": "The JSON body to send"}
            },
            "required": ["url"]
        }
    },
    "net.dns_lookup": {
        "name": "net.dns_lookup",
        "description": "Perform a DNS lookup for a hostname",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hostname": {"type": "string", "description": "The hostname to resolve"}
            },
            "required": ["hostname"]
        }
    },
    "query_db": {
        "name": "query_db",
        "description": "Run a read-only SQL query against a simulated database",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "The SQL query to execute"}
            },
            "required": ["query"]
        }
    },
    "shell.execute": {
        "name": "shell.execute",
        "description": "Execute a shell command on the server",
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "The shell command to execute"}
            },
            "required": ["command"]
        }
    },
    "email.send": {
        "name": "email.send",
        "description": "Send an email message",
        "inputSchema": {
            "type": "object",
            "properties": {
                "to": {"type": "string", "description": "Recipient email address"},
                "subject": {"type": "string", "description": "Email subject"},
                "body": {"type": "string", "description": "Email body content"}
            },
            "required": ["to"]
        }
    },
    "secrets.get": {
        "name": "secrets.get",
        "description": "Retrieve a secret or credential by name",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "The secret name to retrieve"}
            },
            "required": ["name"]
        }
    },
    "process.list": {
        "name": "process.list",
        "description": "List running processes on the server",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    "env.get": {
        "name": "env.get",
        "description": "Get environment variables",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Optional: specific variable name"}
            },
            "required": []
        }
    },
    "crypto.encode": {
        "name": "crypto.encode",
        "description": "Base64 encode data",
        "inputSchema": {
            "type": "object",
            "properties": {
                "data": {"type": "string", "description": "The data to encode"}
            },
            "required": ["data"]
        }
    }
}
