#!/usr/bin/env python3
"""
MCProtector PoC - MCP Server
A minimal MCP server implementing JSON-RPC 2.0 over HTTP.

Usage:
    python -m mcp_server.server [--host HOST] [--port PORT]

Example:
    python -m mcp_server.server --port 9000
"""

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .config import DEFAULT_HOST, DEFAULT_PORT, TOOL_DEFINITIONS
from .tools import execute_tool

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class MCPRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for MCP JSON-RPC requests."""

    def _send_json_response(self, data: dict, status_code: int = 200):
        """Send a JSON response."""
        response_body = json.dumps(data, indent=2).encode('utf-8')
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(response_body))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(response_body)

    def _create_jsonrpc_response(self, request_id: Any, result: Any) -> dict:
        """Create a JSON-RPC 2.0 success response."""
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": result
        }

    def _create_jsonrpc_error(self, request_id: Any, code: int, message: str, data: Any = None) -> dict:
        """Create a JSON-RPC 2.0 error response."""
        error = {
            "code": code,
            "message": message
        }
        if data is not None:
            error["data"] = data
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": error
        }

    def do_OPTIONS(self):
        """Handle CORS preflight requests."""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()

    def do_GET(self):
        """Handle GET requests (health check)."""
        if self.path == '/health':
            self._send_json_response({
                "status": "healthy",
                "server": "MCProtector PoC MCP Server",
                "version": "1.0.0",
                "timestamp": datetime.now(timezone.utc).isoformat()
            })
        else:
            self._send_json_response({
                "error": "Use POST for MCP requests"
            }, 405)

    def do_POST(self):
        """Handle POST requests (MCP JSON-RPC)."""
        # Read request body
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length == 0:
            self._send_json_response(
                self._create_jsonrpc_error(None, -32700, "Parse error: empty request body"),
                400
            )
            return

        try:
            request_body = self.rfile.read(content_length)
            request_data = json.loads(request_body.decode('utf-8'))
        except json.JSONDecodeError as e:
            self._send_json_response(
                self._create_jsonrpc_error(None, -32700, f"Parse error: {str(e)}"),
                400
            )
            return

        # Validate JSON-RPC structure
        if not isinstance(request_data, dict):
            self._send_json_response(
                self._create_jsonrpc_error(None, -32600, "Invalid Request: expected object"),
                400
            )
            return

        request_id = request_data.get("id")
        method = request_data.get("method")
        params = request_data.get("params", {})

        # Log incoming request
        client_ip = self.client_address[0]
        logger.info(f"[{client_ip}] MCP Request: method={method}, id={request_id}")

        if not method:
            self._send_json_response(
                self._create_jsonrpc_error(request_id, -32600, "Invalid Request: missing method"),
                400
            )
            return

        # Route to appropriate handler
        try:
            result = self._handle_mcp_method(method, params)
            self._send_json_response(self._create_jsonrpc_response(request_id, result))
            logger.info(f"[{client_ip}] MCP Response: method={method}, success=true")
        except MCPMethodError as e:
            self._send_json_response(
                self._create_jsonrpc_error(request_id, e.code, e.message, e.data),
                400
            )
            logger.warning(f"[{client_ip}] MCP Error: method={method}, error={e.message}")

    def _handle_mcp_method(self, method: str, params: dict) -> dict:
        """Route MCP method to appropriate handler."""
        handlers = {
            "tools/list": self._handle_tools_list,
            "tools/call": self._handle_tools_call,
            "initialize": self._handle_initialize,
            "ping": self._handle_ping
        }

        if method not in handlers:
            raise MCPMethodError(-32601, f"Method not found: {method}")

        return handlers[method](params)

    def _handle_initialize(self, params: dict) -> dict:
        """Handle initialize method."""
        return {
            "protocolVersion": "2024-11-05",
            "serverInfo": {
                "name": "MCProtector-PoC-Server",
                "version": "1.0.0"
            },
            "capabilities": {
                "tools": {}
            }
        }

    def _handle_ping(self, params: dict) -> dict:
        """Handle ping method."""
        return {}

    def _handle_tools_list(self, params: dict) -> dict:
        """Handle tools/list method."""
        tools = list(TOOL_DEFINITIONS.values())
        return {"tools": tools}

    def _handle_tools_call(self, params: dict) -> dict:
        """Handle tools/call method."""
        tool_name = params.get("name")
        arguments = params.get("arguments", {})

        if not tool_name:
            raise MCPMethodError(-32602, "Invalid params: missing 'name'")

        if tool_name not in TOOL_DEFINITIONS:
            raise MCPMethodError(-32602, f"Unknown tool: {tool_name}")

        # Execute the tool
        result = execute_tool(tool_name, arguments)

        # Format response according to MCP spec
        if result.get("ok"):
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(result["result"], indent=2)
                    }
                ]
            }
        else:
            # Return error in content for tool execution failures
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(result["error"], indent=2)
                    }
                ],
                "isError": True
            }

    def log_message(self, format, *args):
        """Override to use our logger."""
        pass  # Suppress default HTTP logging


class MCPMethodError(Exception):
    """Exception for MCP method errors."""
    def __init__(self, code: int, message: str, data: Any = None):
        self.code = code
        self.message = message
        self.data = data
        super().__init__(message)


def run_server(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT):
    """Run the MCP server."""
    server_address = (host, port)
    httpd = ThreadingHTTPServer(server_address, MCPRequestHandler)
    httpd.daemon_threads = True

    logger.info(f"=" * 60)
    logger.info(f"MCProtector PoC - MCP Server")
    logger.info(f"=" * 60)
    logger.info(f"Listening on http://{host}:{port}")
    logger.info(f"Health check: http://{host}:{port}/health")
    logger.info(f"Available tools: {', '.join(TOOL_DEFINITIONS.keys())}")
    logger.info(f"=" * 60)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Server shutting down...")
        httpd.shutdown()


def main():
    parser = argparse.ArgumentParser(description='MCProtector PoC MCP Server')
    parser.add_argument('--host', default=DEFAULT_HOST, help=f'Host to bind to (default: {DEFAULT_HOST})')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT, help=f'Port to bind to (default: {DEFAULT_PORT})')
    args = parser.parse_args()

    run_server(args.host, args.port)


if __name__ == '__main__':
    main()
