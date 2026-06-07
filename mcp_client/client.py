#!/usr/bin/env python3
"""
MCProtector PoC - MCP Client
A CLI client for interacting with MCP servers.

Usage:
    python -m mcp_client.client tools list
    python -m mcp_client.client tools call --tool filesystem.read --args '{"path": "/project/readme.txt"}'
    python -m mcp_client.client scenario allowed
    python -m mcp_client.client scenario denied

Examples:
    # List available tools
    python -m mcp_client.client tools list

    # Call a tool (allowed path)
    python -m mcp_client.client tools call --tool filesystem.read --args '{"path": "/project/readme.txt"}'

    # Call a tool (forbidden path - will be denied by MCProtector)
    python -m mcp_client.client tools call --tool filesystem.read --args '{"path": "/etc/passwd"}'

    # Run pre-defined scenarios
    python -m mcp_client.client scenario allowed
    python -m mcp_client.client scenario denied
"""

import argparse
import json
import sys
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from typing import Any, Callable


class MCPClient:
    """MCP Client for communicating with MCP servers."""

    def __init__(
        self,
        server_url: str,
        client_id: str | None = None,
        token: str | None = None,
        forwarded_for: str | None = None,
        target_server: str | None = None,
    ):
        self.server_url = server_url.rstrip('/')
        self.client_id = client_id or f"client-{uuid.uuid4().hex[:8]}"
        self.token = token or f"token-{uuid.uuid4().hex[:16]}"
        self.forwarded_for = forwarded_for or self._default_forwarded_for()
        self.target_server = target_server
        self._request_counter = 0

    @staticmethod
    def _default_forwarded_for() -> str:
        octets = uuid.uuid4().int.to_bytes(16, "big")
        return f"10.{octets[0]}.{octets[1]}.{max(2, octets[2])}"

    def _next_request_id(self) -> int:
        """Generate next request ID."""
        self._request_counter += 1
        return self._request_counter

    def _send_request(self, method: str, params: dict | None = None) -> dict:
        """Send a JSON-RPC request to the MCP server."""
        request_id = self._next_request_id()
        request_data = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params or {}
        }

        headers = {
            "Content-Type": "application/json",
            "X-Client-ID": self.client_id,
            "X-Session-Id": self.client_id,
            "X-Forwarded-For": self.forwarded_for,
            "Authorization": f"Bearer {self.token}"
        }
        if self.target_server:
            headers["X-MCP-Server"] = self.target_server

        request_body = json.dumps(request_data).encode('utf-8')
        req = urllib.request.Request(
            self.server_url,
            data=request_body,
            headers=headers,
            method='POST'
        )

        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                response_body = response.read().decode('utf-8')
                return json.loads(response_body)
        except urllib.error.HTTPError as e:
            error_body = e.read().decode('utf-8')
            try:
                return json.loads(error_body)
            except json.JSONDecodeError:
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {
                        "code": -32000,
                        "message": f"HTTP Error {e.code}: {e.reason}",
                        "data": error_body
                    }
                }
        except urllib.error.URLError as e:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32000,
                    "message": f"Connection error: {str(e.reason)}"
                }
            }

    def initialize(self) -> dict:
        """Initialize connection with MCP server."""
        return self._send_request("initialize", {
            "protocolVersion": "2024-11-05",
            "clientInfo": {
                "name": "MCProtector-PoC-Client",
                "version": "1.0.0"
            },
            "capabilities": {}
        })

    def ping(self) -> dict:
        """Ping the MCP server."""
        return self._send_request("ping")

    def list_tools(self) -> dict:
        """List available tools on the MCP server."""
        return self._send_request("tools/list")

    def call_tool(self, tool_name: str, arguments: dict | None = None) -> dict:
        """Call a tool on the MCP server."""
        return self._send_request("tools/call", {
            "name": tool_name,
            "arguments": arguments or {}
        })


def _response_outcome(response: dict) -> str:
    if "error" in response:
        return "denied"
    result = response.get("result")
    if isinstance(result, dict) and result.get("isError"):
        return "denied"
    return "ok"


def _execute_step(
    *,
    title: str,
    detail: str,
    expected_outcome: str,
    action: Callable[[], dict],
) -> dict[str, Any]:
    response = action()
    actual_outcome = _response_outcome(response)
    return {
        "title": title,
        "detail": detail,
        "expected_outcome": expected_outcome,
        "actual_outcome": actual_outcome,
        "passed": actual_outcome == expected_outcome,
        "response": response,
    }


def run_allowed_scenario(client: MCPClient) -> dict[str, Any]:
    """Run Scenario A: Allowed normal requests."""
    steps = [
        _execute_step(
            title="Step 1",
            detail="Listing available tools.",
            expected_outcome="ok",
            action=client.list_tools,
        ),
        _execute_step(
            title="Step 2",
            detail="Reading file from allowed path '/project/data/config.json'.",
            expected_outcome="ok",
            action=lambda: client.call_tool("filesystem.read", {"path": "/project/data/config.json"}),
        ),
        _execute_step(
            title="Step 3",
            detail="Writing file to allowed path '/project/data/dashboard-scenario.txt'.",
            expected_outcome="ok",
            action=lambda: client.call_tool(
                "filesystem.write",
                {
                    "path": "/project/data/dashboard-scenario.txt",
                    "content": "Dashboard scenario run at " + datetime.now(timezone.utc).isoformat()
                },
            ),
        ),
    ]
    passed = all(step["passed"] for step in steps)
    return {
        "name": "allowed",
        "title": "SCENARIO A: Allowed Request",
        "description": "Normal, policy-compliant requests that should pass through MCProtector.",
        "passed": passed,
        "steps": steps,
        "completed_at": datetime.now(timezone.utc).isoformat(),
    }


def run_denied_scenario(client: MCPClient) -> dict[str, Any]:
    """Run Scenario B: Denied requests that trigger policy rules."""
    steps = [
        _execute_step(
            title="Test 1",
            detail="Attempting to read '/etc/passwd' (forbidden path).",
            expected_outcome="denied",
            action=lambda: client.call_tool("filesystem.read", {"path": "/etc/passwd"}),
        ),
        _execute_step(
            title="Test 2",
            detail="Attempting to call unknown tool 'execute_command'.",
            expected_outcome="denied",
            action=lambda: client.call_tool("execute_command", {"cmd": "whoami"}),
        ),
        _execute_step(
            title="Test 3",
            detail="Calling 'filesystem.read' without required 'path' argument.",
            expected_outcome="denied",
            action=lambda: client.call_tool("filesystem.read", {}),
        ),
        _execute_step(
            title="Test 4",
            detail="Attempting to write to '/root/.bashrc' (forbidden path).",
            expected_outcome="denied",
            action=lambda: client.call_tool(
                "filesystem.write",
                {"path": "/root/.bashrc", "content": "malicious content"},
            ),
        ),
    ]
    passed = all(step["passed"] for step in steps)
    return {
        "name": "denied",
        "title": "SCENARIO B: Denied Request (Policy Violation)",
        "description": "Requests that should be blocked and logged by MCProtector.",
        "passed": passed,
        "steps": steps,
        "completed_at": datetime.now(timezone.utc).isoformat(),
    }


def run_scenario(client: MCPClient, scenario_name: str) -> dict[str, Any]:
    if scenario_name == "allowed":
        return run_allowed_scenario(client)
    if scenario_name == "denied":
        return run_denied_scenario(client)
    raise ValueError(f"Unknown scenario: {scenario_name}")


def print_json(data: Any, title: str | None = None):
    """Pretty print JSON data."""
    if title:
        print(f"\n{'=' * 60}")
        print(f" {title}")
        print(f"{'=' * 60}")
    print(json.dumps(data, indent=2))


def print_result(response: dict, verbose: bool = False):
    """Print MCP response in a readable format."""
    if "error" in response:
        print(f"\n[ERROR] {response['error'].get('message', 'Unknown error')}")
        if verbose:
            print_json(response["error"], "Error Details")
        return False

    if "result" in response:
        result = response["result"]
        if verbose:
            print_json(result, "Result")
        else:
            if "tools" in result:
                print(f"\n[OK] Found {len(result['tools'])} tools:")
                for tool in result["tools"]:
                    print(f"  - {tool['name']}: {tool.get('description', 'No description')}")
            elif "content" in result:
                print(f"\n[OK] Tool execution result:")
                for content in result["content"]:
                    if content.get("type") == "text":
                        print(content["text"])
                if result.get("isError"):
                    print("[Note: Tool returned an error]")
            else:
                print_json(result)
        return True

    print_json(response, "Raw Response")
    return True


def print_scenario_report(result: dict[str, Any], verbose: bool = False) -> bool:
    print("\n" + "=" * 60)
    print(f" {result['title']}")
    print("=" * 60)
    print(f"[*] {result['description']}")
    print()

    for step in result["steps"]:
        print(f"[{step['title']}] {step['detail']}")
        print_result(step["response"], verbose)
        expected = step["expected_outcome"].upper()
        actual = step["actual_outcome"].upper()
        status_label = "PASS" if step["passed"] else "FAIL"
        print(f"[{status_label}] Expected {expected}, got {actual}\n")

    summary_label = "passed" if result["passed"] else "had unexpected results"
    print(f"[*] Scenario {result['name']} completed - {summary_label}")
    return result["passed"]


def cmd_tools_list(client: MCPClient, args):
    """Handle 'tools list' command."""
    print(f"[*] Listing tools from {client.server_url}...")
    response = client.list_tools()
    print_result(response, args.verbose)


def cmd_tools_call(client: MCPClient, args):
    """Handle 'tools call' command."""
    tool_name = args.tool
    try:
        arguments = json.loads(args.args) if args.args else {}
    except json.JSONDecodeError as e:
        print(f"[ERROR] Invalid JSON arguments: {e}")
        sys.exit(1)

    print(f"[*] Calling tool '{tool_name}' with arguments: {arguments}")
    response = client.call_tool(tool_name, arguments)
    print_result(response, args.verbose)


def cmd_scenario_allowed(client: MCPClient, args):
    """Run Scenario A: Allowed normal request."""
    result = run_allowed_scenario(client)
    print_scenario_report(result, args.verbose)


def cmd_scenario_denied(client: MCPClient, args):
    """Run Scenario B: Denied request that triggers policy rules."""
    result = run_denied_scenario(client)
    print_scenario_report(result, args.verbose)


def main():
    parser = argparse.ArgumentParser(
        description='MCProtector PoC MCP Client',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument(
        '--server', '-s',
        default='http://127.0.0.1:8080/mcp/message',
        help='MCP server URL (default:http://127.0.0.1:8080/mcp/message)'
    )
    parser.add_argument(
        '--client-id', '-c',
        default=None,
        help='Client ID for requests'
    )
    parser.add_argument(
        '--target-server',
        help='Named upstream server configured by the proxy (sent as X-MCP-Server)'
    )
    parser.add_argument(
        '--token', '-t',
        default=None,
        help='Authorization token'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Verbose output (show full JSON responses)'
    )

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    tools_parser = subparsers.add_parser('tools', help='Tool operations')
    tools_subparsers = tools_parser.add_subparsers(dest='tools_command')

    tools_subparsers.add_parser('list', help='List available tools')

    tools_call_parser = tools_subparsers.add_parser('call', help='Call a tool')
    tools_call_parser.add_argument('--tool', required=True, help='Tool name to call')
    tools_call_parser.add_argument('--args', default='{}', help='Tool arguments as JSON string')

    scenario_parser = subparsers.add_parser('scenario', help='Run pre-defined test scenarios')
    scenario_subparsers = scenario_parser.add_subparsers(dest='scenario_name')

    scenario_subparsers.add_parser('allowed', help='Scenario A: Normal allowed requests')
    scenario_subparsers.add_parser('denied', help='Scenario B: Requests that trigger policy violations')

    subparsers.add_parser('ping', help='Ping the MCP server')
    subparsers.add_parser('init', help='Initialize connection with MCP server')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    client = MCPClient(args.server, args.client_id, args.token, target_server=args.target_server)

    if args.command == 'tools':
        if args.tools_command == 'list':
            cmd_tools_list(client, args)
        elif args.tools_command == 'call':
            cmd_tools_call(client, args)
        else:
            tools_parser.print_help()
            sys.exit(1)

    elif args.command == 'scenario':
        if args.scenario_name == 'allowed':
            cmd_scenario_allowed(client, args)
        elif args.scenario_name == 'denied':
            cmd_scenario_denied(client, args)
        else:
            scenario_parser.print_help()
            sys.exit(1)

    elif args.command == 'ping':
        print(f"[*] Pinging {client.server_url}...")
        response = client.ping()
        print_result(response, args.verbose)

    elif args.command == 'init':
        print(f"[*] Initializing connection with {client.server_url}...")
        response = client.initialize()
        print_result(response, args.verbose)


if __name__ == '__main__':
    main()
