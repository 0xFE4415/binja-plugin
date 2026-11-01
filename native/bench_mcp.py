#!/usr/bin/env python3
"""Live benchmark: the native Rust rx_* MCP tools vs the Python rex_* tools.

Prerequisites: Binary Ninja restarted once after `native/scripts/install.sh`, so
both the Rust plugin and the Python plugin are loaded, with the benchmark
database open and an MCP server on 127.0.0.1:24642.

The server runs tool handlers serially and cannot cancel them; every call here
is bounded by a client-side timeout instead.

Stdlib only (urllib) so it runs anywhere the GUI runs.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
import urllib.error
import urllib.request

DEFAULT_URL = "http://127.0.0.1:24642/mcp"
# The benchmark database's handle, as shown by bn_binary_list. Every
# binary-scoped tool call on this server requires it. There is no static
# default: handles change on every restart, so a stale one would silently
# benchmark the wrong view (or fail). Pass --binary.
DEFAULT_BINARY = None
# Server-side handlers cannot be cancelled; keep every call well under the
# ~30 s single-call budget stated for this server.
CALL_TIMEOUT = 30.0

DEFAULT_PATTERNS = [
    "48 8b 05",
    "48 8b ?? 05",
    "e8 ?? ?? ?? ??",
    "0f 1f 44 00 00",
    "48 89 ?? 24 ??",
    "4c 8b ?? ??",
    "cc cc cc cc",
    "48 83 ?? ??",
]


class McpError(RuntimeError):
    pass


class McpClient:
    """Minimal MCP streamable-HTTP client: initialize once, tools/call many."""

    def __init__(self, url: str) -> None:
        self.url = url
        self.session: str | None = None
        self.next_id = 1

    def _post(self, payload: dict, timeout: float) -> dict:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self.session:
            headers["MCP-Session-Id"] = self.session
        request = urllib.request.Request(
            self.url, data=json.dumps(payload).encode(), headers=headers
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            self.session = response.headers.get("MCP-Session-Id") or self.session
            body = response.read().decode()
        body = body.strip()
        if not body:
            # Notifications (and 202 responses) carry no JSON-RPC payload.
            return {}
        if body.startswith("{"):
            return json.loads(body)
        # SSE framing: take the first data line that parses as JSON.
        for line in body.splitlines():
            if line.startswith("data:"):
                return json.loads(line[5:].strip())
        raise McpError(f"unparseable response body: {body[:200]!r}")

    def initialize(self) -> None:
        message = self._post(
            {
                "jsonrpc": "2.0",
                "id": self._id(),
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "rx-bench", "version": "0.1.0"},
                },
            },
            timeout=CALL_TIMEOUT,
        )
        if "error" in message:
            raise McpError(f"initialize failed: {message['error']}")
        self._post(
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            timeout=CALL_TIMEOUT,
        )

    def _id(self) -> int:
        value = self.next_id
        self.next_id += 1
        return value

    def list_tools(self) -> list[str]:
        message = self._post(
            {
                "jsonrpc": "2.0",
                "id": self._id(),
                "method": "tools/list",
                "params": {},
            },
            timeout=CALL_TIMEOUT,
        )
        if "error" in message:
            raise McpError(f"tools/list failed: {message['error']}")
        return [tool["name"] for tool in message["result"]["tools"]]

    def call_tool(self, name: str, arguments: dict) -> dict:
        """Invoke a tool and return its parsed JSON result payload."""
        message = self._post(
            {
                "jsonrpc": "2.0",
                "id": self._id(),
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            },
            timeout=CALL_TIMEOUT,
        )
        if "error" in message:
            raise McpError(f"{name} call failed: {message['error']}")
        result = message["result"]
        if result.get("isError"):
            text = " ".join(
                block.get("text", "") for block in result.get("content", [])
            )
            raise McpError(f"{name} returned an error result: {text}")
        structured = result.get("structuredContent")
        if structured is not None:
            return structured
        for block in result.get("content", []):
            if block.get("type") == "text":
                try:
                    return json.loads(block["text"])
                except json.JSONDecodeError:
                    return {"text": block["text"]}
        raise McpError(f"{name} returned no usable content")


def timed(client: McpClient, name: str, arguments: dict) -> tuple[dict, float]:
    start = time.perf_counter()
    payload = client.call_tool(name, arguments)
    return payload, (time.perf_counter() - start) * 1000.0


def fmt_ms(samples: list[float]) -> str:
    return f"min {min(samples):7.1f}  median {statistics.median(samples):7.1f}  max {max(samples):7.1f}"


def check_payload_equal(label: str, left: dict, right: dict) -> bool:
    if left == right:
        print(f"  [verify] {label}: identical results")
        return True
    print(f"  [verify] {label}: MISMATCH")
    print(f"    rex: {json.dumps(left)[:400]}")
    print(f"    rx:  {json.dumps(right)[:400]}")
    return False


def bench_single(client: McpClient, repetitions: int, args: argparse.Namespace) -> bool:
    """Head-to-head: rex_data_find vs rx_data_find on the same pattern."""
    arguments = {"binary": args.binary, "pattern": args.pattern, "limit": 50, "offset": 0}
    if args.section:
        arguments["section"] = args.section
    print(f"\n== single pattern {args.pattern!r} "
          f"(binary={args.binary}, section={args.section or 'all mapped segments'}, limit=50) ==")
    rex_samples, rx_samples = [], []
    rex_payload = rx_payload = None
    for _ in range(repetitions):
        rex_payload, seconds = timed(client, "rex_data_find", arguments)
        rex_samples.append(seconds)
        rx_payload, seconds = timed(client, "rx_data_find", arguments)
        rx_samples.append(seconds)
    print(f"  rex_data_find : {fmt_ms(rex_samples)} ms")
    print(f"  rx_data_find  : {fmt_ms(rx_samples)} ms")
    if min(rx_samples) > 0:
        print(f"  speedup (min) : {min(rex_samples) / min(rx_samples):.2f}x")
    return check_payload_equal("rx_data_find vs rex_data_find", rex_payload, rx_payload)


def bench_multi(client: McpClient, repetitions: int, args: argparse.Namespace) -> bool:
    """Headliner: rx_multi_find vs N sequential rex_data_find calls."""
    print(f"\n== {len(args.patterns)} patterns in one pass "
          f"(section={args.section or 'all mapped segments'}, limit=50) ==")
    multi_arguments = {
        "binary": args.binary,
        "patterns": args.patterns,
        "limit": 50,
        "offset": 0,
        **({"section": args.section} if args.section else {}),
    }
    multi_samples, sequential_samples = [], []
    multi_payload = None
    sequential_payloads: dict[str, dict] = {}
    for _ in range(repetitions):
        multi_payload, seconds = timed(client, "rx_multi_find", multi_arguments)
        multi_samples.append(seconds)
        total = 0.0
        for pattern in args.patterns:
            arguments = {"binary": args.binary, "pattern": pattern, "limit": 50, "offset": 0}
            if args.section:
                arguments["section"] = args.section
            payload, seconds = timed(client, "rex_data_find", arguments)
            sequential_payloads[pattern] = payload
            total += seconds
        sequential_samples.append(total)
    print(f"  N x rex_data_find (sum)     : {fmt_ms(sequential_samples)} ms")
    print(f"  rx_multi_find (one pass)    : {fmt_ms(multi_samples)} ms")
    if min(multi_samples) > 0:
        ratio = min(sequential_samples) / min(multi_samples)
        print(f"  speedup (min)               : {ratio:.2f}x")
    ok = True
    for entry in multi_payload.get("results", []):
        pattern = entry.get("pattern")
        rex = sequential_payloads.get(pattern)
        expected = (
            None
            if rex is None
            else {
                "total": rex["total"],
                "truncated": rex["truncated"],
                "matches": rex["matches"],
            }
        )
        observed = {
            "total": entry["total"],
            "truncated": entry["truncated"],
            "matches": entry["matches"],
        }
        ok = check_payload_equal(
            f"rx_multi_find[{pattern!r}] vs rex_data_find", expected, observed
        ) and ok
    return ok


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=DEFAULT_URL, help="MCP streamable HTTP endpoint")
    parser.add_argument("--binary", default=DEFAULT_BINARY,
                        help="handle of the open benchmark binary (see bn_binary_list)")
    parser.add_argument("--repeat", type=int, default=3, help="timed repetitions per scenario")
    parser.add_argument("--pattern", default="48 8b 05", help="single-pattern scenario pattern")
    parser.add_argument(
        "--patterns",
        nargs="+",
        default=DEFAULT_PATTERNS,
        help="rx_multi_find scenario patterns",
    )
    parser.add_argument("--section", default=None, help="restrict scenarios to this section")
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="only verify the handshake and that the rx_* tools are registered",
    )
    args = parser.parse_args()

    client = McpClient(args.url)
    try:
        client.initialize()
        tools = client.list_tools()
    except (urllib.error.URLError, TimeoutError, OSError, ValueError, McpError) as error:
        print(f"cannot reach MCP server at {args.url}: {error}", file=sys.stderr)
        return 2
    missing = [name for name in ("rex_data_find", "rx_data_find", "rx_multi_find") if name not in tools]
    if missing:
        print("MCP server is up, but these tools are missing: "
              + ", ".join(missing), file=sys.stderr)
        print("Did you restart Binary Ninja after scripts/install.sh?", file=sys.stderr)
        return 2
    print(f"handshake ok; {len(tools)} tools registered; rx_* and rex_* both present")
    if args.check_only:
        return 0
    if not args.binary:
        print("no --binary handle given (take one from bn_binary_list); "
              "handles change on every restart", file=sys.stderr)
        return 2

    ok = True
    try:
        ok = bench_single(client, args.repeat, args) and ok
        ok = bench_multi(client, args.repeat, args) and ok
    except McpError as error:
        print(f"benchmark call failed: {error}", file=sys.stderr)
        print("check --binary (bn_binary_list) and --section (bn_binary_info)",
              file=sys.stderr)
        return 2
    print("\nRESULT:", "all verifications passed" if ok else "VERIFICATION MISMATCH")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
