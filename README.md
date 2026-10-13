# Burp MCP Server

Burp Suite extension that exposes an MCP server, letting LLM-powered tools interact with Burp's proxy, scanner, and intercept features.

## Features

- **30 MCP tools** across categories: HTTP requests, proxy history, encoding, scanner, Collaborator, intercept, config, editor, Repeater/Intruder
- **Agent intercept** — hold Burp Proxy traffic so the MCP client can inspect, modify, forward, or drop requests and responses
- **Streamable HTTP transport** on configurable host:port (default `127.0.0.1:9876`)
- **No approval prompts** — every tool works as soon as the client connects. Approving individual tool calls is left to your MCP client (e.g. Claude Code's permission prompts), as in [caido-mcp-server](https://github.com/c0tton-fluff/caido-mcp-server)
- **Auto-restart** — the server restarts automatically when you change the bind host or port

## Requirements

- Burp Suite (Community or Professional)
- Java 21+

## Installation

### Download

Grab the latest JAR from `build/libs/`, or build from source:

```bash
./gradlew shadowJar
```

The output JAR is `build/libs/burp-mcp-server-1.0.0.jar`.

### Load in Burp

1. Open Burp Suite
2. Go to **Extensions → Add**
3. Set Extension type to **Java**
4. Select the JAR file
5. Click **Next** — the MCP tab will appear

## MCP Client Setup

The MCP server listens at `http://<host>:<port>/mcp` (default `http://127.0.0.1:9876/mcp`).

### Claude Code CLI

```bash
claude mcp add --transport http burp http://127.0.0.1:9876/mcp
```

### .mcp.json

Add to your project's `.mcp.json`:

```json
{
  "mcpServers": {
    "burp": {
      "type": "http",
      "url": "http://127.0.0.1:9876/mcp"
    }
  }
}
```

### Claude Desktop

Add to your Claude Desktop config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "burp": {
      "type": "http",
      "url": "http://127.0.0.1:9876/mcp"
    }
  }
}
```

### Generic

Any MCP client that supports HTTP transport can connect to `http://<host>:<port>/mcp`.

## Configuration

All settings are configurable from the **MCP → Server** tab in Burp Suite and persist across sessions. Changing the bind host or port restarts the server automatically.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | Boolean | `true` | Start the MCP server when the extension loads |
| `host` | String | `127.0.0.1` | Bind address for the HTTP server |
| `port` | Int | `9876` | Listen port for the HTTP server |

The server has no authentication and no approval step: anything that can reach the port can drive Burp. Keep the bind host on `127.0.0.1` unless you intend to expose it.

## Tools

### HTTP Requests

| Tool | Description |
|------|-------------|
| `send_http1_request` | Send an HTTP/1.1 request and return the response |
| `send_http2_request` | Send an HTTP/2 request and return the response |

### Burp UI Integration

| Tool | Description |
|------|-------------|
| `create_repeater_tab` | Create a new Repeater tab with a request |
| `send_to_intruder` | Send a request to Intruder |
| `set_task_execution_engine_state` | Pause or resume Burp's task execution engine |
| `set_proxy_intercept_state` | Enable or disable Burp's own Proxy → Intercept (not visible to MCP tools — see [Agent Intercept](#agent-intercept)) |
| `get_active_editor_contents` | Get contents of the active message editor |
| `set_active_editor_contents` | Set contents of the active message editor |

### Encoding / Utilities

| Tool | Description |
|------|-------------|
| `url_encode` | URL-encode a string |
| `url_decode` | URL-decode a string |
| `base64_encode` | Base64-encode a string |
| `base64_decode` | Base64-decode a string |
| `generate_random_string` | Generate a random string with specified length and character set |

### Configuration

| Tool | Description |
|------|-------------|
| `output_project_options` | Export current project-level config as JSON |
| `output_user_options` | Export current user-level config as JSON |
| `set_project_options` | Import project-level config from JSON |
| `set_user_options` | Import user-level config from JSON |

### Proxy History

| Tool | Description |
|------|-------------|
| `get_proxy_http_history` | List proxy HTTP history (paginated) |
| `get_proxy_http_history_regex` | Search proxy HTTP history by regex (paginated) |
| `get_proxy_http_history_item` | Get a single history item by ID (full headers/body + modified versions) |
| `get_proxy_http_history_item_raw` | Get the FULL raw bytes of a history item (incl. request start-line), untruncated |
| `get_proxy_websocket_history` | List proxy WebSocket history (paginated) |
| `get_proxy_websocket_history_regex` | Search proxy WebSocket history by regex (paginated) |

### Capture → Mutate → Replay

Take a real browser request captured in proxy history, mutate one field, and resend it byte-faithfully
(header order, casing, cookies preserved) so the request stays browser-faithful — the analog of manual
Repeater/Intruder, driven programmatically.

| Tool | Description |
|------|-------------|
| `replay_proxy_history_item` | Replay a captured request with surgical mutations (`replacements` / `setHeaders` / `updateParams` / `setBody` / `setPath` / `setMethod` / retarget host:port:tls) and transport control (`httpMode` AUTO\|HTTP_1\|HTTP_2\|HTTP_2_IGNORE_ALPN, `sni`, `redirectionMode`, `responseTimeoutMs`). Returns the exact request sent + the response. |
| `intruder_batch` | Programmatic Intruder: substitute a `marker` in a base request (`baseId` from history, or `baseContent` + target) with each `payload`, send (optional `throttleMs`), return per-payload status/length/timing. Unlike `send_to_intruder` (UI only), this executes and returns results. |
| `get_site_map` | List endpoints Burp discovered in the site map (populated by browsing), optionally filtered by url `prefix` (paginated). |

> Fingerprint note: these tools send via Burp's HTTP stack, so the TLS/JA3 the target sees is Burp's
> unless Burp egresses through a browser-JA3 upstream (e.g. an impersonating MITM proxy). The captured
> request supplies faithful HTTP-layer bytes; the upstream supplies the TLS fingerprint.

### Scanner & Collaborator *(Professional Edition only)*

| Tool | Description |
|------|-------------|
| `get_scanner_issues` | List issues identified by the scanner (paginated) |
| `generate_collaborator_payload` | Generate a Burp Collaborator payload URL for OOB testing |
| `get_collaborator_interactions` | Poll for Collaborator interactions (DNS, HTTP, SMTP) |

### Agent Intercept

| Tool | Description |
|------|-------------|
| `set_mcp_intercept_enabled` | Turn the agent intercept on or off |
| `get_intercepted_requests` | List pending intercepted HTTP requests |
| `get_intercepted_responses` | List pending intercepted HTTP responses |
| `get_intercepted_message_detail` | Get full raw content of an intercepted message |
| `forward_intercepted_message` | Forward a message, optionally with modifications |
| `drop_intercepted_message` | Drop a message, preventing delivery |

## Agent Intercept

The agent intercept holds HTTP traffic passing through **Burp Proxy** (e.g. from a browser using Burp as its proxy) so the MCP client can decide what happens to each message. It is:

- **not** Burp's own **Proxy → Intercept** — that queue is driven from Burp's UI and the Montoya API cannot read it, which is why this extension keeps a queue of its own;
- **not** an intercept of the MCP connection — traffic between your agent and Burp is never held.

Turn it on with `set_mcp_intercept_enabled`, or with **Hold proxy traffic for the agent** under **MCP → Server**. Held messages appear in the **MCP → Agent Intercept** tab, where you can also forward, edit, or drop them by hand.

### Workflow

1. **Enable** — call `set_mcp_intercept_enabled` with `enabled: true`; Burp begins holding proxied traffic
2. **Inspect** — call `get_intercepted_requests` / `get_intercepted_responses` to list held messages
3. **Read** — call `get_intercepted_message_detail` with a message ID to view the full raw HTTP content
4. **Act** — either:
   - `forward_intercepted_message` to send it on (optionally supply `modifiedRaw` or `replacements` to alter the content)
   - `drop_intercepted_message` to silently discard it
5. **Disable** — call `set_mcp_intercept_enabled` with `enabled: false` to auto-forward all remaining messages and stop intercepting

### Limits

- **Timeout**: 10 minutes — unhandled messages are auto-forwarded after this period
- **Max pending**: 50 messages — when the queue is full, new messages pass through without being held

## License

[MIT](LICENSE)
