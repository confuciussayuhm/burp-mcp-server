# Burp MCP Server

Burp Suite extension that exposes an MCP server, letting LLM-powered tools interact with Burp's proxy, scanner, and intercept features.

## Features

- **30 MCP tools** across categories: HTTP requests, proxy history, encoding, scanner, Collaborator, intercept, config, editor, Repeater/Intruder
- **Programmatic proxy intercept** — hold, inspect, modify, forward, or drop requests and responses from an MCP client
- **Streamable HTTP transport** on configurable host:port (default `127.0.0.1:9876`)
- **Approval controls** for HTTP requests and history access with interactive dialogs
- **Auto-approve targets** by hostname, host:port, or wildcard pattern

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

All settings are configurable from the **MCP** tab in Burp Suite and persist across sessions.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | Boolean | `true` | Start the MCP server when the extension loads |
| `host` | String | `127.0.0.1` | Bind address for the HTTP server |
| `port` | Int | `9876` | Listen port for the HTTP server |
| `requireHttpRequestApproval` | Boolean | `true` | Prompt before MCP-initiated HTTP requests are sent |
| `requireHistoryAccessApproval` | Boolean | `true` | Prompt before exposing proxy history to MCP clients |
| `configEditingTooling` | Boolean | `false` | Enable `set_project_options` / `set_user_options` tools |
| `autoApproveTargets` | String | *(empty)* | Comma-separated list of auto-approved hosts |

### Auto-Approve Target Format

| Format | Example | Behavior |
|--------|---------|----------|
| `hostname` | `example.com` | Exact match on hostname (any port) |
| `hostname:port` | `example.com:8443` | Exact match on hostname and port |
| `*.domain` | `*.internal.corp` | Wildcard — matches any subdomain |

Targets can be added manually in the config tab or via the approval dialog ("Always Allow Host" / "Always Allow Host:Port").

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
| `set_proxy_intercept_state` | Enable or disable Burp's native proxy intercept |
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
| `set_project_options` | Import project-level config from JSON *(requires `configEditingTooling` enabled)* |
| `set_user_options` | Import user-level config from JSON *(requires `configEditingTooling` enabled)* |

### Proxy History

| Tool | Description |
|------|-------------|
| `get_proxy_http_history` | List proxy HTTP history (paginated) |
| `get_proxy_http_history_regex` | Search proxy HTTP history by regex (paginated) |
| `get_proxy_websocket_history` | List proxy WebSocket history (paginated) |
| `get_proxy_websocket_history_regex` | Search proxy WebSocket history by regex (paginated) |

### Scanner & Collaborator *(Professional Edition only)*

| Tool | Description |
|------|-------------|
| `get_scanner_issues` | List issues identified by the scanner (paginated) |
| `generate_collaborator_payload` | Generate a Burp Collaborator payload URL for OOB testing |
| `get_collaborator_interactions` | Poll for Collaborator interactions (DNS, HTTP, SMTP) |

### MCP Intercept

| Tool | Description |
|------|-------------|
| `set_mcp_intercept_enabled` | Enable or disable MCP-based proxy interception |
| `get_intercepted_requests` | List pending intercepted HTTP requests |
| `get_intercepted_responses` | List pending intercepted HTTP responses |
| `get_intercepted_message_detail` | Get full raw content of an intercepted message |
| `forward_intercepted_message` | Forward a message, optionally with modifications |
| `drop_intercepted_message` | Drop a message, preventing delivery |

## MCP Intercept

MCP Intercept provides programmatic proxy interception, independent of Burp's native intercept toggle.

### Workflow

1. **Enable** — call `set_mcp_intercept_enabled` with `enabled: true`; Burp begins holding proxied traffic
2. **Inspect** — call `get_intercepted_requests` / `get_intercepted_responses` to list pending messages
3. **Read** — call `get_intercepted_message_detail` with a message ID to view the full raw HTTP content
4. **Act** — either:
   - `forward_intercepted_message` to send it on (optionally supply `modifiedRaw` to alter the content)
   - `drop_intercepted_message` to silently discard it
5. **Disable** — call `set_mcp_intercept_enabled` with `enabled: false` to auto-forward all remaining messages and stop intercepting

### Limits

- **Timeout**: 120 seconds — unhandled messages are auto-forwarded after this period
- **Max pending**: 50 messages — when the queue is full, new messages pass through without being held

## License

[MIT](LICENSE)
