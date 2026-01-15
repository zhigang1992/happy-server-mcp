# Happy Server MCP

MCP (Model Context Protocol) server for managing Happy AI sessions. This allows AI agents to interact with Happy sessions programmatically.

## Features

- **List Sessions**: Query all your Happy AI sessions with their titles, working directories, and activity status
- **List Machines**: See all registered machines and their online/offline status
- **List Recent Paths**: Get recently used working directories for a machine
- **Read Messages**: Fetch recent messages from any session to see conversation history
- **Send Messages**: Trigger a session to work by sending it a message
- **Start Sessions**: Spawn new AI sessions on any connected machine
- **Archive Sessions**: Stop and archive sessions when done
- **Wait for Idle**: Wait for a session to finish processing

## Installation

```bash
npm install -g @zhigang1992/happy-server-mcp
```

## Prerequisites

You must be authenticated with Happy CLI. Run:

```bash
happy auth
```

This creates credentials at `~/.happy/access.key` that the MCP server uses.

## Usage with Claude

Add to your Claude configuration:

```json
{
  "mcpServers": {
    "happy-manager": {
      "command": "happy-server-mcp"
    }
  }
}
```

Or with npx:

```json
{
  "mcpServers": {
    "happy-manager": {
      "command": "npx",
      "args": ["@zhigang1992/happy-server-mcp"]
    }
  }
}
```

## Available Tools

### happy_list_sessions

List all Happy AI sessions. Returns session IDs, titles, paths, machines, and activity status.

**Parameters:**
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `limit` | number | No | 50 | Maximum number of sessions to return |

**Example:**
```
Use happy_list_sessions to see all my active sessions
```

---

### happy_list_machines

List all machines registered with Happy. Returns machine IDs, hostnames, platforms, and activity status.

**Parameters:** None

**Example:**
```
Use happy_list_machines to see which machines are online
```

---

### happy_list_recent_paths

List recently used folder paths for a machine. Useful for starting sessions in familiar locations.

**Parameters:**
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `machine_id` | string | Yes | - | The machine ID to get recent paths for |
| `limit` | number | No | 20 | Maximum number of paths to return |

**Example:**
```
Use happy_list_recent_paths with machine_id "abc123" to see recent working directories
```

---

### happy_read_messages

Read recent messages from a Happy AI session. Use this to see the conversation history.

**Parameters:**
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `session_id` | string | Yes | - | The session ID to read messages from |
| `limit` | number | No | 20 | Maximum number of messages to return |

**Example:**
```
Use happy_read_messages with session_id "xyz789" to see what the AI has been working on
```

---

### happy_send_message

Send a message to a Happy AI session to trigger it to work. The message will be sent with bypass permissions mode.

**Parameters:**
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `session_id` | string | Yes | - | The session ID to send the message to |
| `message` | string | Yes | - | The message text to send |
| `wait` | boolean | No | false | If true, wait for AI to finish processing before returning |

**Example:**
```
Use happy_send_message with session_id "xyz789" and message "Fix the bug in auth.ts" and wait=true
```

---

### happy_start_session

Start a new Happy AI session on a machine. Use `happy_list_machines` to find available machines first.

**Parameters:**
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `machine_id` | string | Yes | - | The machine ID to start the session on |
| `directory` | string | Yes | - | The directory path to run the session in |
| `message` | string | No | - | Optional initial message to send to start the session working |
| `agent` | "claude" \| "codex" | No | "claude" | Agent type to use |
| `wait` | boolean | No | false | If true, wait for AI to finish processing initial message before returning |

**Example:**
```
Use happy_start_session with machine_id "abc123", directory "/home/user/project",
message "Review the codebase and suggest improvements", and wait=true
```

---

### happy_archive_session

Archive (stop) a Happy AI session. The session will be terminated and marked as inactive.

**Parameters:**
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `session_id` | string | Yes | - | The session ID to archive |

**Example:**
```
Use happy_archive_session with session_id "xyz789" to stop the session
```

---

### happy_wait_for_idle

Wait for a Happy AI session to become idle (finish processing). Useful after sending a message to wait for AI to complete its work.

**Parameters:**
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `session_id` | string | Yes | - | The session ID to wait for |
| `timeout_seconds` | number | No | 120 | Maximum time to wait in seconds |

**Example:**
```
Use happy_wait_for_idle with session_id "xyz789" to wait for the AI to finish
```

## Common Workflows

### Start a session and wait for completion

1. Use `happy_list_machines` to find an online machine
2. Use `happy_list_recent_paths` to find a good working directory
3. Use `happy_start_session` with `wait=true` to start and wait for the initial task

### Monitor an existing session

1. Use `happy_list_sessions` to find active sessions
2. Use `happy_read_messages` to see what the AI is working on
3. Use `happy_send_message` to give it new instructions

### Clean up old sessions

1. Use `happy_list_sessions` to see all sessions
2. Use `happy_archive_session` to stop sessions you no longer need

## Environment Variables

- `HAPPY_SERVER_URL`: Override the Happy server URL (default: `https://happy.engineering`)

## License

MIT
