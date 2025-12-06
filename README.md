# Happy Server MCP

MCP (Model Context Protocol) server for managing Happy AI sessions. This allows AI agents to interact with Happy sessions programmatically.

## Features

- **List Sessions**: Query all your Happy AI sessions with their titles, working directories, and activity status
- **Read Messages**: Fetch recent messages from any session to see conversation history
- **Send Messages**: Trigger a session to work by sending it a message

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
    "happy": {
      "command": "happy-server-mcp"
    }
  }
}
```

Or with npx:

```json
{
  "mcpServers": {
    "happy": {
      "command": "npx",
      "args": ["@zhigang1992/happy-server-mcp"]
    }
  }
}
```

## Available Tools

### happy_list_sessions

List all Happy AI sessions.

**Parameters:**
- `limit` (optional): Maximum number of sessions to return (default: 50)

**Returns:** Session IDs, titles, working directories, and activity status

### happy_read_messages

Read recent messages from a Happy AI session.

**Parameters:**
- `session_id` (required): The session ID to read messages from
- `limit` (optional): Maximum number of messages to return (default: 20)

**Returns:** Recent conversation messages with timestamps

### happy_send_message

Send a message to a Happy AI session to trigger it to work.

**Parameters:**
- `session_id` (required): The session ID to send the message to
- `message` (required): The message text to send

**Returns:** Confirmation of message sent

## Environment Variables

- `HAPPY_SERVER_URL`: Override the Happy server URL (default: `https://happy.engineering`)

## License

MIT
