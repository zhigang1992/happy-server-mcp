#!/usr/bin/env node

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { HappyClient } from './happyClient.js';

const serverUrl = process.env.HAPPY_SERVER_URL || 'https://happy.engineering';

async function main() {
  const server = new McpServer({
    name: 'happy-server-mcp',
    version: '0.1.0',
  });

  let client: HappyClient | null = null;

  async function getClient(): Promise<HappyClient> {
    if (!client) {
      client = await HappyClient.create(serverUrl);
    }
    return client;
  }

  // List sessions tool
  server.tool(
    'happy_list_sessions',
    'List all Happy AI sessions. Returns session IDs, titles, working directories, and activity status.',
    {
      limit: z.number().optional().describe('Maximum number of sessions to return (default: 50)')
    },
    async ({ limit }) => {
      try {
        const happyClient = await getClient();
        const sessions = await happyClient.listSessions(limit ?? 50);

        const formatted = sessions.map(session => {
          const status = session.active ? '🟢 Active' : '⚪ Inactive';
          const lastActive = new Date(session.activeAt).toLocaleString();
          return `${status} [${session.id}]
  Title: ${session.title || '(untitled)'}
  Flavor: ${session.flavor || 'unknown'}
  CWD: ${session.cwd || '(not set)'}
  Last Active: ${lastActive}`;
        }).join('\n\n');

        return {
          content: [
            {
              type: 'text' as const,
              text: sessions.length > 0
                ? `Found ${sessions.length} sessions:\n\n${formatted}`
                : 'No sessions found.'
            }
          ]
        };
      } catch (error) {
        return {
          content: [
            {
              type: 'text' as const,
              text: `Error listing sessions: ${error instanceof Error ? error.message : String(error)}`
            }
          ],
          isError: true
        };
      }
    }
  );

  // Read messages tool
  server.tool(
    'happy_read_messages',
    'Read recent messages from a Happy AI session. Use this to see the conversation history.',
    {
      session_id: z.string().describe('The session ID to read messages from'),
      limit: z.number().optional().describe('Maximum number of messages to return (default: 20)')
    },
    async ({ session_id, limit }) => {
      try {
        const happyClient = await getClient();
        const messages = await happyClient.getMessages(session_id, limit ?? 20);

        const formatted = messages.map(msg => {
          const time = new Date(msg.createdAt).toLocaleString();
          const role = msg.role === 'user' ? '👤 User' : '🤖 Agent';
          const content = msg.content || '[No text content]';
          return `[${time}] ${role}:\n${content}`;
        }).join('\n\n---\n\n');

        return {
          content: [
            {
              type: 'text' as const,
              text: messages.length > 0
                ? `Last ${messages.length} messages from session ${session_id}:\n\n${formatted}`
                : 'No messages found in this session.'
            }
          ]
        };
      } catch (error) {
        return {
          content: [
            {
              type: 'text' as const,
              text: `Error reading messages: ${error instanceof Error ? error.message : String(error)}`
            }
          ],
          isError: true
        };
      }
    }
  );

  // Send message tool
  server.tool(
    'happy_send_message',
    'Send a message to a Happy AI session to trigger it to work. The message will be sent with bypass permissions mode.',
    {
      session_id: z.string().describe('The session ID to send the message to'),
      message: z.string().describe('The message text to send')
    },
    async ({ session_id, message }) => {
      try {
        const happyClient = await getClient();
        const result = await happyClient.sendMessage(session_id, message);

        if (result.success) {
          return {
            content: [
              {
                type: 'text' as const,
                text: `Message sent successfully to session ${session_id}.\n\nMessage: "${message}"\n\nNote: The session will process the message asynchronously. Use happy_read_messages to check for responses.`
              }
            ]
          };
        } else {
          return {
            content: [
              {
                type: 'text' as const,
                text: `Failed to send message: ${result.error}`
              }
            ],
            isError: true
          };
        }
      } catch (error) {
        return {
          content: [
            {
              type: 'text' as const,
              text: `Error sending message: ${error instanceof Error ? error.message : String(error)}`
            }
          ],
          isError: true
        };
      }
    }
  );

  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});
