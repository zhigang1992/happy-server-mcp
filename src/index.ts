#!/usr/bin/env node

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { HappyClient } from './happyClient.js';

const serverUrl = process.env.HAPPY_SERVER_URL || 'https://happy.engineering';

async function main() {
  const server = new McpServer({
    name: 'happy-server-mcp',
    version: '0.3.0',
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
    'List all Happy AI sessions. Returns session IDs, titles, paths, machines, and activity status.',
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
  Path: ${session.path || '(unknown)'}
  Host: ${session.host || '(unknown)'}
  Machine ID: ${session.machineId || '(unknown)'}
  Flavor: ${session.flavor || 'claude'}
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

  // List machines tool
  server.tool(
    'happy_list_machines',
    'List all machines registered with Happy. Returns machine IDs, hostnames, platforms, and activity status.',
    {},
    async () => {
      try {
        const happyClient = await getClient();
        const machines = await happyClient.listMachines();

        const formatted = machines.map(machine => {
          const status = machine.active ? '🟢 Online' : '⚪ Offline';
          const lastActive = new Date(machine.activeAt).toLocaleString();
          const displayName = machine.displayName || machine.host || '(unknown)';
          return `${status} [${machine.id}]
  Name: ${displayName}
  Host: ${machine.host || '(unknown)'}
  Platform: ${machine.platform || '(unknown)'}
  Home: ${machine.homeDir || '(unknown)'}
  Last Active: ${lastActive}`;
        }).join('\n\n');

        return {
          content: [
            {
              type: 'text' as const,
              text: machines.length > 0
                ? `Found ${machines.length} machines:\n\n${formatted}`
                : 'No machines found.'
            }
          ]
        };
      } catch (error) {
        return {
          content: [
            {
              type: 'text' as const,
              text: `Error listing machines: ${error instanceof Error ? error.message : String(error)}`
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
      message: z.string().describe('The message text to send'),
      wait: z.boolean().optional().describe('If true, wait for AI to finish processing before returning (default: false)')
    },
    async ({ session_id, message, wait }) => {
      try {
        const happyClient = await getClient();
        const result = await happyClient.sendMessage(session_id, message, wait ?? false);

        if (result.success) {
          const waitNote = wait
            ? 'AI has finished processing.'
            : 'The session will process the message asynchronously. Use happy_read_messages to check for responses.';
          return {
            content: [
              {
                type: 'text' as const,
                text: `Message sent successfully to session ${session_id}.\n\nMessage: "${message}"\n\n${waitNote}${result.error ? `\n\nWarning: ${result.error}` : ''}`
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

  // Start session tool
  server.tool(
    'happy_start_session',
    'Start a new Happy AI session on a machine. Use happy_list_machines to find available machines first.',
    {
      machine_id: z.string().describe('The machine ID to start the session on'),
      directory: z.string().describe('The directory path to run the session in'),
      message: z.string().optional().describe('Optional initial message to send to start the session working'),
      agent: z.enum(['claude', 'codex']).optional().describe('Agent type to use (default: claude)'),
      wait: z.boolean().optional().describe('If true, wait for AI to finish processing initial message before returning (default: false)')
    },
    async ({ machine_id, directory, message, agent, wait }) => {
      try {
        const happyClient = await getClient();
        const result = await happyClient.startSession(machine_id, directory, message, agent ?? 'claude', wait ?? false);

        if (result.success && result.sessionId) {
          const waitNote = (message && wait)
            ? 'AI has finished processing the initial message.'
            : (message ? 'Initial message sent. Use happy_read_messages to check session activity.' : 'Use happy_send_message to start working.');
          return {
            content: [
              {
                type: 'text' as const,
                text: `Session started successfully!\n\nSession ID: ${result.sessionId}\nDirectory: ${directory}\nAgent: ${agent ?? 'claude'}${message ? `\n\nInitial message: "${message}"` : ''}\n\n${waitNote}${result.error ? `\n\nWarning: ${result.error}` : ''}`
              }
            ]
          };
        } else {
          return {
            content: [
              {
                type: 'text' as const,
                text: `Failed to start session: ${result.error}`
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
              text: `Error starting session: ${error instanceof Error ? error.message : String(error)}`
            }
          ],
          isError: true
        };
      }
    }
  );

  // Archive session tool
  server.tool(
    'happy_archive_session',
    'Archive (stop) a Happy AI session. The session will be terminated and marked as inactive.',
    {
      session_id: z.string().describe('The session ID to archive')
    },
    async ({ session_id }) => {
      try {
        const happyClient = await getClient();
        const result = await happyClient.archiveSession(session_id);

        if (result.success) {
          return {
            content: [
              {
                type: 'text' as const,
                text: `Session ${session_id} has been archived successfully.`
              }
            ]
          };
        } else {
          return {
            content: [
              {
                type: 'text' as const,
                text: `Failed to archive session: ${result.error}`
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
              text: `Error archiving session: ${error instanceof Error ? error.message : String(error)}`
            }
          ],
          isError: true
        };
      }
    }
  );

  // Wait for idle tool
  server.tool(
    'happy_wait_for_idle',
    'Wait for a Happy AI session to become idle (finish processing). Useful after sending a message to wait for AI to complete its work.',
    {
      session_id: z.string().describe('The session ID to wait for'),
      timeout_seconds: z.number().optional().describe('Maximum time to wait in seconds (default: 120)')
    },
    async ({ session_id, timeout_seconds }) => {
      try {
        const happyClient = await getClient();
        const timeoutMs = (timeout_seconds ?? 120) * 1000;
        const result = await happyClient.waitForIdle(session_id, timeoutMs);

        if (result.success) {
          return {
            content: [
              {
                type: 'text' as const,
                text: `Session ${session_id} is now idle. AI has finished processing.`
              }
            ]
          };
        } else {
          return {
            content: [
              {
                type: 'text' as const,
                text: `Wait for idle failed: ${result.error}`
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
              text: `Error waiting for idle: ${error instanceof Error ? error.message : String(error)}`
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
