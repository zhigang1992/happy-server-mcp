#!/usr/bin/env node

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { HappyClient } from './happyClient.js';

const serverUrl = process.env.HAPPY_SERVER_URL || 'https://happy-server.innopals.com';

async function main() {
  const server = new McpServer({
    name: 'happy-manager',
    version: '0.3.5',
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

  // List recent paths tool
  server.tool(
    'happy_list_recent_paths',
    'List recently used folder paths for a machine. Useful for starting sessions in familiar locations.',
    {
      machine_id: z.string().describe('The machine ID to get recent paths for'),
      limit: z.number().optional().describe('Maximum number of paths to return (default: 20)')
    },
    async ({ machine_id, limit }) => {
      try {
        const happyClient = await getClient();
        const paths = await happyClient.getRecentPaths(machine_id, limit ?? 20);

        if (paths.length === 0) {
          return {
            content: [
              {
                type: 'text' as const,
                text: `No recent paths found for machine ${machine_id}.`
              }
            ]
          };
        }

        const formatted = paths.map((path, index) => `${index + 1}. ${path}`).join('\n');

        return {
          content: [
            {
              type: 'text' as const,
              text: `Recent paths for machine ${machine_id}:\n\n${formatted}`
            }
          ]
        };
      } catch (error) {
        return {
          content: [
            {
              type: 'text' as const,
              text: `Error listing recent paths: ${error instanceof Error ? error.message : String(error)}`
            }
          ],
          isError: true
        };
      }
    }
  );

  // List environment sets tool
  server.tool(
    'happy_list_environment_sets',
    'List available environment variable presets. These can be used when starting new sessions with happy_start_session.',
    {},
    async () => {
      try {
        const happyClient = await getClient();
        const envSets = await happyClient.getEnvironmentSets();

        if (envSets.length === 0) {
          return {
            content: [
              {
                type: 'text' as const,
                text: 'No environment presets configured. You can create them in the Happy app settings, or pass custom environment_variables directly to happy_start_session.'
              }
            ]
          };
        }

        const formatted = envSets.map(set => {
          const varCount = Object.keys(set.variables).length;
          const varList = Object.keys(set.variables).slice(0, 5).join(', ');
          const moreCount = varCount > 5 ? ` (+${varCount - 5} more)` : '';
          const defaultBadge = set.isDefault ? ' [DEFAULT]' : '';
          return `• ${set.name}${defaultBadge}\n  ID: ${set.id}\n  Variables (${varCount}): ${varList}${moreCount}`;
        }).join('\n\n');

        return {
          content: [
            {
              type: 'text' as const,
              text: `Found ${envSets.length} environment preset${envSets.length !== 1 ? 's' : ''}:\n\n${formatted}\n\nUse the preset ID with happy_start_session's environment_preset_id parameter.`
            }
          ]
        };
      } catch (error) {
        return {
          content: [
            {
              type: 'text' as const,
              text: `Error listing environment sets: ${error instanceof Error ? error.message : String(error)}`
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
    'Start a new Happy AI session on a machine. Use happy_list_machines to find available machines first. Use happy_list_environment_sets to see available environment presets.',
    {
      machine_id: z.string().describe('The machine ID to start the session on'),
      directory: z.string().describe('The directory path to run the session in'),
      message: z.string().optional().describe('Optional initial message to send to start the session working'),
      agent: z.enum(['claude', 'codex']).optional().describe('Agent type to use (default: claude)'),
      wait: z.boolean().optional().describe('If true, wait for AI to finish processing initial message before returning (default: false)'),
      environment_preset_id: z.string().optional().describe('Optional ID of an environment preset to use (from happy_list_environment_sets). Preset variables are applied first, then custom variables override them.'),
      environment_variables: z.record(z.string(), z.string()).optional().describe('Optional custom environment variables as key-value pairs. These override any variables from the preset.')
    },
    async ({ machine_id, directory, message, agent, wait, environment_preset_id, environment_variables }) => {
      try {
        const happyClient = await getClient();

        // Merge environment variables: preset first, then custom overrides
        let mergedEnvVars: Record<string, string> = {};

        if (environment_preset_id) {
          const envSets = await happyClient.getEnvironmentSets();
          const preset = envSets.find(s => s.id === environment_preset_id);
          if (preset) {
            mergedEnvVars = { ...preset.variables };
          } else {
            return {
              content: [
                {
                  type: 'text' as const,
                  text: `Environment preset not found: ${environment_preset_id}. Use happy_list_environment_sets to see available presets.`
                }
              ],
              isError: true
            };
          }
        }

        // Custom variables override preset variables
        if (environment_variables) {
          mergedEnvVars = { ...mergedEnvVars, ...environment_variables };
        }

        const result = await happyClient.startSession(
          machine_id,
          directory,
          message,
          agent ?? 'claude',
          wait ?? false,
          Object.keys(mergedEnvVars).length > 0 ? mergedEnvVars : undefined
        );

        if (result.success && result.sessionId) {
          const waitNote = (message && wait)
            ? 'AI has finished processing the initial message.'
            : (message ? 'Initial message sent. Use happy_read_messages to check session activity.' : 'Use happy_send_message to start working.');

          // Build environment info for response
          let envInfo = '';
          if (environment_preset_id || (environment_variables && Object.keys(environment_variables).length > 0)) {
            const envCount = Object.keys(mergedEnvVars).length;
            envInfo = `\nEnvironment: ${envCount} variable${envCount !== 1 ? 's' : ''} configured`;
            if (environment_preset_id) {
              envInfo += ` (preset: ${environment_preset_id})`;
            }
          }

          return {
            content: [
              {
                type: 'text' as const,
                text: `Session started successfully!\n\nSession ID: ${result.sessionId}\nDirectory: ${directory}\nAgent: ${agent ?? 'claude'}${envInfo}${message ? `\n\nInitial message: "${message}"` : ''}\n\n${waitNote}${result.error ? `\n\nWarning: ${result.error}` : ''}`
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

  // List Zen todos tool
  server.tool(
    'happy_zen_list_todos',
    'List Zen (todo) items with titles, descriptions, and completion status.',
    {},
    async () => {
      try {
        const happyClient = await getClient();
        const { todos } = await happyClient.listTodos();

        if (todos.length === 0) {
          return {
            content: [
              {
                type: 'text' as const,
                text: 'No todos found.'
              }
            ]
          };
        }

        const formatted = todos.map((todo, index) => {
          const status = todo.done ? '✅ Done' : '🟡 Open';
          const title = todo.title || '(untitled)';
          const text = todo.text?.trim() ? `\n  Description: ${todo.text}` : '';
          return `${index + 1}. ${status} [${todo.id}]\n  Title: ${title}${text}`;
        }).join('\n\n');

        return {
          content: [
            {
              type: 'text' as const,
              text: `Found ${todos.length} todos:\n\n${formatted}`
            }
          ]
        };
      } catch (error) {
        return {
          content: [
            {
              type: 'text' as const,
              text: `Error listing todos: ${error instanceof Error ? error.message : String(error)}`
            }
          ],
          isError: true
        };
      }
    }
  );

  // Create Zen todo tool
  server.tool(
    'happy_zen_create_todo',
    'Create a new Zen (todo) item with a title and optional description.',
    {
      title: z.string().describe('Todo title'),
      text: z.string().optional().describe('Optional todo description/details')
    },
    async ({ title, text }) => {
      try {
        const happyClient = await getClient();
        const todo = await happyClient.createTodo(title, text);
        return {
          content: [
            {
              type: 'text' as const,
              text: `Todo created.\n\nID: ${todo.id}\nTitle: ${todo.title}${todo.text ? `\nDescription: ${todo.text}` : ''}`
            }
          ]
        };
      } catch (error) {
        return {
          content: [
            {
              type: 'text' as const,
              text: `Error creating todo: ${error instanceof Error ? error.message : String(error)}`
            }
          ],
          isError: true
        };
      }
    }
  );

  // Update Zen todo tool
  server.tool(
    'happy_zen_update_todo',
    'Update a Zen (todo) item title and/or description.',
    {
      id: z.string().describe('Todo ID'),
      title: z.string().optional().describe('Updated title'),
      text: z.string().optional().describe('Updated description/details')
    },
    async ({ id, title, text }) => {
      try {
        if (title === undefined && text === undefined) {
          return {
            content: [
              {
                type: 'text' as const,
                text: 'No updates provided. Specify title and/or text.'
              }
            ],
            isError: true
          };
        }

        const happyClient = await getClient();
        const todo = await happyClient.updateTodo(id, { title, text });
        return {
          content: [
            {
              type: 'text' as const,
              text: `Todo updated.\n\nID: ${todo.id}\nTitle: ${todo.title}${todo.text ? `\nDescription: ${todo.text}` : ''}`
            }
          ]
        };
      } catch (error) {
        return {
          content: [
            {
              type: 'text' as const,
              text: `Error updating todo: ${error instanceof Error ? error.message : String(error)}`
            }
          ],
          isError: true
        };
      }
    }
  );

  // Toggle/set Zen todo done status tool
  server.tool(
    'happy_zen_set_todo_done',
    'Set or toggle a Zen (todo) item completion status.',
    {
      id: z.string().describe('Todo ID'),
      done: z.boolean().optional().describe('If provided, set to done/undone; otherwise toggles')
    },
    async ({ id, done }) => {
      try {
        const happyClient = await getClient();
        const todo = await happyClient.setTodoDone(id, done);
        return {
          content: [
            {
              type: 'text' as const,
              text: `Todo ${todo.done ? 'completed' : 'reopened'}.\n\nID: ${todo.id}\nTitle: ${todo.title}`
            }
          ]
        };
      } catch (error) {
        return {
          content: [
            {
              type: 'text' as const,
              text: `Error updating todo status: ${error instanceof Error ? error.message : String(error)}`
            }
          ],
          isError: true
        };
      }
    }
  );

  // Delete Zen todo tool
  server.tool(
    'happy_zen_delete_todo',
    'Delete a Zen (todo) item.',
    {
      id: z.string().describe('Todo ID')
    },
    async ({ id }) => {
      try {
        const happyClient = await getClient();
        await happyClient.deleteTodo(id);
        return {
          content: [
            {
              type: 'text' as const,
              text: `Todo ${id} deleted.`
            }
          ]
        };
      } catch (error) {
        return {
          content: [
            {
              type: 'text' as const,
              text: `Error deleting todo: ${error instanceof Error ? error.message : String(error)}`
            }
          ],
          isError: true
        };
      }
    }
  );

  // Link Zen todo to a session tool
  server.tool(
    'happy_zen_link_session',
    'Link a Zen (todo) item to a Happy session with a display title.',
    {
      id: z.string().describe('Todo ID'),
      session_id: z.string().describe('Session ID to link'),
      display_title: z.string().describe('Display title for the linked session')
    },
    async ({ id, session_id, display_title }) => {
      try {
        const happyClient = await getClient();
        const todo = await happyClient.linkTodoToSession(id, session_id, display_title);
        return {
          content: [
            {
              type: 'text' as const,
              text: `Session linked.\n\nTodo ID: ${todo.id}\nTitle: ${todo.title}\nSession: ${session_id}`
            }
          ]
        };
      } catch (error) {
        return {
          content: [
            {
              type: 'text' as const,
              text: `Error linking session: ${error instanceof Error ? error.message : String(error)}`
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
