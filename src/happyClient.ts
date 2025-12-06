import { readFile, stat } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { io, Socket } from 'socket.io-client';
import {
  Credentials,
  CredentialsFileSchema,
  ApiSession,
  ApiMessage,
  ApiMachine,
  SessionMetadata,
  MachineMetadata,
  DecryptedSession,
  SessionInfo,
  MachineInfo,
  MessageInfo,
  MessageContent,
  UserMessageContent,
  AgentMessageContent
} from './types.js';
import {
  decodeBase64,
  encodeBase64,
  encrypt,
  decrypt,
  EncryptionVariant,
  derivePublicKeyFromSeed,
  libsodiumEncryptForPublicKey
} from './encryption.js';

const DEFAULT_SERVER_URL = 'https://happy.engineering';

// For self-hosted setups, you can override via HAPPY_SERVER_URL env var
// Common servers:
// - Production: https://api.cluster-fluster.com
// - Self-hosted example: https://happy-server.reily.app

export class HappyClient {
  private credentials: Credentials;
  private serverUrl: string;
  private socket: Socket | null = null;

  private constructor(credentials: Credentials, serverUrl: string) {
    this.credentials = credentials;
    this.serverUrl = serverUrl;
  }

  /**
   * Create a HappyClient by reading credentials from the standard location
   */
  static async create(serverUrl?: string): Promise<HappyClient> {
    const credentials = await HappyClient.loadCredentials();
    if (!credentials) {
      throw new Error('No Happy credentials found. Please run `happy auth` first.');
    }
    return new HappyClient(credentials, serverUrl ?? DEFAULT_SERVER_URL);
  }

  /**
   * Load credentials from ~/.happy/access.key
   */
  private static async loadCredentials(): Promise<Credentials | null> {
    const keyFile = join(homedir(), '.happy', 'access.key');

    try {
      await stat(keyFile);
    } catch {
      return null;
    }

    try {
      const content = await readFile(keyFile, 'utf8');
      const parsed = CredentialsFileSchema.parse(JSON.parse(content));

      if (parsed.secret) {
        return {
          token: parsed.token,
          encryption: {
            type: 'legacy',
            secret: decodeBase64(parsed.secret)
          }
        };
      } else if (parsed.encryption) {
        return {
          token: parsed.token,
          encryption: {
            type: 'dataKey',
            dataKeySeed: decodeBase64(parsed.encryption.publicKey),
            machineKey: decodeBase64(parsed.encryption.machineKey)
          }
        };
      }
    } catch (error) {
      console.error('Failed to parse credentials:', error);
    }

    return null;
  }

  /**
   * Get encryption key and variant
   */
  private getEncryption(): { key: Uint8Array; variant: EncryptionVariant } {
    if (this.credentials.encryption.type === 'legacy') {
      return {
        key: this.credentials.encryption.secret,
        variant: 'legacy'
      };
    } else {
      return {
        key: this.credentials.encryption.machineKey,
        variant: 'dataKey'
      };
    }
  }

  /**
   * Decrypt session metadata
   */
  private decryptMetadata(encrypted: string, key: Uint8Array, variant: EncryptionVariant): SessionMetadata | null {
    try {
      const decoded = decodeBase64(encrypted);
      return decrypt(key, variant, decoded) as SessionMetadata | null;
    } catch {
      return null;
    }
  }

  /**
   * Decrypt a message content
   */
  private decryptMessage(encrypted: string, key: Uint8Array, variant: EncryptionVariant): MessageContent | null {
    try {
      const decoded = decodeBase64(encrypted);
      return decrypt(key, variant, decoded) as MessageContent | null;
    } catch {
      return null;
    }
  }

  /**
   * Get session title from metadata (matches getSessionName from Happy app)
   */
  private getSessionTitle(metadata: SessionMetadata | null): string | null {
    if (!metadata) return null;
    // Prefer summary.text if available
    if (metadata.summary?.text) {
      return metadata.summary.text;
    }
    // Fall back to last segment of path
    if (metadata.path) {
      const segments = metadata.path.split('/').filter(Boolean);
      return segments.pop() || null;
    }
    return null;
  }

  /**
   * Format path relative to home directory (matches formatPathRelativeToHome from Happy app)
   */
  private formatPathRelativeToHome(path: string, homeDir?: string): string {
    if (!homeDir) return path;
    const normalizedHome = homeDir.endsWith('/') ? homeDir.slice(0, -1) : homeDir;
    if (path.startsWith(normalizedHome)) {
      const relativePath = path.slice(normalizedHome.length);
      if (relativePath.startsWith('/')) {
        return '~' + relativePath;
      } else if (relativePath === '') {
        return '~';
      } else {
        return '~/' + relativePath;
      }
    }
    return path;
  }

  /**
   * List all sessions
   */
  async listSessions(limit: number = 50): Promise<SessionInfo[]> {
    const response = await fetch(`${this.serverUrl}/v1/sessions`, {
      headers: {
        'Authorization': `Bearer ${this.credentials.token}`,
        'Content-Type': 'application/json'
      }
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch sessions: ${response.status} ${response.statusText}`);
    }

    const data = await response.json() as { sessions: ApiSession[] };
    const { key, variant } = this.getEncryption();

    const sessions: SessionInfo[] = [];

    for (const session of data.sessions.slice(0, limit)) {
      const metadata = this.decryptMetadata(session.metadata, key, variant);

      sessions.push({
        id: session.id,
        title: this.getSessionTitle(metadata),
        path: metadata?.path ? this.formatPathRelativeToHome(metadata.path, metadata.homeDir) : null,
        host: metadata?.host ?? null,
        machineId: metadata?.machineId ?? null,
        flavor: metadata?.flavor ?? null,
        active: session.active,
        activeAt: session.activeAt,
        updatedAt: session.updatedAt,
        createdAt: session.createdAt
      });
    }

    return sessions;
  }

  /**
   * List all machines
   */
  async listMachines(): Promise<MachineInfo[]> {
    const response = await fetch(`${this.serverUrl}/v1/machines`, {
      headers: {
        'Authorization': `Bearer ${this.credentials.token}`,
        'Content-Type': 'application/json'
      }
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch machines: ${response.status} ${response.statusText}`);
    }

    const data = await response.json() as ApiMachine[];
    const { key, variant } = this.getEncryption();

    const machines: MachineInfo[] = [];

    for (const machine of data) {
      let metadata: MachineMetadata | null = null;
      try {
        const decoded = decodeBase64(machine.metadata);
        metadata = decrypt(key, variant, decoded) as MachineMetadata | null;
      } catch {
        // Ignore decryption errors
      }

      machines.push({
        id: machine.id,
        host: metadata?.host ?? null,
        displayName: metadata?.displayName ?? null,
        platform: metadata?.platform ?? null,
        homeDir: metadata?.homeDir ?? null,
        active: machine.active,
        activeAt: machine.activeAt
      });
    }

    return machines;
  }

  /**
   * Archive (kill) a session
   */
  async archiveSession(sessionId: string): Promise<{ success: boolean; error?: string }> {
    const { key, variant } = this.getEncryption();

    return new Promise((resolve) => {
      let resolved = false;

      const socket = io(this.serverUrl, {
        auth: {
          token: this.credentials.token,
          clientType: 'user-scoped'
        },
        path: '/v1/updates',
        transports: ['websocket'],
        reconnection: false,
        timeout: 15000
      });

      const cleanup = (result: { success: boolean; error?: string }) => {
        if (resolved) return;
        resolved = true;
        socket.disconnect();
        resolve(result);
      };

      const timeout = setTimeout(() => {
        cleanup({ success: false, error: 'Connection timeout' });
      }, 15000);

      socket.on('connect', () => {
        // Encrypt the empty params for killSession
        const encryptedParams = encodeBase64(encrypt(key, variant, {}));

        // Use rpc-call with the correct method format: sessionId:methodName
        socket.emit('rpc-call', {
          method: `${sessionId}:killSession`,
          params: encryptedParams
        }, (response: { ok: boolean; result?: string; error?: string }) => {
          clearTimeout(timeout);
          if (response.ok && response.result) {
            // Decrypt the response
            try {
              const decryptedResult = decrypt(key, variant, decodeBase64(response.result)) as { success?: boolean; message?: string };
              if (decryptedResult?.success) {
                cleanup({ success: true });
              } else {
                cleanup({ success: false, error: decryptedResult?.message || 'Failed to archive session' });
              }
            } catch {
              // Even if we can't decrypt, if ok is true, consider it success
              cleanup({ success: true });
            }
          } else {
            cleanup({ success: false, error: response.error || 'RPC call failed' });
          }
        });
      });

      socket.on('connect_error', (error) => {
        clearTimeout(timeout);
        cleanup({ success: false, error: `Connection error: ${error.message}` });
      });

      socket.on('error', (error: { message?: string }) => {
        clearTimeout(timeout);
        cleanup({ success: false, error: `Socket error: ${error.message || String(error)}` });
      });
    });
  }

  /**
   * Start a new session on a machine
   */
  async startSession(
    machineId: string,
    directory: string,
    message?: string,
    agent: 'claude' | 'codex' = 'claude'
  ): Promise<{ success: boolean; sessionId?: string; error?: string }> {
    const { key, variant } = this.getEncryption();

    return new Promise((resolve) => {
      let resolved = false;

      const socket = io(this.serverUrl, {
        auth: {
          token: this.credentials.token,
          clientType: 'user-scoped'
        },
        path: '/v1/updates',
        transports: ['websocket'],
        reconnection: false,
        timeout: 30000
      });

      const cleanup = (result: { success: boolean; sessionId?: string; error?: string }) => {
        if (resolved) return;
        resolved = true;
        socket.disconnect();
        resolve(result);
      };

      const timeout = setTimeout(() => {
        cleanup({ success: false, error: 'Connection timeout' });
      }, 30000);

      socket.on('connect', () => {
        // Encrypt the spawn params
        const spawnParams = {
          type: 'spawn-in-directory',
          directory,
          approvedNewDirectoryCreation: true,
          agent
        };
        const encryptedParams = encodeBase64(encrypt(key, variant, spawnParams));

        // Use rpc-call with the correct method format: machineId:methodName
        socket.emit('rpc-call', {
          method: `${machineId}:spawn-happy-session`,
          params: encryptedParams
        }, async (response: { ok: boolean; result?: string; error?: string }) => {
          clearTimeout(timeout);
          if (response.ok && response.result) {
            // Decrypt the response
            try {
              const decryptedResult = decrypt(key, variant, decodeBase64(response.result)) as { type: string; sessionId?: string; errorMessage?: string };
              if (decryptedResult?.type === 'success' && decryptedResult.sessionId) {
                // If message provided, send it to the new session
                if (message) {
                  const content: UserMessageContent = {
                    role: 'user',
                    content: { type: 'text', text: message },
                    meta: { sentFrom: 'mcp', permissionMode: 'bypassPermissions' }
                  };
                  const encrypted = encodeBase64(encrypt(key, variant, content));
                  socket.emit('message', {
                    sid: decryptedResult.sessionId,
                    message: encrypted,
                    localId: `mcp-${Date.now()}`
                  });
                  // Wait a bit for message to be sent
                  await new Promise(r => setTimeout(r, 500));
                }
                cleanup({ success: true, sessionId: decryptedResult.sessionId });
              } else {
                cleanup({ success: false, error: decryptedResult?.errorMessage || 'Failed to start session' });
              }
            } catch (e) {
              cleanup({ success: false, error: `Failed to decrypt response: ${e}` });
            }
          } else {
            cleanup({ success: false, error: response.error || 'RPC call failed' });
          }
        });
      });

      socket.on('connect_error', (error) => {
        clearTimeout(timeout);
        cleanup({ success: false, error: `Connection error: ${error.message}` });
      });

      socket.on('error', (error: { message?: string }) => {
        clearTimeout(timeout);
        cleanup({ success: false, error: `Socket error: ${error.message || String(error)}` });
      });
    });
  }

  /**
   * Get messages from a session
   */
  async getMessages(sessionId: string, limit: number = 20): Promise<MessageInfo[]> {
    const response = await fetch(`${this.serverUrl}/v1/sessions/${sessionId}/messages`, {
      headers: {
        'Authorization': `Bearer ${this.credentials.token}`,
        'Content-Type': 'application/json'
      }
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch messages: ${response.status} ${response.statusText}`);
    }

    const data = await response.json() as { messages: ApiMessage[] };
    const { key, variant } = this.getEncryption();

    const messages: MessageInfo[] = [];

    // Messages come in reverse order (newest first), we reverse to get oldest first
    const sortedMessages = [...data.messages].reverse().slice(-limit);

    for (const msg of sortedMessages) {
      if (msg.content.t === 'encrypted') {
        const decrypted = this.decryptMessage(msg.content.c, key, variant);
        if (decrypted) {
          let textContent: string | null = null;
          let meta: Record<string, unknown> | undefined;

          if (decrypted.role === 'user') {
            const userMsg = decrypted as UserMessageContent;
            textContent = userMsg.content.text;
            meta = userMsg.meta as Record<string, unknown>;
          } else if (decrypted.role === 'agent') {
            const agentMsg = decrypted as AgentMessageContent;
            // Extract meaningful text from agent messages
            if (agentMsg.content.type === 'output' && agentMsg.content.data) {
              textContent = this.extractAgentText(agentMsg.content.data);
            } else if (agentMsg.content.type === 'event' && agentMsg.content.data) {
              textContent = `[Event: ${JSON.stringify(agentMsg.content.data)}]`;
            }
            meta = agentMsg.meta as Record<string, unknown>;
          }

          messages.push({
            id: msg.id,
            role: decrypted.role,
            content: textContent,
            createdAt: msg.createdAt,
            meta
          });
        }
      }
    }

    return messages;
  }

  /**
   * Extract text from agent message data (Claude output format)
   */
  private extractAgentText(data: unknown): string | null {
    if (!data || typeof data !== 'object') {
      return null;
    }

    // Try to extract from Claude SDK format
    const d = data as Record<string, unknown>;

    // Check for message.content (Claude SDK format)
    if (d.message && typeof d.message === 'object') {
      const message = d.message as Record<string, unknown>;
      if (message.content) {
        if (typeof message.content === 'string') {
          return message.content;
        }
        if (Array.isArray(message.content)) {
          // Extract text blocks from content array
          const texts = message.content
            .filter((c): c is { type: string; text: string } =>
              typeof c === 'object' && c !== null && 'type' in c && (c as Record<string, unknown>).type === 'text' && 'text' in c
            )
            .map(c => c.text);
          if (texts.length > 0) {
            return texts.join('\n');
          }
        }
      }
    }

    // Check for type: 'result' format
    if (d.type === 'result' && d.result) {
      if (typeof d.result === 'string') {
        return d.result;
      }
    }

    // Check for summary
    if (d.type === 'summary' && d.summary) {
      return `[Summary: ${d.summary}]`;
    }

    // Fallback: stringify the data
    return `[Agent output: ${JSON.stringify(d).slice(0, 200)}...]`;
  }

  /**
   * Send a message to a session via WebSocket
   */
  async sendMessage(sessionId: string, text: string): Promise<{ success: boolean; error?: string }> {
    const { key, variant } = this.getEncryption();

    // Create user message content
    const content: UserMessageContent = {
      role: 'user',
      content: {
        type: 'text',
        text
      },
      meta: {
        sentFrom: 'mcp',
        permissionMode: 'bypassPermissions'
      }
    };

    // Encrypt the message
    const encrypted = encodeBase64(encrypt(key, variant, content));

    return new Promise((resolve) => {
      let resolved = false;

      const socket = io(this.serverUrl, {
        auth: {
          token: this.credentials.token,
          clientType: 'user-scoped'
        },
        path: '/v1/updates',
        transports: ['websocket'],
        reconnection: false,
        timeout: 10000
      });

      const cleanup = (result: { success: boolean; error?: string }) => {
        if (resolved) return;
        resolved = true;
        socket.disconnect();
        resolve(result);
      };

      const timeout = setTimeout(() => {
        cleanup({ success: false, error: 'Connection timeout' });
      }, 10000);

      socket.on('connect', () => {
        socket.emit('message', {
          sid: sessionId,
          message: encrypted,
          localId: `mcp-${Date.now()}`
        });

        // Give time for the message to be sent
        setTimeout(() => {
          clearTimeout(timeout);
          cleanup({ success: true });
        }, 1000);
      });

      socket.on('connect_error', (error) => {
        clearTimeout(timeout);
        cleanup({ success: false, error: `Connection error: ${error.message}` });
      });

      socket.on('error', (error: { message?: string }) => {
        clearTimeout(timeout);
        cleanup({ success: false, error: `Socket error: ${error.message || String(error)}` });
      });
    });
  }

  /**
   * Disconnect any active socket connection
   */
  disconnect(): void {
    if (this.socket) {
      this.socket.disconnect();
      this.socket = null;
    }
  }
}
