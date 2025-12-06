import { readFile, stat } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { io, Socket } from 'socket.io-client';
import {
  Credentials,
  CredentialsFileSchema,
  ApiSession,
  ApiMessage,
  SessionMetadata,
  DecryptedSession,
  SessionInfo,
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
        title: metadata?.title ?? null,
        flavor: metadata?.flavor ?? null,
        cwd: metadata?.cwd ?? null,
        active: session.active,
        activeAt: session.activeAt,
        updatedAt: session.updatedAt,
        createdAt: session.createdAt
      });
    }

    return sessions;
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
