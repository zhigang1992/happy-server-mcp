import { readFile, stat } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
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
  SessionStatus,
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
  deriveContentKeyPair,
  decryptDataEncryptionKey,
  encryptWithDataKey
} from './encryption.js';

const DEFAULT_SERVER_URL = 'https://happy-server.reily.app';

// For self-hosted setups, you can override via HAPPY_SERVER_URL env var
// Common servers:
// - Production: https://api.cluster-fluster.com
// - Self-hosted example: https://happy-server.reily.app

interface KvItem {
  key: string;
  value: string;
  version: number;
}

interface KvMutation {
  key: string;
  value: string | null;
  version: number;
}

interface KvMutateSuccessResponse {
  success: true;
  results: Array<{ key: string; version: number }>;
}

interface KvMutateErrorResponse {
  success: false;
  errors: Array<{ key: string; error: 'version-mismatch'; version: number; value: string | null }>;
}

type KvMutateResponse = KvMutateSuccessResponse | KvMutateErrorResponse;

interface TodoItem {
  id: string;
  title: string;
  text?: string;
  done: boolean;
  createdAt: number;
  updatedAt: number;
  completedAt?: number;
  linkedSessions?: Record<string, { title: string; linkedAt: number }>;
}

export interface EnvironmentSet {
  id: string;
  name: string;
  variables: Record<string, string>;
  isDefault?: boolean;
}

interface TodoIndex {
  undoneOrder: string[];
  completedOrder: string[];
}

const TODO_PREFIX = 'todo.';
const TODO_INDEX_KEY = 'todo.index';

export class HappyClient {
  private credentials: Credentials;
  private serverUrl: string;
  private socket: Socket | null = null;
  private contentSecretKey: Uint8Array; // For decrypting session data encryption keys
  private sessionEncryptionKeys: Map<string, Uint8Array> = new Map(); // Cache of decrypted session keys

  private constructor(credentials: Credentials, serverUrl: string, contentSecretKey: Uint8Array) {
    this.credentials = credentials;
    this.serverUrl = serverUrl;
    this.contentSecretKey = contentSecretKey;
  }

  /**
   * Create a HappyClient by reading credentials from the standard location
   */
  static async create(serverUrl?: string): Promise<HappyClient> {
    const credentials = await HappyClient.loadCredentials();
    if (!credentials) {
      throw new Error('No Happy credentials found. Please run `happy auth` first.');
    }

    // Derive the content key pair from the master secret for decrypting session data encryption keys
    const masterSecret = credentials.encryption.type === 'legacy'
      ? credentials.encryption.secret
      : credentials.encryption.machineKey;
    const contentKeyPair = deriveContentKeyPair(masterSecret);

    return new HappyClient(credentials, serverUrl ?? DEFAULT_SERVER_URL, contentKeyPair.secretKey);
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

      const legacySecret = parsed.secret ? decodeBase64(parsed.secret) : undefined;

      if (parsed.encryption) {
        return {
          token: parsed.token,
          encryption: {
            type: 'dataKey',
            dataKeySeed: decodeBase64(parsed.encryption.publicKey),
            machineKey: decodeBase64(parsed.encryption.machineKey)
          },
          legacySecret
        };
      }

      if (legacySecret) {
        return {
          token: parsed.token,
          encryption: {
            type: 'legacy',
            secret: legacySecret
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

  private getLegacySecret(): Uint8Array | null {
    if (this.credentials.encryption.type === 'legacy') {
      return this.credentials.encryption.secret;
    }
    return this.credentials.legacySecret ?? null;
  }

  /**
   * Get or fetch the session-specific encryption key
   * Sessions use per-session AES-256 data encryption keys that must be decrypted
   * using the content key pair before use
   */
  private async getSessionEncryptionKey(sessionId: string): Promise<Uint8Array | null> {
    // Check cache first
    const cached = this.sessionEncryptionKeys.get(sessionId);
    if (cached) {
      return cached;
    }

    // Fetch session details to get the dataEncryptionKey
    try {
      const response = await fetch(`${this.serverUrl}/v1/sessions`, {
        headers: {
          'Authorization': `Bearer ${this.credentials.token}`,
          'Content-Type': 'application/json'
        }
      });

      if (!response.ok) {
        console.error(`Failed to fetch sessions: ${response.status}`);
        return null;
      }

      const data = await response.json() as { sessions: ApiSession[] };
      const session = data.sessions.find(s => s.id === sessionId);

      if (!session) {
        console.error(`Session ${sessionId} not found`);
        return null;
      }

      if (!session.dataEncryptionKey) {
        // Session uses legacy encryption, not per-session keys
        // Fall back to the account-level key
        return null;
      }

      // Decrypt the session's data encryption key
      const encryptedKey = decodeBase64(session.dataEncryptionKey);
      const decryptedKey = decryptDataEncryptionKey(encryptedKey, this.contentSecretKey);

      if (!decryptedKey) {
        console.error(`Failed to decrypt data encryption key for session ${sessionId}`);
        return null;
      }

      // Cache the decrypted key
      this.sessionEncryptionKeys.set(sessionId, decryptedKey);
      return decryptedKey;
    } catch (error) {
      console.error(`Error fetching session encryption key: ${error}`);
      return null;
    }
  }

  /**
   * Decrypt session metadata
   */
  private decryptMetadata(encrypted: string, key: Uint8Array, variant: EncryptionVariant): SessionMetadata | null {
    try {
      const decoded = decodeBase64(encrypted);
      const primary = decrypt(key, variant, decoded) as SessionMetadata | null;
      if (primary) {
        return primary;
      }
      const legacySecret = this.getLegacySecret();
      if (legacySecret && variant !== 'legacy') {
        return decrypt(legacySecret, 'legacy', decoded) as SessionMetadata | null;
      }
      return null;
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
      const primary = decrypt(key, variant, decoded) as MessageContent | null;
      if (primary) {
        return primary;
      }
      const legacySecret = this.getLegacySecret();
      if (legacySecret && variant !== 'legacy') {
        return decrypt(legacySecret, 'legacy', decoded) as MessageContent | null;
      }
      return null;
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
   * Get recent paths for a machine
   * Combines paths from settings (recentMachinePaths) and session metadata
   */
  async getRecentPaths(machineId: string, limit: number = 20): Promise<string[]> {
    const { key, variant } = this.getEncryption();
    const pathSet = new Set<string>();
    const paths: string[] = [];

    // First, try to get recentMachinePaths from account settings
    try {
      const settingsResponse = await fetch(`${this.serverUrl}/v1/account/settings`, {
        headers: {
          'Authorization': `Bearer ${this.credentials.token}`,
          'Content-Type': 'application/json'
        }
      });

      if (settingsResponse.ok) {
        const settingsData = await settingsResponse.json() as { settings: string | null };
        if (settingsData.settings) {
          const decryptedSettings = decrypt(key, variant, decodeBase64(settingsData.settings)) as {
            recentMachinePaths?: Array<{ machineId: string; path: string }>;
          } | null;

          if (decryptedSettings?.recentMachinePaths) {
            for (const entry of decryptedSettings.recentMachinePaths) {
              if (entry.machineId === machineId && !pathSet.has(entry.path)) {
                paths.push(entry.path);
                pathSet.add(entry.path);
              }
            }
          }
        }
      }
    } catch {
      // Ignore settings errors, continue with session paths
    }

    // Then add paths from sessions for this machine
    try {
      const sessions = await this.listSessions(100);
      const sessionPaths: Array<{ path: string; activeAt: number }> = [];

      for (const session of sessions) {
        if (session.machineId === machineId && session.path && !pathSet.has(session.path)) {
          pathSet.add(session.path);
          sessionPaths.push({
            path: session.path,
            activeAt: session.activeAt
          });
        }
      }

      // Sort by most recent and add to paths
      sessionPaths
        .sort((a, b) => b.activeAt - a.activeAt)
        .forEach(item => paths.push(item.path));
    } catch {
      // Ignore session errors
    }

    return paths.slice(0, limit);
  }

  /**
   * Get environment variable sets from account settings
   * These are named presets that can be used when starting sessions
   */
  async getEnvironmentSets(): Promise<EnvironmentSet[]> {
    const { key, variant } = this.getEncryption();

    try {
      const settingsResponse = await fetch(`${this.serverUrl}/v1/account/settings`, {
        headers: {
          'Authorization': `Bearer ${this.credentials.token}`,
          'Content-Type': 'application/json'
        }
      });

      if (!settingsResponse.ok) {
        return [];
      }

      const settingsData = await settingsResponse.json() as { settings: string | null };
      if (!settingsData.settings) {
        return [];
      }

      const decryptedSettings = decrypt(key, variant, decodeBase64(settingsData.settings)) as {
        environmentSets?: EnvironmentSet[];
      } | null;

      return decryptedSettings?.environmentSets ?? [];
    } catch {
      return [];
    }
  }

  private getTodoKey(id: string): string {
    return `${TODO_PREFIX}${id}`;
  }

  private encryptTodoData(data: unknown): string {
    const legacySecret = this.getLegacySecret();
    if (!legacySecret) {
      throw new Error('Legacy secret not available; cannot encrypt Zen todos.');
    }
    const encrypted = encrypt(legacySecret, 'legacy', data);
    return encodeBase64(encrypted);
  }

  private decryptTodoData(encrypted: string): unknown | null {
    const legacySecret = this.getLegacySecret();
    if (!legacySecret) {
      return null;
    }
    const decoded = decodeBase64(encrypted);
    return decrypt(legacySecret, 'legacy', decoded);
  }

  async kvGet(key: string): Promise<KvItem | null> {
    const response = await fetch(`${this.serverUrl}/v1/kv/${encodeURIComponent(key)}`, {
      headers: {
        'Authorization': `Bearer ${this.credentials.token}`,
        'Content-Type': 'application/json'
      }
    });

    if (response.status === 404) {
      return null;
    }

    if (!response.ok) {
      throw new Error(`Failed to get KV value: ${response.status} ${response.statusText}`);
    }

    return await response.json() as KvItem;
  }

  async kvList(params: { prefix?: string; limit?: number } = {}): Promise<{ items: KvItem[] }> {
    const queryParams = new URLSearchParams();
    if (params.prefix) {
      queryParams.append('prefix', params.prefix);
    }
    if (params.limit !== undefined) {
      queryParams.append('limit', params.limit.toString());
    }

    const url = queryParams.toString()
      ? `${this.serverUrl}/v1/kv?${queryParams.toString()}`
      : `${this.serverUrl}/v1/kv`;

    const response = await fetch(url, {
      headers: {
        'Authorization': `Bearer ${this.credentials.token}`,
        'Content-Type': 'application/json'
      }
    });

    if (!response.ok) {
      throw new Error(`Failed to list KV items: ${response.status} ${response.statusText}`);
    }

    return await response.json() as { items: KvItem[] };
  }

  async kvBulkGet(keys: string[]): Promise<{ values: KvItem[] }> {
    const response = await fetch(`${this.serverUrl}/v1/kv/bulk`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.credentials.token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ keys })
    });

    if (!response.ok) {
      throw new Error(`Failed to bulk get KV values: ${response.status} ${response.statusText}`);
    }

    return await response.json() as { values: KvItem[] };
  }

  async kvMutate(mutations: KvMutation[]): Promise<KvMutateResponse> {
    const response = await fetch(`${this.serverUrl}/v1/kv`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.credentials.token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ mutations })
    });

    if (response.status === 409) {
      return await response.json() as KvMutateErrorResponse;
    }

    if (!response.ok) {
      throw new Error(`Failed to mutate KV values: ${response.status} ${response.statusText}`);
    }

    return await response.json() as KvMutateSuccessResponse;
  }

  async listTodos(): Promise<{ todos: TodoItem[]; undoneOrder: string[]; doneOrder: string[] }> {
    const response = await this.kvList({ prefix: TODO_PREFIX, limit: 1000 });
    const todoMap = new Map<string, TodoItem>();
    let index: TodoIndex = { undoneOrder: [], completedOrder: [] };

    for (const item of response.items) {
      if (item.key === TODO_INDEX_KEY) {
        const decrypted = this.decryptTodoData(item.value);
        if (decrypted) {
          index = decrypted as TodoIndex;
        }
        continue;
      }

      if (!item.key.startsWith(TODO_PREFIX) || item.key === TODO_INDEX_KEY) {
        continue;
      }

      const decrypted = this.decryptTodoData(item.value);
      if (!decrypted) {
        continue;
      }

      const todoId = item.key.substring(TODO_PREFIX.length);
      if (todoId && todoId !== 'index') {
        todoMap.set(todoId, decrypted as TodoItem);
      }
    }

    const undoneOrder = index.undoneOrder || [];
    const doneOrder = index.completedOrder || [];
    const orderedTodos: TodoItem[] = [];
    const orderedIds = new Set<string>();

    const pushTodo = (id: string) => {
      const todo = todoMap.get(id);
      if (todo) {
        orderedTodos.push(todo);
        orderedIds.add(id);
      }
    };

    for (const id of undoneOrder) {
      pushTodo(id);
    }
    for (const id of doneOrder) {
      pushTodo(id);
    }

    for (const [id, todo] of todoMap.entries()) {
      if (!orderedIds.has(id)) {
        orderedTodos.push(todo);
      }
    }

    return { todos: orderedTodos, undoneOrder, doneOrder };
  }

  async createTodo(title: string, text?: string): Promise<TodoItem> {
    const id = randomUUID();
    const now = Date.now();
    const newTodo: TodoItem = {
      id,
      title,
      text,
      done: false,
      createdAt: now,
      updatedAt: now,
      linkedSessions: {}
    };

    const indexResponse = await this.kvGet(TODO_INDEX_KEY);
    let currentIndex: TodoIndex = { undoneOrder: [], completedOrder: [] };
    let indexVersion = -1;

    if (indexResponse) {
      indexVersion = indexResponse.version;
      const decrypted = this.decryptTodoData(indexResponse.value);
      if (decrypted) {
        currentIndex = decrypted as TodoIndex;
      }
    }

    const mergedIndex: TodoIndex = {
      undoneOrder: (currentIndex.undoneOrder || []).includes(id)
        ? (currentIndex.undoneOrder || [])
        : [...(currentIndex.undoneOrder || []), id],
      completedOrder: (currentIndex.completedOrder || []).filter(tid => tid !== id)
    };

    const mutations: KvMutation[] = [
      {
        key: this.getTodoKey(id),
        value: this.encryptTodoData(newTodo),
        version: -1
      },
      {
        key: TODO_INDEX_KEY,
        value: this.encryptTodoData(mergedIndex),
        version: indexVersion
      }
    ];

    const result = await this.kvMutate(mutations);
    if (result.success === false) {
      const details = result.errors.map(err => `${err.key} (${err.error})`).join(', ');
      throw new Error(`Todo create failed due to version mismatch: ${details}`);
    }

    return newTodo;
  }

  async updateTodo(
    id: string,
    updates: { title?: string; text?: string }
  ): Promise<TodoItem> {
    const todoKey = this.getTodoKey(id);
    const todoResponse = await this.kvGet(todoKey);
    if (!todoResponse) {
      throw new Error(`Todo ${id} not found.`);
    }

    const decrypted = this.decryptTodoData(todoResponse.value);
    if (!decrypted) {
      throw new Error(`Failed to decrypt todo ${id}.`);
    }

    const now = Date.now();
    const updatedTodo: TodoItem = {
      ...(decrypted as TodoItem),
      ...(updates.title !== undefined ? { title: updates.title } : {}),
      ...(updates.text !== undefined ? { text: updates.text } : {}),
      updatedAt: now
    };

    const result = await this.kvMutate([{
      key: todoKey,
      value: this.encryptTodoData(updatedTodo),
      version: todoResponse.version
    }]);

    if (result.success === false) {
      const details = result.errors.map(err => `${err.key} (${err.error})`).join(', ');
      throw new Error(`Todo update failed due to version mismatch: ${details}`);
    }

    return updatedTodo;
  }

  async setTodoDone(id: string, done?: boolean): Promise<TodoItem> {
    const todoKey = this.getTodoKey(id);
    const [todoResponse, indexResponse] = await Promise.all([
      this.kvGet(todoKey),
      this.kvGet(TODO_INDEX_KEY)
    ]);

    if (!todoResponse) {
      throw new Error(`Todo ${id} not found.`);
    }

    const decryptedTodo = this.decryptTodoData(todoResponse.value);
    if (!decryptedTodo) {
      throw new Error(`Failed to decrypt todo ${id}.`);
    }

    let currentIndex: TodoIndex = { undoneOrder: [], completedOrder: [] };
    let indexVersion = -1;

    if (indexResponse) {
      indexVersion = indexResponse.version;
      const decryptedIndex = this.decryptTodoData(indexResponse.value);
      if (decryptedIndex) {
        currentIndex = decryptedIndex as TodoIndex;
      }
    }

    const now = Date.now();
    const todo = decryptedTodo as TodoItem;
    const nextDone = done ?? !todo.done;
    const updatedTodo: TodoItem = {
      ...todo,
      done: nextDone,
      updatedAt: now,
      completedAt: nextDone ? now : undefined
    };

    const newUndoneOrder = (currentIndex.undoneOrder || []).filter(tid => tid !== id);
    const newCompletedOrder = (currentIndex.completedOrder || []).filter(tid => tid !== id);

    if (nextDone) {
      newCompletedOrder.unshift(id);
    } else {
      newUndoneOrder.push(id);
    }

    const mergedIndex: TodoIndex = {
      undoneOrder: newUndoneOrder,
      completedOrder: newCompletedOrder
    };

    const result = await this.kvMutate([
      {
        key: todoKey,
        value: this.encryptTodoData(updatedTodo),
        version: todoResponse.version
      },
      {
        key: TODO_INDEX_KEY,
        value: this.encryptTodoData(mergedIndex),
        version: indexVersion
      }
    ]);

    if (result.success === false) {
      const details = result.errors.map(err => `${err.key} (${err.error})`).join(', ');
      throw new Error(`Todo toggle failed due to version mismatch: ${details}`);
    }

    return updatedTodo;
  }

  async deleteTodo(id: string): Promise<void> {
    const todoKey = this.getTodoKey(id);
    const [todoResponse, indexResponse] = await Promise.all([
      this.kvGet(todoKey),
      this.kvGet(TODO_INDEX_KEY)
    ]);

    if (!todoResponse) {
      throw new Error(`Todo ${id} not found.`);
    }

    let currentIndex: TodoIndex = { undoneOrder: [], completedOrder: [] };
    let indexVersion = -1;

    if (indexResponse) {
      indexVersion = indexResponse.version;
      const decryptedIndex = this.decryptTodoData(indexResponse.value);
      if (decryptedIndex) {
        currentIndex = decryptedIndex as TodoIndex;
      }
    }

    const mergedIndex: TodoIndex = {
      undoneOrder: (currentIndex.undoneOrder || []).filter(tid => tid !== id),
      completedOrder: (currentIndex.completedOrder || []).filter(tid => tid !== id)
    };

    const result = await this.kvMutate([
      {
        key: todoKey,
        value: null,
        version: todoResponse.version
      },
      {
        key: TODO_INDEX_KEY,
        value: this.encryptTodoData(mergedIndex),
        version: indexVersion
      }
    ]);

    if (result.success === false) {
      const details = result.errors.map(err => `${err.key} (${err.error})`).join(', ');
      throw new Error(`Todo delete failed due to version mismatch: ${details}`);
    }
  }

  async linkTodoToSession(
    id: string,
    sessionId: string,
    displayTitle: string
  ): Promise<TodoItem> {
    const todoKey = this.getTodoKey(id);
    const todoResponse = await this.kvGet(todoKey);
    if (!todoResponse) {
      throw new Error(`Todo ${id} not found.`);
    }

    const decrypted = this.decryptTodoData(todoResponse.value);
    if (!decrypted) {
      throw new Error(`Failed to decrypt todo ${id}.`);
    }

    const todo = decrypted as TodoItem;
    const linkedSessions = {
      ...(todo.linkedSessions || {}),
      [sessionId]: {
        title: displayTitle,
        linkedAt: Date.now()
      }
    };

    const updatedTodo: TodoItem = {
      ...todo,
      linkedSessions,
      updatedAt: Date.now()
    };

    const result = await this.kvMutate([{
      key: todoKey,
      value: this.encryptTodoData(updatedTodo),
      version: todoResponse.version
    }]);

    if (result.success === false) {
      const details = result.errors.map(err => `${err.key} (${err.error})`).join(', ');
      throw new Error(`Todo link failed due to version mismatch: ${details}`);
    }

    return updatedTodo;
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
   * @param wait - If true, wait for AI to finish processing initial message
   * @param environmentVariables - Optional environment variables to pass to the session
   */
  async startSession(
    machineId: string,
    directory: string,
    message?: string,
    agent: 'claude' | 'codex' = 'claude',
    wait: boolean = false,
    environmentVariables?: Record<string, string>
  ): Promise<{ success: boolean; sessionId?: string; error?: string }> {
    const { key, variant } = this.getEncryption();

    // Step 1: Spawn the session via RPC
    const spawnResult = await new Promise<{ success: boolean; sessionId?: string; error?: string }>((resolve) => {
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
        const spawnParams: {
          type: 'spawn-in-directory';
          directory: string;
          approvedNewDirectoryCreation: boolean;
          agent: 'claude' | 'codex';
          environmentVariables?: Record<string, string>;
        } = {
          type: 'spawn-in-directory',
          directory,
          approvedNewDirectoryCreation: true,
          agent
        };
        // Only include environmentVariables if provided and non-empty
        if (environmentVariables && Object.keys(environmentVariables).length > 0) {
          spawnParams.environmentVariables = environmentVariables;
        }
        const encryptedParams = encodeBase64(encrypt(key, variant, spawnParams));

        // Use rpc-call with the correct method format: machineId:methodName
        socket.emit('rpc-call', {
          method: `${machineId}:spawn-happy-session`,
          params: encryptedParams
        }, (response: { ok: boolean; result?: string; error?: string }) => {
          clearTimeout(timeout);
          if (response.ok && response.result) {
            // Decrypt the response
            try {
              const decryptedResult = decrypt(key, variant, decodeBase64(response.result)) as { type: string; sessionId?: string; errorMessage?: string };
              if (decryptedResult?.type === 'success' && decryptedResult.sessionId) {
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

    if (!spawnResult.success || !spawnResult.sessionId) {
      return spawnResult;
    }

    // Step 2: Wait for session to become active (give CLI time to connect)
    // Poll the sessions API until we see this session as active
    const sessionId = spawnResult.sessionId;
    let sessionActive = false;
    const maxWaitTime = 15000;
    const startTime = Date.now();

    while (!sessionActive && (Date.now() - startTime) < maxWaitTime) {
      await new Promise(r => setTimeout(r, 1000));
      try {
        const sessions = await this.listSessions(100);
        const session = sessions.find(s => s.id === sessionId);
        if (session?.active) {
          sessionActive = true;
        }
      } catch {
        // Ignore errors, keep polling
      }
    }

    if (!sessionActive) {
      return { success: true, sessionId, error: 'Session spawned but may not be ready yet' };
    }

    // Step 3: If message provided, send it
    if (message) {
      const sendResult = await this.sendMessage(sessionId, message);
      if (!sendResult.success) {
        return { success: true, sessionId, error: `Session started but message failed: ${sendResult.error}` };
      }

      // Step 4: If wait=true, wait for AI to finish
      if (wait) {
        const idleResult = await this.waitForIdle(sessionId);
        if (!idleResult.success) {
          return { success: true, sessionId, error: `Session started but wait for idle failed: ${idleResult.error}` };
        }
      }
    }

    return { success: true, sessionId };
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
   * @param wait - If true, wait for AI to finish processing the message
   */
  async sendMessage(sessionId: string, text: string, wait: boolean = false): Promise<{ success: boolean; error?: string }> {
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

    // Get session-specific encryption key (per-session AES-256)
    // If not available, fall back to legacy/account-level encryption
    const sessionKey = await this.getSessionEncryptionKey(sessionId);
    let encrypted: string;
    if (sessionKey) {
      // Use per-session AES-256-GCM encryption (this is what the frontend uses)
      encrypted = encodeBase64(encryptWithDataKey(content, sessionKey));
    } else {
      // Fall back to legacy encryption
      const { key, variant } = this.getEncryption();
      encrypted = encodeBase64(encrypt(key, variant, content));
    }

    const sendResult = await new Promise<{ success: boolean; error?: string }>((resolve) => {
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

    if (!sendResult.success) {
      return sendResult;
    }

    // If wait=true, wait for AI to finish processing
    if (wait) {
      const idleResult = await this.waitForIdle(sessionId);
      if (!idleResult.success) {
        return { success: true, error: `Message sent but wait for idle failed: ${idleResult.error}` };
      }
    }

    return { success: true };
  }

  /**
   * Watch session status via WebSocket ephemeral updates
   * Returns when the session reaches the target status or timeout
   */
  async waitForSessionStatus(
    sessionId: string,
    targetStatus: 'online' | 'thinking',
    timeoutMs: number = 60000
  ): Promise<{ success: boolean; status?: SessionStatus; error?: string }> {
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
        timeout: timeoutMs
      });

      const cleanup = (result: { success: boolean; status?: SessionStatus; error?: string }) => {
        if (resolved) return;
        resolved = true;
        socket.disconnect();
        resolve(result);
      };

      const timeout = setTimeout(() => {
        cleanup({ success: false, error: `Timeout waiting for session to become ${targetStatus}` });
      }, timeoutMs);

      socket.on('connect', () => {
        // Listen for ephemeral updates
        socket.on('ephemeral', (update: { type: string; id: string; active?: boolean; thinking?: boolean }) => {
          if (update.type === 'activity' && update.id === sessionId) {
            const status: SessionStatus = !update.active ? 'offline' : (update.thinking ? 'thinking' : 'online');

            if (targetStatus === 'online' && status === 'online') {
              clearTimeout(timeout);
              cleanup({ success: true, status: 'online' });
            } else if (targetStatus === 'thinking' && status === 'thinking') {
              clearTimeout(timeout);
              cleanup({ success: true, status: 'thinking' });
            }
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
   * Wait for a session to become idle (online but not thinking)
   * Useful after sending a message to wait for AI to finish processing
   * If session is already idle, returns immediately
   */
  async waitForIdle(
    sessionId: string,
    timeoutMs: number = 120000
  ): Promise<{ success: boolean; error?: string }> {
    // First, check current session state via API
    // If already idle, return immediately without waiting for ephemeral updates
    try {
      const sessions = await this.listSessions(100);
      const session = sessions.find(s => s.id === sessionId);
      // Note: We can't know 'thinking' state from API, but if session is not active,
      // we know it's definitely not processing. If active, we need to wait for ephemeral.
      if (session && !session.active) {
        // Session is offline/inactive, consider it idle
        return { success: true };
      }
    } catch {
      // Ignore API errors, proceed with WebSocket
    }

    return new Promise((resolve) => {
      let resolved = false;
      let sawThinking = false;
      let checkedInitialState = false;

      const socket = io(this.serverUrl, {
        auth: {
          token: this.credentials.token,
          clientType: 'user-scoped'
        },
        path: '/v1/updates',
        transports: ['websocket'],
        reconnection: false,
        timeout: timeoutMs
      });

      const cleanup = (result: { success: boolean; error?: string }) => {
        if (resolved) return;
        resolved = true;
        socket.disconnect();
        resolve(result);
      };

      const timeout = setTimeout(() => {
        cleanup({ success: false, error: 'Timeout waiting for session to become idle' });
      }, timeoutMs);

      socket.on('connect', () => {
        // Set a grace period - if we don't receive any 'thinking' update within 3 seconds,
        // assume the session is already idle (no activity happening)
        const graceTimeout = setTimeout(() => {
          if (!sawThinking) {
            // No thinking update received, assume already idle
            clearTimeout(timeout);
            cleanup({ success: true });
          }
        }, 3000);

        // Listen for ephemeral updates
        socket.on('ephemeral', (update: { type: string; id: string; active?: boolean; thinking?: boolean }) => {
          if (update.type === 'activity' && update.id === sessionId) {
            // On first update for this session, check if already idle
            if (!checkedInitialState) {
              checkedInitialState = true;
              clearTimeout(graceTimeout);
              if (update.active && !update.thinking) {
                // Already idle, return immediately
                clearTimeout(timeout);
                cleanup({ success: true });
                return;
              }
            }

            if (update.thinking) {
              sawThinking = true;
              clearTimeout(graceTimeout);
            } else if (update.active && sawThinking) {
              // Session was thinking and is now online (idle)
              clearTimeout(timeout);
              cleanup({ success: true });
            }
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
   * Disconnect any active socket connection
   */
  disconnect(): void {
    if (this.socket) {
      this.socket.disconnect();
      this.socket = null;
    }
  }
}
