import { z } from 'zod';

// Credentials schema matching happy-cli
export const CredentialsFileSchema = z.object({
  token: z.string(),
  secret: z.string().nullish(), // Legacy
  encryption: z.object({
    publicKey: z.string(),  // Actually a seed (legacy naming)
    machineKey: z.string()
  }).nullish()
});

export type CredentialsFile = z.infer<typeof CredentialsFileSchema>;

export interface Credentials {
  token: string;
  encryption: {
    type: 'legacy';
    secret: Uint8Array;
  } | {
    type: 'dataKey';
    dataKeySeed: Uint8Array;
    machineKey: Uint8Array;
  };
}

// Session metadata (matches MetadataSchema from Happy app)
export interface SessionMetadata {
  path: string;
  host: string;
  version?: string;
  name?: string;
  os?: string;
  summary?: { text: string; updatedAt: number };
  machineId?: string;
  claudeSessionId?: string;
  tools?: string[];
  slashCommands?: string[];
  homeDir?: string;
  happyHomeDir?: string;
  hostPid?: number;
  flavor?: string;
  permissionMode?: 'default' | 'acceptEdits' | 'bypassPermissions' | 'plan';
  [key: string]: unknown;
}

// API response types
export interface ApiSession {
  id: string;
  seq: number;
  createdAt: number;
  updatedAt: number;
  active: boolean;
  activeAt: number;
  metadata: string; // encrypted
  metadataVersion: number;
  agentState: string | null; // encrypted
  agentStateVersion: number;
  dataEncryptionKey: string | null;
}

export interface ApiMessage {
  id: string;
  seq: number;
  localId: string | null;
  content: {
    t: 'encrypted';
    c: string; // Base64 encoded encrypted content
  };
  createdAt: number;
  updatedAt?: number;
}

// Decrypted message content
export interface UserMessageContent {
  role: 'user';
  content: {
    type: 'text';
    text: string;
  };
  meta?: {
    sentFrom?: string;
    permissionMode?: string;
    displayText?: string;
  };
}

export interface AgentMessageContent {
  role: 'agent';
  content: {
    type: 'output' | 'codex' | 'event';
    data?: unknown;
    id?: string;
  };
  meta?: {
    sentFrom?: string;
  };
}

export type MessageContent = UserMessageContent | AgentMessageContent;

// Decrypted session for internal use
export interface DecryptedSession {
  id: string;
  seq: number;
  createdAt: number;
  updatedAt: number;
  active: boolean;
  activeAt: number;
  metadata: SessionMetadata | null;
  encryptionKey: Uint8Array;
  encryptionVariant: 'legacy' | 'dataKey';
}

// Session status - matches the UI indicators
export type SessionStatus = 'offline' | 'online' | 'thinking';

// Simplified session for MCP tool output
export interface SessionInfo {
  id: string;
  title: string | null;
  path: string | null;
  host: string | null;
  machineId: string | null;
  flavor: string | null;
  active: boolean;
  activeAt: number;
  updatedAt: number;
  createdAt: number;
  // Status from ephemeral updates - only available via WebSocket
  status?: SessionStatus;
}

// Machine metadata (matches MachineMetadataSchema from Happy app)
export interface MachineMetadata {
  host: string;
  platform: string;
  happyCliVersion: string;
  happyHomeDir: string;
  homeDir: string;
  username?: string;
  arch?: string;
  displayName?: string;
  daemonLastKnownStatus?: 'running' | 'shutting-down';
  daemonLastKnownPid?: number;
  shutdownRequestedAt?: number;
  shutdownSource?: 'happy-app' | 'happy-cli' | 'os-signal' | 'unknown';
}

// API machine response
export interface ApiMachine {
  id: string;
  seq: number;
  createdAt: number;
  updatedAt: number;
  active: boolean;
  activeAt: number;
  metadata: string; // encrypted
  metadataVersion: number;
  daemonState: string | null;
  daemonStateVersion: number;
}

// Simplified machine for MCP tool output
export interface MachineInfo {
  id: string;
  host: string | null;
  displayName: string | null;
  platform: string | null;
  homeDir: string | null;
  active: boolean;
  activeAt: number;
}

// Simplified message for MCP tool output
export interface MessageInfo {
  id: string;
  role: 'user' | 'agent';
  content: string | null;
  createdAt: number;
  meta?: Record<string, unknown>;
}
