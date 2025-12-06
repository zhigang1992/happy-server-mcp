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

// Session metadata
export interface SessionMetadata {
  title?: string;
  summary?: { text: string; updatedAt: number };
  cwd?: string;
  flavor?: 'claude' | 'codex';
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

// Simplified session for MCP tool output
export interface SessionInfo {
  id: string;
  title: string | null;
  flavor: string | null;
  cwd: string | null;
  active: boolean;
  activeAt: number;
  updatedAt: number;
  createdAt: number;
}

// Simplified message for MCP tool output
export interface MessageInfo {
  id: string;
  role: 'user' | 'agent';
  content: string | null;
  createdAt: number;
  meta?: Record<string, unknown>;
}
