export type MatchMode = 'prefix' | 'suffix' | 'anywhere';

export interface PatternOptions {
  ignoreCase: boolean;
  matchMode: MatchMode;
}

export interface Pattern {
  raw: string;
  options: PatternOptions;
}

export interface FoundKey {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  address: string;
  attempts: number;
}

export interface GrinderStats {
  attempts: number;
  rate: number;
  elapsedMs: number;
}

export interface Grinder {
  searchBatch(maxAttempts: number): Promise<FoundKey | null>;
  getStats(): GrinderStats;
  reset(): void;
}

export interface DifficultyStats {
  effectiveLength: number;
  alphabetSize: number;
  expectedAttempts: number;
  p50Attempts: number;
}

export const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
export const INVALID_BASE58_CHARS = ['0', 'O', 'I', 'l'];
