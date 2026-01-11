// Shared GPU buffer utilities for WebGPU grinders
import { Pattern, FoundKey } from './types';

// Buffer layout sizes (aligned for WebGPU)
export const RESULT_BUFFER_SIZE = 256;
export const PARAMS_BUFFER_SIZE = 16;
export const PATTERN_BUFFER_SIZE = 48; // PatternConfig struct: 4 u32s + 2 vec4<u32>

export const WORKGROUP_SIZE = 64;

/**
 * Creates pattern config data for GPU buffer.
 * PatternConfig layout:
 *   length: u32 (offset 0)
 *   match_mode: u32 (offset 4) - 0=prefix, 1=suffix, 2=anywhere
 *   ignore_case: u32 (offset 8)
 *   pad: u32 (offset 12)
 *   pattern0: vec4<u32> (offset 16, 16 bytes for chars 0-15)
 *   pattern1: vec4<u32> (offset 32, 16 bytes for chars 16-31)
 */
export function createPatternConfig(pattern: Pattern): Uint32Array {
  const patternStr = pattern.raw;
  const config = new Uint32Array(12); // 48 bytes

  config[0] = patternStr.length;
  config[1] = pattern.options.matchMode === 'prefix' ? 0 :
              pattern.options.matchMode === 'suffix' ? 1 : 2;
  config[2] = pattern.options.ignoreCase ? 1 : 0;
  config[3] = 0; // pad

  // Pack pattern string as bytes into u32 array (indices 4-11)
  for (let i = 0; i < patternStr.length && i < 32; i++) {
    const wordIndex = 4 + Math.floor(i / 4);
    const byteOffset = (i % 4) * 8;
    config[wordIndex] |= patternStr.charCodeAt(i) << byteOffset;
  }

  return config;
}

/**
 * Creates pattern config from raw parameters (for browser GpuGrinder).
 */
export function createPatternConfigRaw(
  patternStr: string,
  matchMode: string,
  ignoreCase: boolean
): Uint32Array {
  const config = new Uint32Array(12);

  config[0] = patternStr.length;
  config[1] = matchMode === 'prefix' ? 0 : matchMode === 'suffix' ? 1 : 2;
  config[2] = ignoreCase ? 1 : 0;
  config[3] = 0;

  for (let i = 0; i < patternStr.length && i < 32; i++) {
    const wordIndex = 4 + Math.floor(i / 4);
    const byteOffset = (i % 4) * 8;
    config[wordIndex] |= patternStr.charCodeAt(i) << byteOffset;
  }

  return config;
}

/**
 * Parses GPU result buffer to extract FoundKey.
 * ResultBuffer layout:
 *   found: u32 (offset 0) - atomic flag
 *   thread_id: u32 (offset 4)
 *   address_len: u32 (offset 8)
 *   pad: u32 (offset 12)
 *   public_key: array<u32, 8> (offset 16, 32 bytes)
 *   private_key: array<u32, 16> (offset 48, 64 bytes)
 *   address: array<u32, 12> (offset 112, 48 bytes)
 *
 * Returns null if no match found (found flag is 0).
 */
export function parseResultBuffer(data: Uint32Array, attempts: number): FoundKey | null {
  if (data[0] === 0) {
    return null;
  }

  const addressLen = data[2];

  // Extract public key (32 bytes from offset 16 = index 4)
  const publicKey = new Uint8Array(32);
  for (let i = 0; i < 8; i++) {
    const word = data[4 + i];
    publicKey[i * 4] = word & 0xff;
    publicKey[i * 4 + 1] = (word >> 8) & 0xff;
    publicKey[i * 4 + 2] = (word >> 16) & 0xff;
    publicKey[i * 4 + 3] = (word >> 24) & 0xff;
  }

  // Extract private key (64 bytes from offset 48 = index 12)
  const privateKey = new Uint8Array(64);
  for (let i = 0; i < 16; i++) {
    const word = data[12 + i];
    privateKey[i * 4] = word & 0xff;
    privateKey[i * 4 + 1] = (word >> 8) & 0xff;
    privateKey[i * 4 + 2] = (word >> 16) & 0xff;
    privateKey[i * 4 + 3] = (word >> 24) & 0xff;
  }

  // Extract address string (from offset 112 = index 28)
  let address = '';
  for (let i = 0; i < addressLen; i++) {
    const wordIndex = 28 + Math.floor(i / 4);
    const byteOffset = (i % 4) * 8;
    address += String.fromCharCode((data[wordIndex] >> byteOffset) & 0xff);
  }

  return {
    publicKey,
    privateKey,
    address,
    attempts,
  };
}
