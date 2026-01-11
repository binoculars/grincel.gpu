import {
  Pattern,
  PatternOptions,
  DifficultyStats,
  BASE58_ALPHABET,
  INVALID_BASE58_CHARS,
} from './types';

export function validatePattern(patternStr: string): void {
  if (patternStr.length > 44) {
    throw new Error('Pattern too long (max 44 characters)');
  }

  for (let i = 0; i < patternStr.length; i++) {
    const c = patternStr[i];
    if (c === '?') continue; // Wildcard

    if (INVALID_BASE58_CHARS.includes(c)) {
      throw new Error(
        `Invalid character '${c}' at position ${i}. Base58 alphabet does not include: 0, O, I, l`
      );
    }

    if (!BASE58_ALPHABET.includes(c)) {
      throw new Error(`Invalid character '${c}' at position ${i}. Not in Base58 alphabet.`);
    }
  }
}

export function parsePatternWithCount(input: string): { pattern: string; count: number } {
  const lastColon = input.lastIndexOf(':');
  if (lastColon > 0) {
    const countStr = input.slice(lastColon + 1);
    const count = parseInt(countStr, 10);
    if (!isNaN(count) && count > 0) {
      return { pattern: input.slice(0, lastColon), count };
    }
  }
  return { pattern: input, count: 1 };
}

export function createPattern(raw: string, options: Partial<PatternOptions> = {}): Pattern {
  validatePattern(raw);
  return {
    raw,
    options: {
      ignoreCase: options.ignoreCase ?? true,
      matchMode: options.matchMode ?? 'prefix',
    },
  };
}

export function matchesPattern(address: string, pattern: Pattern): boolean {
  const { raw, options } = pattern;
  const { ignoreCase, matchMode } = options;

  const normalizedAddress = ignoreCase ? address.toLowerCase() : address;
  const normalizedPattern = ignoreCase ? raw.toLowerCase() : raw;

  switch (matchMode) {
    case 'prefix':
      return matchesAt(normalizedAddress, normalizedPattern, 0);
    case 'suffix':
      if (address.length < raw.length) return false;
      return matchesAt(normalizedAddress, normalizedPattern, address.length - raw.length);
    case 'anywhere':
      for (let i = 0; i <= address.length - raw.length; i++) {
        if (matchesAt(normalizedAddress, normalizedPattern, i)) return true;
      }
      return false;
  }
}

function matchesAt(address: string, pattern: string, start: number): boolean {
  if (start + pattern.length > address.length) return false;

  for (let i = 0; i < pattern.length; i++) {
    const patternChar = pattern[i];
    if (patternChar === '?') continue; // Wildcard matches any
    if (address[start + i] !== patternChar) return false;
  }
  return true;
}

export function calculateDifficulty(
  patternStr: string,
  options: PatternOptions
): DifficultyStats {
  // Count non-wildcard characters
  let effectiveLength = 0;
  for (const c of patternStr) {
    if (c !== '?') effectiveLength++;
  }

  // Case-insensitive: ~34 unique values, case-sensitive: 58
  const alphabetSize = options.ignoreCase ? 34 : 58;

  let combinations = Math.pow(alphabetSize, effectiveLength);

  // Anywhere match has more positions to match
  if (options.matchMode === 'anywhere' && patternStr.length < 44) {
    const positions = 44 - patternStr.length + 1;
    combinations /= positions;
  }

  const p50Attempts = combinations * 0.693; // ln(2)

  return {
    effectiveLength,
    alphabetSize,
    expectedAttempts: combinations,
    p50Attempts,
  };
}
