import {
  validatePattern,
  parsePatternWithCount,
  createPattern,
  matchesPattern,
  calculateDifficulty,
} from '../src/pattern';

describe('Pattern Validation', () => {
  test('accepts valid Base58 characters', () => {
    expect(() => validatePattern('ABC')).not.toThrow();
    expect(() => validatePattern('123')).not.toThrow();
    expect(() => validatePattern('xyz')).not.toThrow();
    expect(() => validatePattern('Sun')).not.toThrow();  // Note: O, I, l, 0 are invalid
  });

  test('accepts wildcards', () => {
    expect(() => validatePattern('A?C')).not.toThrow();
    expect(() => validatePattern('???')).not.toThrow();
  });

  test('rejects invalid Base58 characters', () => {
    expect(() => validatePattern('0')).toThrow(/Invalid character '0'/);
    expect(() => validatePattern('O')).toThrow(/Invalid character 'O'/);
    expect(() => validatePattern('I')).toThrow(/Invalid character 'I'/);
    expect(() => validatePattern('l')).toThrow(/Invalid character 'l'/);
  });

  test('rejects patterns longer than 44 characters', () => {
    const longPattern = 'A'.repeat(45);
    expect(() => validatePattern(longPattern)).toThrow(/too long/);
  });
});

describe('parsePatternWithCount', () => {
  test('parses pattern without count', () => {
    expect(parsePatternWithCount('Sun')).toEqual({ pattern: 'Sun', count: 1 });
    expect(parsePatternWithCount('ABC')).toEqual({ pattern: 'ABC', count: 1 });
  });

  test('parses pattern with count', () => {
    expect(parsePatternWithCount('Sun:5')).toEqual({ pattern: 'Sun', count: 5 });
    expect(parsePatternWithCount('ABC:10')).toEqual({ pattern: 'ABC', count: 10 });
  });

  test('handles invalid count as pattern', () => {
    expect(parsePatternWithCount('Sun:abc')).toEqual({ pattern: 'Sun:abc', count: 1 });
    expect(parsePatternWithCount('Sun:')).toEqual({ pattern: 'Sun:', count: 1 });
  });

  test('handles zero count as invalid', () => {
    expect(parsePatternWithCount('Sun:0')).toEqual({ pattern: 'Sun:0', count: 1 });
  });
});

describe('Pattern Matching', () => {
  test('prefix matching case-insensitive', () => {
    const pattern = createPattern('Sun', { ignoreCase: true, matchMode: 'prefix' });
    expect(matchesPattern('Sunana123', pattern)).toBe(true);
    expect(matchesPattern('sunana123', pattern)).toBe(true);
    expect(matchesPattern('SuNaNa123', pattern)).toBe(true);
    expect(matchesPattern('ABC123', pattern)).toBe(false);
    expect(matchesPattern('xSun123', pattern)).toBe(false);
  });

  test('prefix matching case-sensitive', () => {
    const pattern = createPattern('Sun', { ignoreCase: false, matchMode: 'prefix' });
    expect(matchesPattern('Sunana123', pattern)).toBe(true);
    expect(matchesPattern('sunana123', pattern)).toBe(false);
    expect(matchesPattern('SuNana123', pattern)).toBe(false);
  });

  test('suffix matching', () => {
    const pattern = createPattern('END', { ignoreCase: true, matchMode: 'suffix' });
    expect(matchesPattern('startEND', pattern)).toBe(true);
    expect(matchesPattern('startend', pattern)).toBe(true);
    expect(matchesPattern('ENDstart', pattern)).toBe(false);
  });

  test('anywhere matching', () => {
    const pattern = createPattern('MxD', { ignoreCase: true, matchMode: 'anywhere' });
    expect(matchesPattern('startMxDend', pattern)).toBe(true);
    expect(matchesPattern('MxDstart', pattern)).toBe(true);
    expect(matchesPattern('endMxD', pattern)).toBe(true);
    expect(matchesPattern('nomatch', pattern)).toBe(false);
  });

  test('wildcard matching', () => {
    const pattern = createPattern('A?C', { ignoreCase: true, matchMode: 'prefix' });
    expect(matchesPattern('ABC123', pattern)).toBe(true);
    expect(matchesPattern('AxC123', pattern)).toBe(true);
    expect(matchesPattern('A1C123', pattern)).toBe(true);
    expect(matchesPattern('ABB123', pattern)).toBe(false);
  });
});

describe('Difficulty Calculation', () => {
  test('calculates correct difficulty for case-insensitive', () => {
    const stats = calculateDifficulty('AB', { ignoreCase: true, matchMode: 'prefix' });
    expect(stats.effectiveLength).toBe(2);
    expect(stats.alphabetSize).toBe(34);
    expect(stats.expectedAttempts).toBe(34 * 34); // 1156
  });

  test('calculates correct difficulty for case-sensitive', () => {
    const stats = calculateDifficulty('AB', { ignoreCase: false, matchMode: 'prefix' });
    expect(stats.effectiveLength).toBe(2);
    expect(stats.alphabetSize).toBe(58);
    expect(stats.expectedAttempts).toBe(58 * 58); // 3364
  });

  test('wildcards reduce effective length', () => {
    const stats = calculateDifficulty('A?C', { ignoreCase: true, matchMode: 'prefix' });
    expect(stats.effectiveLength).toBe(2); // Only A and C count
    expect(stats.expectedAttempts).toBe(34 * 34);
  });

  test('p50 is approximately 0.693 * expected', () => {
    const stats = calculateDifficulty('ABC', { ignoreCase: true, matchMode: 'prefix' });
    expect(stats.p50Attempts).toBeCloseTo(stats.expectedAttempts * 0.693, 0);
  });
});
