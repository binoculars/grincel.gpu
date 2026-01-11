import { formatDuration, printDifficultyEstimate } from '../src/benchmark';
import { calculateDifficulty } from '../src/pattern';
import { PatternOptions } from '../src/types';

describe('Benchmark Utilities', () => {
  describe('formatDuration', () => {
    test('formats sub-second durations', () => {
      expect(formatDuration(0.5)).toBe('<1 second');
      expect(formatDuration(0.001)).toBe('<1 second');
    });

    test('formats seconds', () => {
      expect(formatDuration(1)).toBe('1.0 seconds');
      expect(formatDuration(30)).toBe('30.0 seconds');
      expect(formatDuration(59.9)).toBe('59.9 seconds');
    });

    test('formats minutes', () => {
      expect(formatDuration(60)).toBe('1.0 minutes');
      expect(formatDuration(120)).toBe('2.0 minutes');
      expect(formatDuration(3599)).toBe('60.0 minutes');
    });

    test('formats hours', () => {
      expect(formatDuration(3600)).toBe('1.0 hours');
      expect(formatDuration(7200)).toBe('2.0 hours');
      expect(formatDuration(86399)).toBe('24.0 hours');
    });

    test('formats days', () => {
      expect(formatDuration(86400)).toBe('1.0 days');
      expect(formatDuration(172800)).toBe('2.0 days');
      expect(formatDuration(86400 * 364)).toBe('364.0 days');
    });

    test('formats years', () => {
      expect(formatDuration(86400 * 365)).toBe('1.0 years');
      expect(formatDuration(86400 * 365 * 2)).toBe('2.0 years');
      expect(formatDuration(86400 * 365 * 100)).toBe('100.0 years');
    });
  });

  describe('Difficulty Calculations', () => {
    test('calculates correct difficulty for 1-char case-insensitive', () => {
      const options: PatternOptions = { ignoreCase: true, matchMode: 'prefix' };
      const stats = calculateDifficulty('A', options);
      expect(stats.effectiveLength).toBe(1);
      expect(stats.alphabetSize).toBe(34);
      expect(stats.expectedAttempts).toBe(34);
      expect(stats.p50Attempts).toBeCloseTo(34 * 0.693, 0);
    });

    test('calculates correct difficulty for 2-char case-insensitive', () => {
      const options: PatternOptions = { ignoreCase: true, matchMode: 'prefix' };
      const stats = calculateDifficulty('AB', options);
      expect(stats.effectiveLength).toBe(2);
      expect(stats.alphabetSize).toBe(34);
      expect(stats.expectedAttempts).toBe(34 * 34); // 1156
    });

    test('calculates correct difficulty for 4-char case-insensitive (ZZZZ)', () => {
      const options: PatternOptions = { ignoreCase: true, matchMode: 'prefix' };
      const stats = calculateDifficulty('ZZZZ', options);
      expect(stats.effectiveLength).toBe(4);
      expect(stats.alphabetSize).toBe(34);
      expect(stats.expectedAttempts).toBe(Math.pow(34, 4)); // 1336336
    });

    test('calculates correct difficulty for case-sensitive', () => {
      const options: PatternOptions = { ignoreCase: false, matchMode: 'prefix' };
      const stats = calculateDifficulty('AB', options);
      expect(stats.effectiveLength).toBe(2);
      expect(stats.alphabetSize).toBe(58);
      expect(stats.expectedAttempts).toBe(58 * 58); // 3364
    });

    test('wildcards reduce effective length', () => {
      const options: PatternOptions = { ignoreCase: true, matchMode: 'prefix' };
      const stats = calculateDifficulty('A?B', options);
      expect(stats.effectiveLength).toBe(2); // Only A and B count
    });

    test('anywhere mode reduces expected attempts', () => {
      const optionsPrefix: PatternOptions = { ignoreCase: true, matchMode: 'prefix' };
      const optionsAnywhere: PatternOptions = { ignoreCase: true, matchMode: 'anywhere' };

      const statsPrefix = calculateDifficulty('AB', optionsPrefix);
      const statsAnywhere = calculateDifficulty('AB', optionsAnywhere);

      // Anywhere should have lower expected attempts due to multiple match positions
      expect(statsAnywhere.expectedAttempts).toBeLessThan(statsPrefix.expectedAttempts);
    });
  });

  describe('P50 Time Estimation', () => {
    test('calculates reasonable P50 time for ZZZZ at 10k keys/sec', () => {
      const options: PatternOptions = { ignoreCase: true, matchMode: 'prefix' };
      const stats = calculateDifficulty('ZZZZ', options);
      const rate = 10000; // 10k keys/sec
      const p50Seconds = stats.p50Attempts / rate;

      // ZZZZ: 1336336 expected, P50 ~ 926081
      // At 10k/s: ~93 seconds
      expect(p50Seconds).toBeGreaterThan(80);
      expect(p50Seconds).toBeLessThan(100);
    });

    test('P50 is approximately 69.3% of expected (ln(2))', () => {
      const options: PatternOptions = { ignoreCase: true, matchMode: 'prefix' };
      const stats = calculateDifficulty('ABC', options);
      const ratio = stats.p50Attempts / stats.expectedAttempts;
      expect(ratio).toBeCloseTo(0.693, 2);
    });
  });

  describe('Comparison with Zig Version', () => {
    test('matches Zig difficulty calculation for ZZZZ', () => {
      // From Zig benchmark:
      // Pattern: ZZZZ, case-insensitive
      // Alphabet size: 34
      // Expected: 34^4 = 1336336
      const options: PatternOptions = { ignoreCase: true, matchMode: 'prefix' };
      const stats = calculateDifficulty('ZZZZ', options);

      expect(stats.alphabetSize).toBe(34);
      expect(stats.expectedAttempts).toBe(1336336);
    });

    test('matches Zig difficulty calculation for 2-char case-sensitive', () => {
      // Alphabet size: 58 for case-sensitive
      // Expected: 58^2 = 3364
      const options: PatternOptions = { ignoreCase: false, matchMode: 'prefix' };
      const stats = calculateDifficulty('AB', options);

      expect(stats.alphabetSize).toBe(58);
      expect(stats.expectedAttempts).toBe(3364);
    });
  });
});
