import { CpuGrinder } from '../src/cpu-grinder';
import { createPattern } from '../src/pattern';
import bs58 from 'bs58';

describe('CpuGrinder', () => {
  test('generates valid Solana addresses', async () => {
    // Use a very common pattern that should match quickly
    const pattern = createPattern('1', { ignoreCase: false, matchMode: 'prefix' });
    const grinder = new CpuGrinder(pattern);

    const result = await grinder.searchBatch(100000);

    // Should find at least one match with such a common pattern
    expect(result).not.toBeNull();
    if (result) {
      expect(result.address).toMatch(/^[1-9A-HJ-NP-Za-km-z]+$/);
      expect(result.address.length).toBeGreaterThanOrEqual(32);
      expect(result.address.length).toBeLessThanOrEqual(44);
      expect(result.publicKey.length).toBe(32);
      expect(result.privateKey.length).toBe(64);
    }
  });

  test('public key encodes to address correctly', async () => {
    const pattern = createPattern('A', { ignoreCase: true, matchMode: 'prefix' });
    const grinder = new CpuGrinder(pattern);

    const result = await grinder.searchBatch(100000);

    expect(result).not.toBeNull();
    if (result) {
      // Verify address is Base58 encoding of public key
      const encodedPubKey = bs58.encode(result.publicKey);
      expect(result.address).toBe(encodedPubKey);
    }
  });

  test('private key contains seed and public key', async () => {
    const pattern = createPattern('B', { ignoreCase: true, matchMode: 'prefix' });
    const grinder = new CpuGrinder(pattern);

    const result = await grinder.searchBatch(100000);

    expect(result).not.toBeNull();
    if (result) {
      // Private key should be 64 bytes: 32-byte seed + 32-byte public key
      expect(result.privateKey.length).toBe(64);

      // Last 32 bytes should match public key
      const pubKeyFromPrivate = result.privateKey.slice(32);
      expect(Array.from(pubKeyFromPrivate)).toEqual(Array.from(result.publicKey));
    }
  });

  test('tracks attempts correctly', async () => {
    const pattern = createPattern('ZZZZ', { ignoreCase: true, matchMode: 'prefix' });
    const grinder = new CpuGrinder(pattern);

    await grinder.searchBatch(1000);
    const stats1 = grinder.getStats();
    expect(stats1.attempts).toBe(1000);

    await grinder.searchBatch(500);
    const stats2 = grinder.getStats();
    expect(stats2.attempts).toBe(1500);
  });

  test('reset clears attempts', async () => {
    const pattern = createPattern('ZZZZ', { ignoreCase: true, matchMode: 'prefix' });
    const grinder = new CpuGrinder(pattern);

    await grinder.searchBatch(1000);
    expect(grinder.getStats().attempts).toBe(1000);

    grinder.reset();
    expect(grinder.getStats().attempts).toBe(0);
  });

  test('finds pattern match', async () => {
    const pattern = createPattern('AB', { ignoreCase: true, matchMode: 'prefix' });
    const grinder = new CpuGrinder(pattern);

    const result = await grinder.searchBatch(1000000);

    // AB prefix should be found within 1M attempts (expected ~1156)
    expect(result).not.toBeNull();
    if (result) {
      expect(result.address.toLowerCase().startsWith('ab')).toBe(true);
    }
  });

  test('respects case sensitivity', async () => {
    const pattern = createPattern('AB', { ignoreCase: false, matchMode: 'prefix' });
    const grinder = new CpuGrinder(pattern);

    const result = await grinder.searchBatch(1000000);

    if (result) {
      // Case-sensitive: must start with exactly 'AB'
      expect(result.address.startsWith('AB')).toBe(true);
    }
  });

  test('calculates rate correctly', async () => {
    const pattern = createPattern('ZZZZ', { ignoreCase: true, matchMode: 'prefix' });
    const grinder = new CpuGrinder(pattern);

    // Run for a short time
    const startTime = Date.now();
    await grinder.searchBatch(10000);
    const elapsed = Date.now() - startTime;

    const stats = grinder.getStats();

    // Rate should be approximately attempts / time
    const expectedRate = stats.attempts / (elapsed / 1000);
    expect(stats.rate).toBeGreaterThan(0);
    expect(Math.abs(stats.rate - expectedRate)).toBeLessThan(expectedRate * 0.1); // Within 10%
  });
});
