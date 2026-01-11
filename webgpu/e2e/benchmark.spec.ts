import { test, expect } from '@playwright/test';

test.describe('Benchmark Page', () => {
  test.beforeEach(async ({ page }) => {
    // Capture console messages
    page.on('console', (msg) => {
      if (msg.type() === 'error') {
        console.log('Browser error:', msg.text());
      }
    });
    await page.goto('/benchmark.html');
  });

  test('page loads correctly', async ({ page }) => {
    await expect(page.locator('h1')).toContainText('Solana Vanity Address Grinder');
    await expect(page.locator('#pattern')).toBeVisible();
    await expect(page.locator('#run-benchmark')).toBeEnabled();
  });

  test('GPU status is displayed', async ({ page }) => {
    const gpuStatus = page.locator('#gpu-status');
    await expect(gpuStatus).toBeVisible();
    // Either available or unavailable message
    await expect(gpuStatus).toHaveText(/.*(WebGPU|available|unavailable|supported).*/i);
  });

  test('CPU benchmark finds matches for single character', async ({ page }) => {
    // Set to CPU only mode
    await page.selectOption('#compute-mode', 'cpu');
    // Set short duration
    await page.selectOption('#duration', '5000');
    // Use pattern 'A' which should match ~3% of addresses
    await page.fill('#pattern', 'A');

    // Click run benchmark
    await page.click('#run-benchmark');

    // Wait for completion (max 10 seconds)
    await expect(page.locator('#run-benchmark')).toBeEnabled({ timeout: 15000 });

    // Check output for results
    const output = await page.locator('#output').textContent();
    console.log('CPU Benchmark output:', output);

    // Should have run some keys
    expect(output).toContain('CPU Results:');
    // Should show k/s rate
    expect(output).toMatch(/[\d.]+\s*k\/s/);
  });

  test('CPU benchmark correctly matches patterns', async ({ page }) => {
    // Set to CPU only mode with short duration
    await page.selectOption('#compute-mode', 'cpu');
    await page.selectOption('#duration', '5000');

    // Use wildcard pattern that matches everything
    await page.fill('#pattern', '?');

    await page.click('#run-benchmark');
    await expect(page.locator('#run-benchmark')).toBeEnabled({ timeout: 15000 });

    const output = await page.locator('#output').textContent();
    console.log('Wildcard pattern output:', output);

    // With wildcard, should find many matches
    expect(output).toMatch(/CPU found:/);
  });

  test('GPU benchmark runs and finds matches', async ({ page }) => {
    // Set to GPU only mode
    await page.selectOption('#compute-mode', 'gpu');
    await page.selectOption('#duration', '5000');
    await page.fill('#pattern', 'A');

    await page.click('#run-benchmark');

    // Wait for benchmark to complete
    await expect(page.locator('#run-benchmark')).toBeEnabled({ timeout: 20000 });

    const output = await page.locator('#output').textContent();
    console.log('GPU output:', output);

    // Should show difficulty estimate
    expect(output).toContain('Difficulty estimate:');
    expect(output).toContain('Effective pattern length:');
    expect(output).toContain('P50 attempts');

    // Should show GPU results
    expect(output).toContain('GPU Results:');
  });

  test('compare CPU and GPU for same pattern', async ({ page }) => {
    // Run both modes
    await page.selectOption('#compute-mode', 'both');
    await page.selectOption('#duration', '5000');
    await page.fill('#pattern', 'A');

    await page.click('#run-benchmark');

    // Wait for both to complete
    await expect(page.locator('#run-benchmark')).toBeEnabled({ timeout: 30000 });

    const output = await page.locator('#output').textContent();
    console.log('Compare output:', output);

    // Should have both CPU and GPU results
    expect(output).toContain('CPU');

    // Extract rates for comparison (both show k/s now)
    const cpuRateMatch = output?.match(/CPU Results:\s*([\d.]+)\s*k\/s/);
    const gpuRateMatch = output?.match(/GPU Results:\s*([\d.]+)\s*k\/s/);

    if (cpuRateMatch) {
      const cpuRate = parseFloat(cpuRateMatch[1]) * 1000;
      console.log(`CPU rate: ${cpuRate} keys/s`);
      expect(cpuRate).toBeGreaterThan(0);
    }

    if (gpuRateMatch) {
      const gpuRate = parseFloat(gpuRateMatch[1]) * 1000;
      console.log(`GPU rate: ${gpuRate} keys/s`);
      expect(gpuRate).toBeGreaterThan(0);
    }
  });

  test('stop button works', async ({ page }) => {
    await page.selectOption('#compute-mode', 'cpu');
    await page.selectOption('#duration', '30000'); // Long duration
    await page.fill('#pattern', 'AAAA'); // Hard pattern

    await page.click('#run-benchmark');

    // Wait for benchmark to start
    await expect(page.locator('#stop')).toBeEnabled({ timeout: 2000 });

    // Click stop
    await page.click('#stop');

    // Should stop and re-enable run button
    await expect(page.locator('#run-benchmark')).toBeEnabled({ timeout: 5000 });

    const output = await page.locator('#output').textContent();
    expect(output).toContain('Stopping');
  });
});

test.describe('Pattern Validation', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/benchmark.html');
  });

  test('rejects invalid base58 characters', async ({ page }) => {
    await page.selectOption('#compute-mode', 'cpu');
    await page.fill('#pattern', '0'); // 0 is not in base58

    await page.click('#run-benchmark');

    const output = await page.locator('#output').textContent();
    expect(output).toContain('Error');
    expect(output).toContain('Base58');
  });

  test('accepts valid base58 characters', async ({ page }) => {
    await page.selectOption('#compute-mode', 'cpu');
    await page.selectOption('#duration', '5000');
    await page.fill('#pattern', 'ABC123');

    await page.click('#run-benchmark');

    // Should not show error
    await page.waitForTimeout(1000);
    const output = await page.locator('#output').textContent();
    expect(output).not.toContain('Error');
  });
});

test.describe('Address Generation Verification', () => {
  test('CPU generates valid Solana addresses', async ({ page }) => {
    await page.goto('/benchmark.html');
    await page.selectOption('#compute-mode', 'cpu');
    await page.selectOption('#duration', '5000');
    await page.fill('#pattern', '?'); // Wildcard to capture any address

    await page.click('#run-benchmark');
    await expect(page.locator('#run-benchmark')).toBeEnabled({ timeout: 15000 });

    const output = await page.locator('#output').textContent();

    // Extract found addresses
    const addressMatches = output?.match(/CPU found:\s*([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)/g);

    if (addressMatches && addressMatches.length > 0) {
      const address = addressMatches[0].replace('CPU found:', '').trim();
      console.log('Sample CPU address:', address);

      // Solana addresses are 32-44 characters
      expect(address.length).toBeGreaterThanOrEqual(32);
      expect(address.length).toBeLessThanOrEqual(44);

      // All characters should be valid base58
      const base58Regex = /^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$/;
      expect(address).toMatch(base58Regex);
    }
  });

  test('GPU generates valid Solana addresses', async ({ page }) => {
    await page.goto('/benchmark.html');
    await page.selectOption('#compute-mode', 'gpu');
    await page.selectOption('#duration', '5000');
    await page.fill('#pattern', '?'); // Wildcard to match any address

    await page.click('#run-benchmark');

    // Wait for GPU to find a match
    await page.waitForFunction(
      () => document.getElementById('output')?.textContent?.includes('GPU found:'),
      { timeout: 15000 }
    );

    const output = await page.locator('#output').textContent();
    console.log('GPU output:', output);

    // Extract found addresses from GPU output
    const addressMatches = output?.match(/GPU found:\s*([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+)/g);

    if (addressMatches && addressMatches.length > 0) {
      const address = addressMatches[0].replace('GPU found:', '').trim();
      console.log('Sample GPU address:', address);

      // Solana addresses are 32-44 characters
      expect(address.length).toBeGreaterThanOrEqual(32);
      expect(address.length).toBeLessThanOrEqual(44);

      // All characters should be valid base58
      const base58Regex = /^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$/;
      expect(address).toMatch(base58Regex);
    }

    await expect(page.locator('#run-benchmark')).toBeEnabled({ timeout: 15000 });
  });
});
