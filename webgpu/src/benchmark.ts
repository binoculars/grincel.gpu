import { CpuGrinder } from './cpu-grinder';
import { createWebGpuGrinder, WebGpuGrinder } from './webgpu-grinder';
import { createPattern, calculateDifficulty } from './pattern';
import { PatternOptions, DifficultyStats } from './types';

const BENCHMARK_DURATION_MS = 10_000; // 10 seconds per benchmark
const BATCH_SIZE = 10_000;

function formatDuration(seconds: number): string {
  if (seconds < 1) {
    return '<1 second';
  } else if (seconds < 60) {
    return `${seconds.toFixed(1)} seconds`;
  } else if (seconds < 3600) {
    return `${(seconds / 60).toFixed(1)} minutes`;
  } else if (seconds < 86400) {
    return `${(seconds / 3600).toFixed(1)} hours`;
  } else if (seconds < 86400 * 365) {
    return `${(seconds / 86400).toFixed(1)} days`;
  } else {
    return `${(seconds / (86400 * 365)).toFixed(1)} years`;
  }
}

function printDifficultyEstimate(
  patternStr: string,
  options: PatternOptions,
  estimatedRate: number
): DifficultyStats {
  const stats = calculateDifficulty(patternStr, options);

  console.log('\nDifficulty estimate:');
  console.log(`  Effective pattern length: ${stats.effectiveLength} chars`);
  console.log(
    `  Alphabet size: ${stats.alphabetSize} (${options.ignoreCase ? 'case-insensitive' : 'case-sensitive'})`
  );
  console.log(`  Probability per attempt: 1 in ${stats.expectedAttempts.toFixed(0)}`);
  console.log(`  Expected attempts (mean): ${stats.expectedAttempts.toFixed(0)}`);
  console.log(`  P50 attempts (median): ${stats.p50Attempts.toFixed(0)}`);

  const p50Seconds = stats.p50Attempts / estimatedRate;
  console.log(
    `  Estimated P50 time: ${formatDuration(p50Seconds)} (at ~${(estimatedRate / 1000).toFixed(0)}k keys/sec)`
  );

  return stats;
}

interface BenchmarkResult {
  name: string;
  rate: number; // keys per second
  attempts: number;
  elapsed: number; // seconds
}

async function runBenchmark(): Promise<void> {
  console.log('\n=== Vanity Address Grinder Benchmark (WebGPU/TypeScript) ===');
  console.log(`Running each mode for ${BENCHMARK_DURATION_MS / 1000} seconds...\n`);

  const patternStr = 'ZZZZ';
  const patternOptions: PatternOptions = { ignoreCase: true, matchMode: 'prefix' };
  const pattern = createPattern(patternStr, patternOptions);

  const results: BenchmarkResult[] = [];

  // CPU Benchmark
  console.log('CPU benchmark (using Web Crypto Ed25519)...');
  const cpuGrinder = new CpuGrinder(pattern);
  const cpuStart = Date.now();

  while (Date.now() - cpuStart < BENCHMARK_DURATION_MS) {
    const found = await cpuGrinder.searchBatch(BATCH_SIZE);
    if (found) {
      // Match found during benchmark, continue anyway
    }
  }

  const cpuElapsed = (Date.now() - cpuStart) / 1000;
  const cpuStats = cpuGrinder.getStats();
  const cpuRate = cpuStats.attempts / cpuElapsed;
  results.push({
    name: 'CPU',
    rate: cpuRate,
    attempts: cpuStats.attempts,
    elapsed: cpuElapsed,
  });
  console.log(`  CPU: ${(cpuRate / 1000).toFixed(2)} k/s`);

  // WebGPU Hybrid Benchmark
  let webgpuGrinder: WebGpuGrinder | null = null;

  try {
    console.log('WebGPU Hybrid benchmark (GPU seeds + CPU crypto)...');
    webgpuGrinder = await createWebGpuGrinder(pattern);
    const webgpuStart = Date.now();

    while (Date.now() - webgpuStart < BENCHMARK_DURATION_MS) {
      const found = await webgpuGrinder.searchBatch(BATCH_SIZE);
      if (found) {
        // Match found during benchmark, continue anyway
      }
    }

    const webgpuElapsed = (Date.now() - webgpuStart) / 1000;
    const webgpuStats = webgpuGrinder.getStats();
    const webgpuRate = webgpuStats.attempts / webgpuElapsed;
    results.push({
      name: 'WebGPU Hybrid',
      rate: webgpuRate,
      attempts: webgpuStats.attempts,
      elapsed: webgpuElapsed,
    });
    console.log(`  WebGPU Hybrid: ${(webgpuRate / 1000).toFixed(2)} k/s`);
  } catch (error) {
    console.log(`  WebGPU not available: ${(error as Error).message}`);
  }

  // Results Summary
  console.log('\n=== Results ===');

  const cpuResult = results.find((r) => r.name === 'CPU')!;
  const baselineRate = cpuResult.rate;

  console.log(`CPU:           ${(cpuResult.rate / 1000).toFixed(2)} k/s (baseline)`);

  for (const result of results) {
    if (result.name !== 'CPU') {
      const speedup = result.rate / baselineRate;
      const speedupStr = speedup >= 1 ? 'faster' : 'slower';
      console.log(
        `${result.name.padEnd(14)} ${(result.rate / 1000).toFixed(2)} k/s (${speedup.toFixed(1)}x ${speedupStr})`
      );
    }
  }

  // Determine fastest
  const fastest = results.reduce((a, b) => (a.rate > b.rate ? a : b));
  console.log(`\n${fastest.name} mode is fastest!`);

  // Show difficulty estimate for the benchmark pattern
  console.log('\n--- Pattern Difficulty Analysis ---');
  console.log(`Pattern: ${patternStr}`);
  console.log(`Match mode: ${patternOptions.matchMode}`);
  console.log(`Case sensitive: ${!patternOptions.ignoreCase}`);
  printDifficultyEstimate(patternStr, patternOptions, fastest.rate);

  // Cleanup
  webgpuGrinder?.destroy();

  console.log('\nNote: WebGPU hybrid uses GPU for parallel seed generation,');
  console.log('      CPU for Ed25519 derivation (using Web Crypto API).');
}

// CLI entry point
async function main(): Promise<void> {
  const args = process.argv.slice(2);

  if (args.includes('--help') || args.includes('-h')) {
    console.log('grincel-webgpu - Solana vanity address grinder with WebGPU acceleration\n');
    console.log('Usage: npx ts-node src/benchmark.ts [options]\n');
    console.log('Options:');
    console.log('  -h, --help      Show this help message');
    console.log('  --benchmark     Run benchmark (default)');
    console.log('\nThis benchmark compares:');
    console.log('  - CPU: Pure JavaScript/TypeScript using Web Crypto Ed25519');
    console.log('  - WebGPU Hybrid: GPU seed generation + CPU Ed25519 derivation');
    return;
  }

  await runBenchmark();
}

// Run if called directly
main().catch(console.error);

export { runBenchmark, formatDuration, printDifficultyEstimate };
