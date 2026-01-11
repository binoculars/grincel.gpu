import { CpuGrinder } from './cpu-grinder';
import { createWebGpuGrinder, WebGpuGrinder } from './webgpu-grinder';
import {
  createPattern,
  parsePatternWithCount,
  calculateDifficulty,
  validatePattern,
} from './pattern';
import { FoundKey, Pattern, Grinder } from './types';
import bs58 from 'bs58';
import * as fs from 'fs';

const BATCH_SIZE = 10_000;

function printUsage(): void {
  console.log('grincel-webgpu - Solana vanity address generator (WebGPU/Node.js)\n');
  console.log('Usage: npx ts-node src/cli.ts <pattern>[:<count>] [options]\n');
  console.log('Options:');
  console.log('  -h, --help            Show help message');
  console.log('  -s, --case-sensitive  Case sensitive matching');
  console.log('  --cpu                 Use CPU only (no WebGPU)');
  console.log('  --prefix              Match at start of address (default)');
  console.log('  --suffix              Match at end of address');
  console.log('  --anywhere            Match anywhere in address');
  console.log('  --benchmark           Run CPU vs WebGPU benchmark');
  console.log('\nPattern syntax:');
  console.log('  PATTERN               Find one match for PATTERN');
  console.log('  PATTERN:N             Find N matches for PATTERN');
  console.log('  ?                     Wildcard (matches any character)');
  console.log('\nValid characters: 1-9, A-H, J-N, P-Z, a-k, m-z (Base58, no 0/O/I/l)');
}

function saveKeyAsJson(found: FoundKey): void {
  const filename = `${found.address}.json`;
  const content = JSON.stringify(Array.from(found.privateKey));
  fs.writeFileSync(filename, content + '\n');
  console.log(`Saved: ${filename}`);
}

function formatDuration(seconds: number): string {
  if (seconds < 1) return '<1 second';
  if (seconds < 60) return `${seconds.toFixed(1)} seconds`;
  if (seconds < 3600) return `${(seconds / 60).toFixed(1)} minutes`;
  if (seconds < 86400) return `${(seconds / 3600).toFixed(1)} hours`;
  return `${(seconds / 86400).toFixed(1)} days`;
}

async function search(
  patternStr: string,
  matchCount: number,
  options: {
    ignoreCase: boolean;
    matchMode: 'prefix' | 'suffix' | 'anywhere';
    useWebGpu: boolean;
  }
): Promise<void> {
  const pattern = createPattern(patternStr, {
    ignoreCase: options.ignoreCase,
    matchMode: options.matchMode,
  });

  console.log('\n=== Solana Vanity Address Search (WebGPU/Node.js) ===');
  console.log(`Pattern: ${patternStr}`);
  console.log(`Match mode: ${options.matchMode}`);
  console.log(`Case sensitive: ${!options.ignoreCase}`);
  if (matchCount > 1) console.log(`Finding: ${matchCount} matches`);
  console.log(`Using: ${options.useWebGpu ? 'WebGPU Hybrid' : 'CPU'}`);

  // Difficulty estimate
  const stats = calculateDifficulty(patternStr, pattern.options);
  console.log('\nDifficulty estimate:');
  console.log(`  Effective pattern length: ${stats.effectiveLength} chars`);
  console.log(
    `  Alphabet size: ${stats.alphabetSize} (${options.ignoreCase ? 'case-insensitive' : 'case-sensitive'})`
  );
  console.log(`  Expected attempts: ${stats.expectedAttempts.toLocaleString()}`);
  console.log(`  P50 attempts (median): ${Math.round(stats.p50Attempts).toLocaleString()}`);

  const estimatedRate = options.useWebGpu ? 5000 : 3000;
  const p50Seconds = stats.p50Attempts / estimatedRate;
  console.log(`  Estimated P50 time: ${formatDuration(p50Seconds)} (at ~${estimatedRate / 1000}k keys/sec)`);
  console.log('');

  // Create grinder
  let grinder: Grinder;
  if (options.useWebGpu) {
    try {
      grinder = await createWebGpuGrinder(pattern);
      console.log('WebGPU initialized successfully');
    } catch (error) {
      console.log(`WebGPU not available: ${(error as Error).message}`);
      console.log('Falling back to CPU...\n');
      grinder = new CpuGrinder(pattern);
    }
  } else {
    grinder = new CpuGrinder(pattern);
  }

  console.log('Searching...');
  let foundCount = 0;
  let lastReportTime = Date.now();

  while (foundCount < matchCount) {
    const found = await grinder.searchBatch(BATCH_SIZE);

    if (found) {
      foundCount++;
      console.log(`\n\n*** FOUND MATCH ${foundCount}/${matchCount}! ***`);
      console.log(`Address: ${found.address}`);
      console.log(`Attempts: ${found.attempts.toLocaleString()}`);
      console.log(`Public Key (hex): ${Buffer.from(found.publicKey).toString('hex')}`);
      console.log(`Public Key (Base58): ${bs58.encode(found.publicKey)}`);
      console.log(`Private Key (Base58): ${bs58.encode(found.privateKey)}`);
      saveKeyAsJson(found);

      if (foundCount < matchCount) {
        console.log('\nContinuing search...');
      }
    }

    // Progress report every second
    if (Date.now() - lastReportTime > 1000) {
      const grinderStats = grinder.getStats();
      const rate = grinderStats.rate / 1000;
      process.stdout.write(
        `\r[${options.useWebGpu ? 'WebGPU' : 'CPU'}] ${grinderStats.attempts.toLocaleString()} keys, ${rate.toFixed(2)} k/s    `
      );
      lastReportTime = Date.now();
    }
  }

  console.log(`\n\nDone! Found ${foundCount} matching address(es).`);

  // Cleanup
  if ('destroy' in grinder) {
    (grinder as WebGpuGrinder).destroy();
  }
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  // Check for help
  if (args.includes('-h') || args.includes('--help') || args.length === 0) {
    printUsage();
    return;
  }

  // Check for benchmark
  if (args.includes('--benchmark')) {
    await import('./benchmark');
    return;
  }

  // Parse pattern
  const patternArg = args.find((arg) => !arg.startsWith('-'));
  if (!patternArg) {
    printUsage();
    return;
  }

  const { pattern: patternStr, count: matchCount } = parsePatternWithCount(patternArg);

  // Validate pattern
  try {
    validatePattern(patternStr);
  } catch (error) {
    console.error((error as Error).message);
    process.exit(1);
  }

  // Parse options
  const ignoreCase = !args.includes('-s') && !args.includes('--case-sensitive');
  const useWebGpu = !args.includes('--cpu');
  let matchMode: 'prefix' | 'suffix' | 'anywhere' = 'prefix';
  if (args.includes('--suffix')) matchMode = 'suffix';
  if (args.includes('--anywhere')) matchMode = 'anywhere';

  await search(patternStr, matchCount, {
    ignoreCase,
    matchMode,
    useWebGpu,
  });
}

main().catch(console.error);
