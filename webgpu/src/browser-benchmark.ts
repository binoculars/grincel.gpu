// Browser benchmark for Solana vanity address grinder
// This file is compiled and bundled for browser use

import WGSL_SHADER from './shaders/vanity.wgsl?raw';
import {
  Pattern,
  FoundKey,
  GrinderStats,
  Grinder,
  DifficultyStats,
  MatchMode,
  BASE58_ALPHABET,
} from './types';
import {
  createPattern,
  matchesPattern,
  calculateDifficulty,
} from './pattern';
import {
  RESULT_BUFFER_SIZE,
  PARAMS_BUFFER_SIZE,
  PATTERN_BUFFER_SIZE,
  WORKGROUP_SIZE,
  createPatternConfigRaw,
  parseResultBuffer,
} from './gpu-utils';

// Default GPU batch size (can be changed via UI)
const DEFAULT_GPU_BATCH_SIZE = 96000;
const MIN_BATCH_SIZE = 64;
const MAX_BATCH_SIZE = 262144; // 256K

// Get GPU batch size from UI or use default
function getGpuBatchSize(): number {
  const input = document.getElementById('batch-size') as HTMLInputElement | null;
  if (!input) return DEFAULT_GPU_BATCH_SIZE;

  const value = parseInt(input.value, 10);
  if (isNaN(value) || value < MIN_BATCH_SIZE) return MIN_BATCH_SIZE;
  if (value > MAX_BATCH_SIZE) return MAX_BATCH_SIZE;
  return value;
}

// Base58 encode for browser
function base58Encode(bytes: Uint8Array): string {
  const digits = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let result = '';
  for (const byte of bytes) {
    if (byte === 0) result += '1';
    else break;
  }
  for (let i = digits.length - 1; i >= 0; i--) {
    result += BASE58_ALPHABET[digits[i]];
  }
  return result;
}



function formatDifficultyInfo(diff: DifficultyStats, ignoreCase: boolean): string {
  const lines: string[] = [];
  lines.push(`Difficulty estimate:`);
  lines.push(`  Effective pattern length: ${diff.effectiveLength} chars`);
  lines.push(`  Alphabet size: ${diff.alphabetSize} (${ignoreCase ? 'case-insensitive' : 'case-sensitive'})`);
  lines.push(`  Probability per attempt: 1 in ${formatNum(diff.expectedAttempts)}`);
  lines.push(`  Expected attempts (mean): ${formatNum(diff.expectedAttempts)}`);
  lines.push(`  P50 attempts (median): ${formatNum(diff.p50Attempts)}`);
  return lines.join('\n');
}

function formatDuration(s: number): string {
  if (s < 1) return '<1 sec';
  if (s < 60) return s.toFixed(1) + ' sec';
  if (s < 3600) return (s / 60).toFixed(1) + ' min';
  if (s < 86400) return (s / 3600).toFixed(1) + ' hr';
  return (s / 86400).toFixed(1) + ' days';
}

function formatNum(n: number): string {
  if (n >= 1e9) return (n / 1e9).toFixed(2) + 'B';
  if (n >= 1e6) return (n / 1e6).toFixed(2) + 'M';
  if (n >= 1e3) return (n / 1e3).toFixed(2) + 'K';
  return n.toFixed(0);
}

class GpuGrinder implements Grinder {
  private device: GPUDevice;
  private patternStr: string;
  private matchMode: string;
  private ignoreCase: boolean;
  public attempts: number = 0;
  private startTime: number = Date.now();
  public batchOffset: number = 0;
  private destroyed: boolean = false;

  private shaderModule!: GPUShaderModule;
  private pipeline!: GPUComputePipeline;
  private resultBuffer!: GPUBuffer;
  private resultReadBuffer!: GPUBuffer;
  private paramsBuffer!: GPUBuffer;
  private patternBuffer!: GPUBuffer;
  private bindGroup!: GPUBindGroup;

  private constructor(device: GPUDevice, patternStr: string, matchMode: string, ignoreCase: boolean) {
    this.device = device;
    this.patternStr = patternStr;
    this.matchMode = matchMode;
    this.ignoreCase = ignoreCase;
  }

  static async create(
    device: GPUDevice,
    patternStr: string,
    matchMode: string,
    ignoreCase: boolean
  ): Promise<GpuGrinder> {
    const grinder = new GpuGrinder(device, patternStr, matchMode, ignoreCase);
    await grinder.setupPipeline();
    return grinder;
  }

  private async setupPipeline(): Promise<void> {
    this.shaderModule = this.device.createShaderModule({ code: WGSL_SHADER });

    // Check for shader compilation errors
    const info = await this.shaderModule.getCompilationInfo();
    for (const msg of info.messages) {
      if (msg.type === 'error') {
        throw new Error(`Shader compilation error at line ${msg.lineNum}: ${msg.message}`);
      }
    }

    this.pipeline = this.device.createComputePipeline({
      layout: 'auto',
      compute: { module: this.shaderModule, entryPoint: 'main' },
    });

    this.resultBuffer = this.device.createBuffer({
      size: RESULT_BUFFER_SIZE,
      usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_SRC | GPUBufferUsage.COPY_DST,
    });
    this.resultReadBuffer = this.device.createBuffer({
      size: RESULT_BUFFER_SIZE,
      usage: GPUBufferUsage.MAP_READ | GPUBufferUsage.COPY_DST,
    });
    this.paramsBuffer = this.device.createBuffer({
      size: PARAMS_BUFFER_SIZE,
      usage: GPUBufferUsage.UNIFORM | GPUBufferUsage.COPY_DST,
    });
    this.patternBuffer = this.device.createBuffer({
      size: PATTERN_BUFFER_SIZE,
      usage: GPUBufferUsage.UNIFORM | GPUBufferUsage.COPY_DST,
    });

    const patternData = createPatternConfigRaw(this.patternStr, this.matchMode, this.ignoreCase);
    this.device.queue.writeBuffer(this.patternBuffer, 0, patternData.buffer);

    this.bindGroup = this.device.createBindGroup({
      layout: this.pipeline.getBindGroupLayout(0),
      entries: [
        { binding: 0, resource: { buffer: this.resultBuffer } },
        { binding: 1, resource: { buffer: this.paramsBuffer } },
        { binding: 2, resource: { buffer: this.patternBuffer } },
      ],
    });
  }

  async searchBatch(batchSize: number): Promise<FoundKey | null> {
    if (this.destroyed) return null;

    const workgroups = Math.ceil(batchSize / WORKGROUP_SIZE);
    const actual = workgroups * WORKGROUP_SIZE;

    // Update params with crypto-secure random seed
    const seedBytes = new Uint32Array(2);
    crypto.getRandomValues(seedBytes);
    const paramsData = new Uint32Array([this.batchOffset, seedBytes[0], seedBytes[1], 0]);
    this.device.queue.writeBuffer(this.paramsBuffer, 0, paramsData);

    // Use command encoder to reset and dispatch in same command buffer
    const encoder = this.device.createCommandEncoder();

    // Clear the result buffer
    encoder.clearBuffer(this.resultBuffer, 0, RESULT_BUFFER_SIZE);

    // Dispatch compute
    const pass = encoder.beginComputePass();
    pass.setPipeline(this.pipeline);
    pass.setBindGroup(0, this.bindGroup);
    pass.dispatchWorkgroups(workgroups);
    pass.end();

    // Copy results
    encoder.copyBufferToBuffer(this.resultBuffer, 0, this.resultReadBuffer, 0, RESULT_BUFFER_SIZE);
    this.device.queue.submit([encoder.finish()]);

    // Read results
    await this.resultReadBuffer.mapAsync(GPUMapMode.READ);
    const data = new Uint32Array(this.resultReadBuffer.getMappedRange().slice(0));
    this.resultReadBuffer.unmap();

    this.attempts += actual;
    this.batchOffset += actual;

    return parseResultBuffer(data, this.attempts);
  }

  getStats(): GrinderStats {
    const elapsedMs = Date.now() - this.startTime;
    const elapsedSec = elapsedMs / 1000;
    return {
      attempts: this.attempts,
      rate: elapsedSec > 0 ? this.attempts / elapsedSec : 0,
      elapsedMs,
    };
  }

  reset(): void {
    this.attempts = 0;
    this.startTime = Date.now();
    this.batchOffset = 0;
  }

  destroy(): void {
    this.destroyed = true;
  }
}

// CPU Grinder using Web Crypto API
class CpuGrinder implements Grinder {
  private pattern: Pattern;
  private attempts: number = 0;
  private startTime: number = Date.now();
  private destroyed: boolean = false;

  constructor(pattern: Pattern) {
    this.pattern = pattern;
  }

  async searchBatch(maxAttempts: number): Promise<FoundKey | null> {
    if (this.destroyed) return null;

    const endAttempts = this.attempts + maxAttempts;

    while (this.attempts < endAttempts && !this.destroyed) {
      try {
        // Generate Ed25519 keypair using Web Crypto API
        const keyPair = await crypto.subtle.generateKey('Ed25519' as unknown as EcKeyGenParams, true, [
          'sign',
          'verify',
        ]);

        // Export public key as raw bytes
        const publicKeyBuffer = await crypto.subtle.exportKey('raw', keyPair.publicKey);
        const publicKey = new Uint8Array(publicKeyBuffer);

        // Export private key as PKCS8 format
        const privateKeyPkcs8 = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
        const pkcs8Bytes = new Uint8Array(privateKeyPkcs8);
        const seed = pkcs8Bytes.slice(16, 48);

        // Encode public key as Base58 (Solana address)
        const address = base58Encode(publicKey);

        this.attempts++;

        // Check pattern match using shared utility
        if (matchesPattern(address, this.pattern)) {
          const fullPrivateKey = new Uint8Array(64);
          fullPrivateKey.set(seed, 0);
          fullPrivateKey.set(publicKey, 32);

          return {
            publicKey,
            privateKey: fullPrivateKey,
            address,
            attempts: this.attempts,
          };
        }
      } catch {
        this.attempts++;
      }
    }

    return null;
  }

  getStats(): GrinderStats {
    const elapsedMs = Date.now() - this.startTime;
    const elapsedSec = elapsedMs / 1000;
    return {
      attempts: this.attempts,
      rate: elapsedSec > 0 ? this.attempts / elapsedSec : 0,
      elapsedMs,
    };
  }

  reset(): void {
    this.attempts = 0;
    this.startTime = Date.now();
  }

  destroy(): void {
    this.destroyed = true;
  }
}

// UI helpers
function log(msg: string, cls: string = ''): void {
  const o = document.getElementById('output')!;
  if (cls) o.innerHTML += `<span class="${cls}">${msg}</span>\n`;
  else o.textContent += msg + '\n';
  o.scrollTop = o.scrollHeight;
}

function clearLog(): void {
  document.getElementById('output')!.textContent = '';
}

function updateStats(rate: number, attempts: number, mode: string, eta: string): void {
  document.getElementById('stat-rate')!.textContent = (rate / 1000).toFixed(2);
  document.getElementById('stat-attempts')!.textContent = formatNum(attempts);
  document.getElementById('stat-mode')!.textContent = mode;
  document.getElementById('stat-eta')!.textContent = eta;
}

function showStats(s: boolean): void {
  document.getElementById('stats-grid')!.style.display = s ? 'grid' : 'none';
}

function setButtons(bench: boolean, search: boolean, stop: boolean): void {
  (document.getElementById('run-benchmark') as HTMLButtonElement).disabled = !bench;
  (document.getElementById('run-search') as HTMLButtonElement).disabled = !search;
  (document.getElementById('stop') as HTMLButtonElement).disabled = !stop;
}

async function checkWebGPU(): Promise<GPUDevice | null> {
  const el = document.getElementById('gpu-status')!;
  if (!navigator.gpu) {
    el.className = 'gpu-status gpu-unavailable';
    el.innerHTML = '&#9888; WebGPU not supported';
    return null;
  }
  try {
    const adapter = await navigator.gpu.requestAdapter();
    if (!adapter) {
      el.className = 'gpu-status gpu-unavailable';
      el.innerHTML = '&#9888; No adapter';
      return null;
    }
    const device = await adapter.requestDevice();
    el.className = 'gpu-status gpu-available';
    el.innerHTML = '&#10003; WebGPU available';
    return device;
  } catch (e) {
    el.className = 'gpu-status gpu-unavailable';
    el.innerHTML = `&#9888; ${(e as Error).message}`;
    return null;
  }
}

let running = false;
let shouldStop = false;

async function runBenchmark(): Promise<void> {
  if (running) return;
  running = true;
  shouldStop = false;
  setButtons(false, false, true);
  clearLog();
  showStats(true);

  const patternStr = (document.getElementById('pattern') as HTMLInputElement).value || 'A';
  const matchModeStr = (document.getElementById('match-mode') as HTMLSelectElement).value as MatchMode;
  const ignoreCase = (document.getElementById('case-sensitive') as HTMLSelectElement).value === 'false';
  const duration = parseInt((document.getElementById('duration') as HTMLSelectElement).value);
  const computeMode = (document.getElementById('compute-mode') as HTMLSelectElement)?.value || 'gpu';

  let pattern: Pattern;
  try {
    pattern = createPattern(patternStr, { ignoreCase, matchMode: matchModeStr });
  } catch (e) {
    log(`Error: ${(e as Error).message}`, 'error');
    running = false;
    setButtons(true, true, false);
    return;
  }

  const diff = calculateDifficulty(patternStr, pattern.options);

  log('=== Vanity Address Benchmark ===', 'highlight');
  log(`Pattern: ${patternStr}`);
  log(`Match mode: ${matchModeStr}`);
  log(`Case sensitive: ${!ignoreCase}\n`);
  log(formatDifficultyInfo(diff, ignoreCase));
  log('');

  // Run CPU benchmark
  if (computeMode === 'cpu' || computeMode === 'both') {
    log('Running CPU benchmark (Web Crypto API)...', 'info');
    const cpuGrinder = new CpuGrinder(pattern);
    const cpuStart = Date.now();
    let cpuMatches = 0;

    while (Date.now() - cpuStart < duration && !shouldStop) {
      const result = await cpuGrinder.searchBatch(100);
      if (result) {
        cpuMatches++;
        log(`CPU found: ${result.address}`, 'result');
      }
      const stats = cpuGrinder.getStats();
      const eta = diff.p50Attempts / stats.rate;
      updateStats(stats.rate, stats.attempts, 'CPU', formatDuration(eta));
      await new Promise((r) => setTimeout(r, 0));
    }

    const cpuElapsed = (Date.now() - cpuStart) / 1000;
    const cpuStats = cpuGrinder.getStats();
    const cpuRate = cpuStats.attempts / cpuElapsed;

    log(`\nCPU Results: ${(cpuRate / 1000).toFixed(2)} k/s, ${cpuMatches} matches in ${cpuElapsed.toFixed(1)}s`, 'highlight');
    cpuGrinder.destroy();
  }

  // Run GPU benchmark
  if ((computeMode === 'gpu' || computeMode === 'both') && !shouldStop) {
    const device = await checkWebGPU();
    if (!device) {
      log('WebGPU not available!', 'error');
      running = false;
      setButtons(true, true, false);
      return;
    }

    log('\nRunning GPU benchmark (WebGPU)...', 'info');
    const batchSize = getGpuBatchSize();
    log(`Batch size: ${(batchSize / 1000).toFixed(0)}K threads`);
    const grinder = await GpuGrinder.create(device, patternStr, matchModeStr, ignoreCase);

    const start = Date.now();
    let matchesFound = 0;
    let batchCount = 0;

    while (Date.now() - start < duration && !shouldStop) {
      const result = await grinder.searchBatch(batchSize);
      batchCount++;

      if (result) {
        matchesFound++;
        log(`GPU found: ${result.address}`, 'result');
        grinder.batchOffset = grinder.attempts;
      }
      const stats = grinder.getStats();
      const eta = diff.p50Attempts / stats.rate;
      updateStats(stats.rate, stats.attempts, 'GPU', formatDuration(eta));
      await new Promise((r) => setTimeout(r, 0));
    }

    const elapsed = (Date.now() - start) / 1000;
    const stats = grinder.getStats();
    const rate = stats.attempts / elapsed;

    log(`\nGPU Results: ${(rate / 1000).toFixed(2)} k/s`, 'highlight');
    log(`Total: ${formatNum(stats.attempts)} attempts in ${elapsed.toFixed(1)}s`);
    log(`Matches found: ${matchesFound}`, 'result');
    log(`P50 ETA at current rate: ${formatDuration(diff.p50Attempts / rate)}`, 'result');

    grinder.destroy();
  }

  running = false;
  setButtons(true, true, false);
}

async function runSearch(): Promise<void> {
  if (running) return;
  running = true;
  shouldStop = false;
  setButtons(false, false, true);
  clearLog();
  showStats(true);

  const patternStr = (document.getElementById('pattern') as HTMLInputElement).value || 'A';
  const matchModeStr = (document.getElementById('match-mode') as HTMLSelectElement).value as MatchMode;
  const ignoreCase = (document.getElementById('case-sensitive') as HTMLSelectElement).value === 'false';

  let pattern: Pattern;
  try {
    pattern = createPattern(patternStr, { ignoreCase, matchMode: matchModeStr });
  } catch (e) {
    log(`Error: ${(e as Error).message}`, 'error');
    running = false;
    setButtons(true, true, false);
    return;
  }

  const diff = calculateDifficulty(patternStr, pattern.options);

  log('=== Searching for Vanity Address ===', 'highlight');
  log(`Pattern: ${patternStr}`);
  log(`Match mode: ${matchModeStr}`);
  log(`Case sensitive: ${!ignoreCase}\n`);
  log(formatDifficultyInfo(diff, ignoreCase));
  log('');

  const device = await checkWebGPU();
  if (!device) {
    log('WebGPU not available!', 'error');
    running = false;
    setButtons(true, true, false);
    return;
  }

  log('Searching with full Ed25519 on GPU...', 'info');
  const batchSize = getGpuBatchSize();
  const grinder = await GpuGrinder.create(device, patternStr, matchModeStr, ignoreCase);
  const start = Date.now();
  let found: FoundKey | null = null;

  while (!found && !shouldStop) {
    found = await grinder.searchBatch(batchSize);
    const stats = grinder.getStats();
    const eta = Math.max(0, (diff.p50Attempts - stats.attempts) / stats.rate);
    updateStats(stats.rate, stats.attempts, 'GPU', formatDuration(eta));
    await new Promise((r) => setTimeout(r, 0));
  }

  if (found) {
    const elapsed = (Date.now() - start) / 1000;
    log(`\n*** FOUND! ***`, 'result');
    log(`Address: ${found.address}`, 'highlight');
    log(`Attempts: ${formatNum(found.attempts)} | Time: ${formatDuration(elapsed)}`);
    log(`\nPrivate Key (Solana JSON):`, 'info');
    log(`[${Array.from(found.privateKey).join(',')}]`);
    updateStats(found.attempts / elapsed, found.attempts, 'GPU', 'Found!');
  } else {
    log('\nStopped.', 'info');
  }

  grinder.destroy();
  running = false;
  setButtons(true, true, false);
}

function stopExecution(): void {
  shouldStop = true;
  log('\nStopping...', 'info');
}

// Batch size slider/input synchronization
function setupBatchSizeControls(): void {
  const slider = document.getElementById('batch-slider') as HTMLInputElement;
  const input = document.getElementById('batch-size') as HTMLInputElement;

  if (!slider || !input) return;

  // Slider uses log2 scale: value 10 = 1024, value 12 = 4096, value 18 = 262144
  const sliderToValue = (sliderVal: number): number => Math.pow(2, sliderVal);
  const valueToSlider = (value: number): number => Math.round(Math.log2(value));

  // Update input when slider changes
  slider.addEventListener('input', () => {
    const value = sliderToValue(parseInt(slider.value, 10));
    input.value = value.toString();
    input.classList.remove('invalid');
  });

  // Update slider when input changes (with validation)
  input.addEventListener('input', () => {
    const value = parseInt(input.value, 10);

    if (isNaN(value) || value < MIN_BATCH_SIZE || value > MAX_BATCH_SIZE) {
      input.classList.add('invalid');
    } else {
      input.classList.remove('invalid');
      // Update slider to closest power of 2
      slider.value = Math.max(10, Math.min(18, valueToSlider(value))).toString();
    }
  });

  // On blur, clamp to valid range
  input.addEventListener('blur', () => {
    let value = parseInt(input.value, 10);

    if (isNaN(value)) {
      value = DEFAULT_GPU_BATCH_SIZE;
    } else {
      value = Math.max(MIN_BATCH_SIZE, Math.min(MAX_BATCH_SIZE, value));
    }

    input.value = value.toString();
    input.classList.remove('invalid');
    slider.value = Math.max(10, Math.min(18, valueToSlider(value))).toString();
  });
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
  checkWebGPU();
  setupBatchSizeControls();

  document.getElementById('run-benchmark')!.addEventListener('click', runBenchmark);
  document.getElementById('run-search')!.addEventListener('click', runSearch);
  document.getElementById('stop')!.addEventListener('click', stopExecution);
});
