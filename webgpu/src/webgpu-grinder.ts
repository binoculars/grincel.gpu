import * as fs from 'fs';
import * as path from 'path';
import { Grinder, GrinderStats, FoundKey, Pattern } from './types';
import {
  RESULT_BUFFER_SIZE,
  PARAMS_BUFFER_SIZE,
  PATTERN_BUFFER_SIZE,
  WORKGROUP_SIZE,
  createPatternConfig,
  parseResultBuffer,
} from './gpu-utils';

// Try to import WebGPU from the webgpu package (Dawn bindings for Node.js)
let gpu: any = null;
try {
  gpu = require('webgpu');
} catch {
  // WebGPU not available
}

// Batch size for GPU computation
const GPU_BATCH_SIZE = 65536; // 64K threads per batch

export class WebGpuGrinder implements Grinder {
  private device: GPUDevice | null = null;
  private pipeline: GPUComputePipeline | null = null;
  private resultBuffer: GPUBuffer | null = null;
  private resultStagingBuffer: GPUBuffer | null = null;
  private paramsBuffer: GPUBuffer | null = null;
  private patternBuffer: GPUBuffer | null = null;
  private bindGroup: GPUBindGroup | null = null;

  private pattern: Pattern;
  private attempts: number = 0;
  private startTime: number = Date.now();
  private batchCounter: number = 0;
  private initialized: boolean = false;
  private useGpu: boolean = false;

  constructor(pattern: Pattern) {
    this.pattern = pattern;
  }

  async init(): Promise<void> {
    if (this.initialized) return;

    if (!gpu) {
      console.log('WebGPU package not available, using CPU fallback');
      this.initialized = true;
      return;
    }

    try {
      const adapter = await gpu.requestAdapter();
      if (!adapter) {
        console.log('No WebGPU adapter found, using CPU fallback');
        this.initialized = true;
        return;
      }

      this.device = await adapter.requestDevice() as GPUDevice;
      if (!this.device) {
        console.log('Could not get WebGPU device, using CPU fallback');
        this.initialized = true;
        return;
      }

      console.log('WebGPU Device:', (adapter as any).name || 'Unknown');

      // Load shader
      const shaderPath = path.join(__dirname, 'shaders', 'vanity.wgsl');
      const shaderCode = fs.readFileSync(shaderPath, 'utf-8');

      const shaderModule = this.device.createShaderModule({
        code: shaderCode,
      });

      // Create pipeline
      this.pipeline = this.device.createComputePipeline({
        layout: 'auto',
        compute: {
          module: shaderModule,
          entryPoint: 'main',
        },
      });

      // Create result buffer (read_write storage)
      this.resultBuffer = this.device.createBuffer({
        size: RESULT_BUFFER_SIZE,
        usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_SRC | GPUBufferUsage.COPY_DST,
      });

      // Staging buffer for reading results
      this.resultStagingBuffer = this.device.createBuffer({
        size: RESULT_BUFFER_SIZE,
        usage: GPUBufferUsage.MAP_READ | GPUBufferUsage.COPY_DST,
      });

      // Params buffer (uniform)
      this.paramsBuffer = this.device.createBuffer({
        size: PARAMS_BUFFER_SIZE,
        usage: GPUBufferUsage.UNIFORM | GPUBufferUsage.COPY_DST,
      });

      // Pattern buffer (uniform)
      this.patternBuffer = this.device.createBuffer({
        size: PATTERN_BUFFER_SIZE,
        usage: GPUBufferUsage.UNIFORM | GPUBufferUsage.COPY_DST,
      });

      // Initialize pattern buffer
      this.writePatternConfig();

      // Create bind group
      this.bindGroup = this.device.createBindGroup({
        layout: this.pipeline.getBindGroupLayout(0),
        entries: [
          { binding: 0, resource: { buffer: this.resultBuffer } },
          { binding: 1, resource: { buffer: this.paramsBuffer } },
          { binding: 2, resource: { buffer: this.patternBuffer } },
        ],
      });

      this.useGpu = true;
      console.log('WebGPU initialized successfully (full GPU computation)');
    } catch (error) {
      console.log('WebGPU initialization failed:', (error as Error).message);
      console.log('Using CPU fallback');
    }

    this.initialized = true;
  }

  private writePatternConfig(): void {
    if (!this.device || !this.patternBuffer) return;
    const config = createPatternConfig(this.pattern);
    this.device.queue.writeBuffer(this.patternBuffer, 0, config.buffer);
  }

  private async resetResultBuffer(): Promise<void> {
    if (!this.device || !this.resultBuffer) return;

    // Clear the result buffer (set found=0)
    const zeros = new Uint32Array(RESULT_BUFFER_SIZE / 4);
    this.device.queue.writeBuffer(this.resultBuffer, 0, zeros);
  }

  private async dispatchGpu(): Promise<FoundKey | null> {
    if (!this.device || !this.pipeline || !this.bindGroup) {
      throw new Error('WebGPU not initialized');
    }

    // Reset result buffer before dispatch
    await this.resetResultBuffer();

    // Update params with batch offset and random base seed
    const params = new Uint32Array([
      this.batchCounter * GPU_BATCH_SIZE, // batch_offset
      Math.floor(Math.random() * 0xFFFFFFFF), // base_seed_lo
      Math.floor(Math.random() * 0xFFFFFFFF), // base_seed_hi
      0, // unused
    ]);
    this.device.queue.writeBuffer(this.paramsBuffer!, 0, params);
    this.batchCounter++;

    // Create command encoder
    const commandEncoder = this.device.createCommandEncoder();
    const passEncoder = commandEncoder.beginComputePass();

    passEncoder.setPipeline(this.pipeline);
    passEncoder.setBindGroup(0, this.bindGroup);
    passEncoder.dispatchWorkgroups(Math.ceil(GPU_BATCH_SIZE / WORKGROUP_SIZE));
    passEncoder.end();

    // Copy result buffer to staging
    commandEncoder.copyBufferToBuffer(
      this.resultBuffer!,
      0,
      this.resultStagingBuffer!,
      0,
      RESULT_BUFFER_SIZE
    );

    // Submit commands
    this.device.queue.submit([commandEncoder.finish()]);

    // Read back results
    await this.resultStagingBuffer!.mapAsync(GPUMapMode.READ);
    const resultData = new Uint32Array(this.resultStagingBuffer!.getMappedRange().slice(0));
    this.resultStagingBuffer!.unmap();

    // Track attempts
    this.attempts += GPU_BATCH_SIZE;

    return parseResultBuffer(resultData, this.attempts);
  }

  async searchBatch(maxAttempts: number): Promise<FoundKey | null> {
    await this.init();

    if (!this.useGpu) {
      // No GPU available, return null (caller should use CPU grinder)
      return null;
    }

    const targetAttempts = this.attempts + maxAttempts;

    while (this.attempts < targetAttempts) {
      const result = await this.dispatchGpu();
      if (result) return result;
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
    this.batchCounter = 0;
  }

  destroy(): void {
    this.resultBuffer?.destroy();
    this.resultStagingBuffer?.destroy();
    this.paramsBuffer?.destroy();
    this.patternBuffer?.destroy();
    this.device?.destroy();
    this.initialized = false;
  }
}

// Factory function to create grinder (handles async init)
export async function createWebGpuGrinder(pattern: Pattern): Promise<WebGpuGrinder> {
  const grinder = new WebGpuGrinder(pattern);
  await grinder.init();
  return grinder;
}
