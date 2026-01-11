import * as fs from 'fs';
import * as path from 'path';

// Read the WGSL shader
const shaderPath = path.join(__dirname, '../src/shaders/vanity.wgsl');
const shaderCode = fs.readFileSync(shaderPath, 'utf-8');

describe('WGSL Shader', () => {
  describe('Shader File', () => {
    test('shader file exists and is readable', () => {
      expect(shaderCode).toBeDefined();
      expect(shaderCode.length).toBeGreaterThan(0);
    });

    test('contains main entry point', () => {
      expect(shaderCode).toMatch(/@compute\s+@workgroup_size\(\d+\)\s*\n\s*fn\s+main/);
    });

    test('defines required structures', () => {
      expect(shaderCode).toContain('struct PatternConfig');
      expect(shaderCode).toContain('struct ResultBuffer');
      expect(shaderCode).toContain('struct Params');
      expect(shaderCode).toContain('struct Rng');
    });

    test('defines required bindings', () => {
      expect(shaderCode).toContain('@group(0) @binding(0)');
      expect(shaderCode).toContain('@group(0) @binding(1)');
      expect(shaderCode).toContain('@group(0) @binding(2)');
    });
  });

  describe('64-bit Emulation Functions', () => {
    test('contains u64 add function', () => {
      expect(shaderCode).toContain('fn u64_add');
    });

    test('contains u64 sub function', () => {
      expect(shaderCode).toContain('fn u64_sub');
    });

    test('contains u64 shift functions', () => {
      expect(shaderCode).toContain('fn u64_shl');
      expect(shaderCode).toContain('fn u64_shr');
      expect(shaderCode).toContain('fn u64_rotr');
    });

    test('contains u64 bitwise functions', () => {
      expect(shaderCode).toContain('fn u64_xor');
      expect(shaderCode).toContain('fn u64_and');
      expect(shaderCode).toContain('fn u64_or');
      expect(shaderCode).toContain('fn u64_not');
    });

    test('contains u64 multiply function', () => {
      expect(shaderCode).toContain('fn u64_mul');
    });
  });

  describe('SHA-512 Implementation', () => {
    test('contains K512 constants', () => {
      expect(shaderCode).toContain('K512_LO');
      expect(shaderCode).toContain('K512_HI');
      // Check for first constant value (0x428a2f98d728ae22)
      expect(shaderCode).toContain('0xd728ae22u');
      expect(shaderCode).toContain('0x428a2f98u');
    });

    test('contains SHA-512 helper functions', () => {
      expect(shaderCode).toContain('fn sha_Ch');
      expect(shaderCode).toContain('fn sha_Maj');
      expect(shaderCode).toContain('fn sha_Sigma0');
      expect(shaderCode).toContain('fn sha_Sigma1');
      expect(shaderCode).toContain('fn sha_sigma0');
      expect(shaderCode).toContain('fn sha_sigma1');
    });

    test('contains sha512 function', () => {
      expect(shaderCode).toContain('fn sha512');
    });

    test('contains SHA-512 initial hash values', () => {
      // H0 = 0x6a09e667f3bcc908
      expect(shaderCode).toContain('0xf3bcc908u');
      expect(shaderCode).toContain('0x6a09e667u');
    });
  });

  describe('Ed25519 Implementation', () => {
    test('contains field element structure', () => {
      expect(shaderCode).toContain('struct Fe');
    });

    test('contains field element operations', () => {
      expect(shaderCode).toContain('fn fe_zero');
      expect(shaderCode).toContain('fn fe_one');
      expect(shaderCode).toContain('fn fe_add');
      expect(shaderCode).toContain('fn fe_sub');
      expect(shaderCode).toContain('fn fe_mul');
      expect(shaderCode).toContain('fn fe_sq');
      expect(shaderCode).toContain('fn fe_invert');
    });

    test('contains Ed25519 point structure', () => {
      expect(shaderCode).toContain('struct GeP3');
    });

    test('contains Ed25519 point operations', () => {
      expect(shaderCode).toContain('fn ge_p3_identity');
      expect(shaderCode).toContain('fn ge_base_point');
      expect(shaderCode).toContain('fn ge_p3_dbl');
      expect(shaderCode).toContain('fn ge_p3_add');
      expect(shaderCode).toContain('fn ge_scalarmult_base');
      expect(shaderCode).toContain('fn ge_p3_tobytes');
    });

    test('contains curve constants', () => {
      expect(shaderCode).toContain('fn fe_d');
      expect(shaderCode).toContain('fn fe_2d');
    });
  });

  describe('RNG Implementation', () => {
    test('contains RNG structure', () => {
      expect(shaderCode).toMatch(/struct\s+Rng\s*\{/);
    });

    test('contains rng_next function', () => {
      expect(shaderCode).toContain('fn rng_next');
    });

    test('contains rng_init function', () => {
      expect(shaderCode).toContain('fn rng_init');
    });
  });

  describe('Base58 Implementation', () => {
    test('contains BASE58 constant', () => {
      expect(shaderCode).toContain('const BASE58:');
    });

    test('contains base58_encode function', () => {
      expect(shaderCode).toContain('fn base58_encode');
    });

    test('BASE58 has correct first characters', () => {
      // '1' = 0x31, '2' = 0x32, etc.
      expect(shaderCode).toContain('0x31u');
      expect(shaderCode).toContain('0x32u');
    });
  });

  describe('Pattern Matching Implementation', () => {
    test('contains pattern_matches function', () => {
      expect(shaderCode).toContain('fn pattern_matches');
    });

    test('contains to_lower function for case-insensitive matching', () => {
      expect(shaderCode).toContain('fn to_lower');
    });

    test('PatternConfig has required fields', () => {
      expect(shaderCode).toMatch(/struct\s+PatternConfig\s*\{[^}]*length:\s*u32/);
      expect(shaderCode).toMatch(/struct\s+PatternConfig\s*\{[^}]*match_mode:\s*u32/);
      expect(shaderCode).toMatch(/struct\s+PatternConfig\s*\{[^}]*ignore_case:\s*u32/);
      // Pattern is split into two vec4<u32> for uniform buffer alignment
      expect(shaderCode).toMatch(/struct\s+PatternConfig\s*\{[^}]*pattern0:\s*vec4<u32>/);
      expect(shaderCode).toMatch(/struct\s+PatternConfig\s*\{[^}]*pattern1:\s*vec4<u32>/);
    });
  });

  describe('Atomic Operations', () => {
    test('uses atomic for found flag', () => {
      expect(shaderCode).toContain('atomic<u32>');
      expect(shaderCode).toContain('atomicMax');
    });
  });

  describe('Workgroup Configuration', () => {
    test('main kernel has workgroup_size of 64', () => {
      expect(shaderCode).toMatch(/@compute\s+@workgroup_size\(64\)\s*\n\s*fn\s+main/);
    });
  });
});

describe('WebGPU Grinder Mock', () => {
  // Mock WebGPU API for testing
  const mockDevice = {
    createShaderModule: jest.fn().mockReturnValue({
      getCompilationInfo: jest.fn().mockResolvedValue({ messages: [] }),
    }),
    createBindGroupLayout: jest.fn().mockReturnValue({}),
    createPipelineLayout: jest.fn().mockReturnValue({}),
    createComputePipeline: jest.fn().mockReturnValue({}),
    createBuffer: jest.fn().mockReturnValue({
      mapAsync: jest.fn().mockResolvedValue(undefined),
      getMappedRange: jest.fn().mockReturnValue(new ArrayBuffer(256)),
      unmap: jest.fn(),
      destroy: jest.fn(),
    }),
    createBindGroup: jest.fn().mockReturnValue({}),
    createCommandEncoder: jest.fn().mockReturnValue({
      beginComputePass: jest.fn().mockReturnValue({
        setPipeline: jest.fn(),
        setBindGroup: jest.fn(),
        dispatchWorkgroups: jest.fn(),
        end: jest.fn(),
      }),
      copyBufferToBuffer: jest.fn(),
      finish: jest.fn().mockReturnValue({}),
    }),
    queue: {
      submit: jest.fn(),
      writeBuffer: jest.fn(),
    },
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('shader module can be created with shader code', async () => {
    mockDevice.createShaderModule({ code: shaderCode });
    expect(mockDevice.createShaderModule).toHaveBeenCalledWith({ code: shaderCode });
  });

  test('shader compilation returns no errors in mock', async () => {
    const module = mockDevice.createShaderModule({ code: shaderCode });
    const info = await module.getCompilationInfo();
    expect(info.messages).toHaveLength(0);
  });

  test('compute pipeline can be created', () => {
    const module = mockDevice.createShaderModule({ code: shaderCode });

    mockDevice.createComputePipeline({
      layout: 'auto',
      compute: {
        module,
        entryPoint: 'main',
      },
    });

    expect(mockDevice.createComputePipeline).toHaveBeenCalled();
  });

  test('buffers can be created for shader data', () => {
    // Result buffer
    mockDevice.createBuffer({
      size: 256,
      usage: 0x0001 | 0x0008, // STORAGE | COPY_SRC
    });

    // Params buffer
    mockDevice.createBuffer({
      size: 16,
      usage: 0x0040 | 0x0008, // UNIFORM | COPY_DST
    });

    expect(mockDevice.createBuffer).toHaveBeenCalledTimes(2);
  });
});

describe('Shader Constants Validation', () => {
  test('has exactly 80 K512 low constants', () => {
    const matches = shaderCode.match(/K512_LO:\s*array<u32,\s*80>/);
    expect(matches).toBeTruthy();
  });

  test('has exactly 80 K512 high constants', () => {
    const matches = shaderCode.match(/K512_HI:\s*array<u32,\s*80>/);
    expect(matches).toBeTruthy();
  });

  test('has exactly 58 BASE58 characters', () => {
    const matches = shaderCode.match(/const\s+BASE58:\s*array<u32,\s*58>/);
    expect(matches).toBeTruthy();
  });
});
