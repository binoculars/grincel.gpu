# Grincel - GPU Vanity Address Generator

A high-performance GPU-accelerated Solana vanity address generator written in Zig with Metal compute shaders.

## Features

- **Full GPU acceleration** - SHA-512, Ed25519, Base58, and pattern matching all run on Metal GPU
- **~820k keys/sec** on Apple Silicon (vs ~2.3k/sec CPU-only, ~357x faster)
- **Flexible pattern matching** - prefix, suffix, or anywhere in address
- **Case-insensitive by default** (like solana-keygen)
- **Wildcard support** - use `?` to match any character
- **Multiple matches** - use `PATTERN:N` to find N matching addresses
- **P50 time estimation** - shows estimated time to 50% probability
- **Solana-compatible output** - saves keys as JSON in solana-keygen format

## Building

Requires Zig 0.14+ and macOS with Metal support.

```bash
zig build
```

## Usage

```
grincel <pattern>[:<count>] [options]

Options:
  -h, --help            Show help message
  -s, --case-sensitive  Case sensitive matching
  --cpu                 Use CPU only (no GPU)
  --prefix              Match at start of address (default)
  --suffix              Match at end of address
  --anywhere            Match anywhere in address
  --benchmark           Run CPU vs GPU benchmark

Pattern syntax:
  PATTERN               Find one match for PATTERN
  PATTERN:N             Find N matches for PATTERN
  ?                     Wildcard (matches any character)

Valid characters: 1-9, A-H, J-N, P-Z, a-k, m-z (Base58, no 0/O/I/l)
```

## Example

```bash
$ ./zig-out/bin/grincel SOL:2
```

Output:
```
=== Solana Vanity Address Search ===
Pattern: SOL
Match mode: prefix
Case sensitive: false
Finding: 2 matches
Using: Full GPU (Metal)

Difficulty estimate:
  Effective pattern length: 3 chars
  Alphabet size: 34 (case-insensitive)
  Probability per attempt: 1 in 39304
  Expected attempts (mean): 39304
  P50 attempts (median): 27238
  Estimated P50 time: <1 second (at ~800k keys/sec)

Metal Device: Apple M1 Max
Searching...

*** FOUND MATCH 1/2! ***
Address: SoLNY6vrNHjShkazB1YZWYJzLDrZ8UQ3EVrgMMnRtNf
Public Key (Base58): SoLNY6vrNHjShkazB1YZWYJzLDrZ8UQ3EVrgMMnRtNf
VERIFIED: Address matches Base58(PublicKey)
Saved: SoLNY6vrNHjShkazB1YZWYJzLDrZ8UQ3EVrgMMnRtNf.json

*** FOUND MATCH 2/2! ***
Address: SoLqJzPXAkcVCcBCWsHT3fKbTNzoyAXxEBHABCdeFgh
Public Key (Base58): SoLqJzPXAkcVCcBCWsHT3fKbTNzoyAXxEBHABCdeFgh
VERIFIED: Address matches Base58(PublicKey)
Saved: SoLqJzPXAkcVCcBCWsHT3fKbTNzoyAXxEBHABCdeFgh.json

Done! Found 2 matching address(es).
```

## Output Format

Keys are saved as `<address>.json` in Solana keypair format (64-byte array):

```json
[56,58,232,178,50,63,239,242,168,78,220,231,243,166,131,48,...]
```

This format is compatible with `solana-keygen` and can be used directly with Solana CLI tools.

## More Examples

```bash
# Find 5 addresses starting with 'SOL'
./zig-out/bin/grincel SOL:5

# Case-sensitive match
./zig-out/bin/grincel ABC -s

# Match at end of address
./zig-out/bin/grincel XYZ --suffix

# Match anywhere in address
./zig-out/bin/grincel COOL --anywhere

# Wildcard pattern (matches A?C where ? is any char)
./zig-out/bin/grincel A?C

# CPU-only mode
./zig-out/bin/grincel TEST --cpu
```

## Input Validation

Invalid Base58 characters are rejected with a clear error:

```bash
$ ./zig-out/bin/grincel "0OIl"
Error: Invalid character '0' at position 0
Base58 alphabet does not include: 0, O, I, l
```

## Benchmark

```bash
$ ./zig-out/bin/grincel --benchmark
=== Vanity Address Grinder Benchmark ===
Running each mode for 10 seconds...

CPU benchmark...
  CPU: 2.50 k/s
Hybrid (GPU seeds + CPU derive) benchmark...
  Hybrid: 16.62 k/s
Full GPU (all on GPU) benchmark...
  Full GPU: 823.28 k/s

=== Results ===
CPU:      2.50 k/s (baseline)
Hybrid:   16.62 k/s (7x faster)
Full GPU: 823.28 k/s (329x faster)

Full GPU mode is fastest!
```

## Difficulty Estimation

The tool shows probability statistics before searching:

| Pattern Length | Case-Insensitive | Case-Sensitive | P50 Time (@ 800k/s) |
|----------------|------------------|----------------|---------------------|
| 2 chars        | 1 in 1,156       | 1 in 3,364     | <1 second           |
| 3 chars        | 1 in 39,304      | 1 in 195,112   | <1 second           |
| 4 chars        | 1 in 1,336,336   | 1 in 11,316,496| ~1 second           |
| 5 chars        | 1 in 45,435,424  | 1 in 656,356,768| ~39 seconds        |
| 6 chars        | 1 in 1.5 billion | 1 in 38 billion | ~22 minutes        |

The P50 (median) time is when you have a 50% chance of finding a match. Progress shows countdown to P50, then time past P50 with a `+` prefix.

## Architecture

```
src/
  main.zig          # Entry point
  cli.zig           # CLI parsing, validation, search orchestration
  pattern.zig       # Pattern matching logic
  grinders/
    mod.zig         # Shared types and config
    cpu.zig         # CPU-only grinder
    hybrid.zig      # GPU seeds + CPU derive
    full_gpu.zig    # Full GPU implementation
  cpu/
    ed25519.zig     # Ed25519 implementation
    base58.zig      # Base58 encoding
  shaders/
    vanity.metal    # Metal compute shader
```

## License

This project is released into the public domain. See LICENSE file for details.
