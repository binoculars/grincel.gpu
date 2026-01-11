# Grincel - GPU Vanity Address Generator

A high-performance GPU-accelerated Solana vanity address generator written in Zig.

**Platforms:** macOS, Linux
**GPU Backends:** Metal (macOS), Vulkan (Linux, macOS via MoltenVK)

## Features

- **Full GPU acceleration** - SHA-512, Ed25519, Base58, and pattern matching all run on GPU
- **Cross-platform** - Metal on macOS (default), Vulkan on Linux (default) and macOS (via MoltenVK)
- **~820k keys/sec** on Apple Silicon (vs ~2.3k/sec CPU-only, ~357x faster)
- **Flexible pattern matching** - prefix, suffix, or anywhere in address
- **Case-insensitive by default** (like solana-keygen)
- **Wildcard support** - use `?` to match any character
- **Multiple matches** - use `PATTERN:N` to find N matching addresses
- **P50 time estimation** - shows estimated time to 50% probability
- **Solana-compatible output** - saves keys as JSON in solana-keygen format

## Installation

### macOS (Homebrew)

```bash
brew tap binoculars/grincel.gpu https://github.com/binoculars/grincel.gpu
brew install grincel
```

### Linux (Homebrew)

Requires [Homebrew on Linux](https://docs.brew.sh/Homebrew-on-Linux):

```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Add to PATH (add to ~/.bashrc or ~/.zshrc for persistence)
eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"

# Install grincel
brew tap binoculars/grincel.gpu https://github.com/binoculars/grincel.gpu
brew install grincel
```

### Docker (GHCR)

Pre-built images are available on GitHub Container Registry for `linux/amd64` and `linux/arm64`:

```bash
# Pull the latest image
docker pull ghcr.io/binoculars/grincel.gpu:latest

# Run with Vulkan GPU passthrough
docker run --rm --device /dev/dri \
  -v $(pwd):/output \
  -w /output \
  ghcr.io/binoculars/grincel.gpu Ace

# Run in CPU-only mode (no GPU required)
docker run --rm \
  -v $(pwd):/output \
  -w /output \
  ghcr.io/binoculars/grincel.gpu Ace --cpu

# Find 5 addresses ending with 'Sol'
docker run --rm --device /dev/dri \
  -v $(pwd):/output \
  -w /output \
  ghcr.io/binoculars/grincel.gpu Sol:5 --suffix

# Use a specific version
docker pull ghcr.io/binoculars/grincel.gpu:1.0.0
```

### Build from Source

Requires Zig 0.15+ and platform-specific dependencies:

**macOS:**
```bash
brew bundle
zig build -Doptimize=ReleaseFast
```

**Linux:**
```bash
# Install Vulkan SDK and shaderc
apt-get install libvulkan-dev shaderc
zig build -Doptimize=ReleaseFast
```

## Usage

```
grincel <pattern>[:<count>] [options]

Options:
  -h, --help            Show help message
  -s, --case-sensitive  Case sensitive matching
  -t, --threads N       Threads per threadgroup (default: 64)
  --cpu                 Use CPU only (no GPU)
  --vulkan              Use Vulkan backend (macOS only, Linux uses Vulkan by default)
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
$ grincel Ace:2
```

Output:
```
=== Solana Vanity Address Search ===
Pattern: Ace
Match mode: prefix
Case sensitive: false
Finding: 2 matches
Using: Metal GPU

Difficulty estimate:
  Effective pattern length: 3 chars
  Alphabet size: 34 (case-insensitive)
  Probability per attempt: 1 in 39304
  Expected attempts (mean): 39304
  P50 attempts (median): 27238

Metal Device: Apple M1 Max
Searching...

*** FOUND MATCH 1/2! ***
Address: AceNY6vrNHjShkazB1YZWYJzLDrZ8UQ3EVrgMMnRtNf
Public Key (Base58): AceNY6vrNHjShkazB1YZWYJzLDrZ8UQ3EVrgMMnRtNf
VERIFIED: Address matches Base58(PublicKey)
Saved: AceNY6vrNHjShkazB1YZWYJzLDrZ8UQ3EVrgMMnRtNf.json

*** FOUND MATCH 2/2! ***
Address: AceqJzPXAkcVCcBCWsHT3fKbTNzoyAXxEBHABCdeFgh
Public Key (Base58): AceqJzPXAkcVCcBCWsHT3fKbTNzoyAXxEBHABCdeFgh
VERIFIED: Address matches Base58(PublicKey)
Saved: AceqJzPXAkcVCcBCWsHT3fKbTNzoyAXxEBHABCdeFgh.json

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
# Find 5 addresses starting with 'Ace'
grincel Ace:5

# Case-sensitive match
grincel ABC -s

# Match at end of address
grincel XYZ --suffix

# Match anywhere in address
grincel Fun --anywhere

# Wildcard pattern (matches A?C where ? is any char)
grincel A?C

# CPU-only mode
grincel TEST --cpu

# Use Vulkan instead of Metal (macOS)
grincel Ace --vulkan

# Use 128 threads per threadgroup (experiment for best performance)
grincel Ace -t 128
```

## Input Validation

Invalid Base58 characters are rejected with a clear error:

```bash
$ grincel "0OIl"
Error: Invalid character '0' at position 0
Base58 alphabet does not include: 0, O, I, l
```

## Benchmark

```bash
$ grincel --benchmark
=== Vanity Address Grinder Benchmark ===
Running each mode for 10 seconds...

CPU benchmark...
  CPU: 2.50 k/s
Metal GPU benchmark...
  Metal GPU: 823.28 k/s
Vulkan GPU benchmark...
  Vulkan GPU: 780.15 k/s

=== Results ===
CPU:        2.50 k/s (baseline)
Metal GPU:  823.28 k/s (329x faster)
Vulkan GPU: 780.15 k/s (312x faster)

Metal GPU mode is fastest!
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
.
├── build.zig           # Zig build configuration
├── build.zig.zon       # Dependencies (vulkan-zig, zig-metal, etc.)
├── libs/
│   └── zigtrait/       # Vendored zigtrait library
├── src/
│   ├── main.zig        # Entry point
│   ├── cli.zig         # CLI parsing, validation, search orchestration
│   ├── pattern.zig     # Pattern matching logic
│   ├── grinders/
│   │   ├── mod.zig     # Shared types and conditional exports
│   │   ├── cpu.zig     # CPU-only grinder
│   │   ├── metal.zig   # Metal GPU implementation (macOS)
│   │   └── vulkan.zig  # Vulkan GPU implementation (Linux, macOS)
│   ├── cpu/
│   │   ├── ed25519.zig # Ed25519 implementation
│   │   └── base58.zig  # Base58 encoding
│   └── shaders/
│       ├── vanity.metal # Metal compute shader (embedded at compile time)
│       └── vanity.comp  # Vulkan/GLSL compute shader (compiled to SPIR-V)
├── Formula/
│   └── grincel.rb      # Homebrew formula
└── Dockerfile          # Multi-arch Linux container
```

### Dependencies

Managed via Zig's package manager (`build.zig.zon`):
- **zig-metal** - Metal bindings for Zig (macOS GPU)
- **vulkan-zig** - Vulkan bindings for Zig (cross-platform GPU)
- **zigtrait** - Zig trait library (vendored)

## License

This project is released into the public domain. See LICENSE file for details.
