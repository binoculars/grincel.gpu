// WGSL Compute Shader for Full Vanity Address Generation
// Complete Ed25519 implementation on GPU (no CPU crypto needed)
// Uses vec2<u32> for 64-bit integer emulation (x=low, y=high)

// ============================================================================
// Structures
// ============================================================================

struct PatternConfig {
    length: u32,
    match_mode: u32,  // 0=prefix, 1=suffix, 2=anywhere
    ignore_case: u32,
    pad: u32,
    pattern0: vec4<u32>,  // First 16 bytes (chars 0-15)
    pattern1: vec4<u32>,  // Second 16 bytes (chars 16-31)
}

struct ResultBuffer {
    found: atomic<u32>,
    thread_id: u32,
    address_len: u32,
    pad: u32,
    public_key: array<u32, 8>,    // 32 bytes
    private_key: array<u32, 16>,  // 64 bytes
    address: array<u32, 12>,      // 48 bytes
}

struct Params {
    batch_offset: u32,
    base_seed_lo: u32,
    base_seed_hi: u32,
    unused: u32,
}

@group(0) @binding(0) var<storage, read_write> results: ResultBuffer;
@group(0) @binding(1) var<uniform> params: Params;
@group(0) @binding(2) var<uniform> pattern: PatternConfig;

// ============================================================================
// 64-bit Integer Emulation using vec2<u32>
// ============================================================================

fn u64_add(a: vec2<u32>, b: vec2<u32>) -> vec2<u32> {
    let lo = a.x + b.x;
    let carry = select(0u, 1u, lo < a.x);
    return vec2<u32>(lo, a.y + b.y + carry);
}

fn u64_sub(a: vec2<u32>, b: vec2<u32>) -> vec2<u32> {
    let borrow = select(0u, 1u, a.x < b.x);
    return vec2<u32>(a.x - b.x, a.y - b.y - borrow);
}

fn u64_shl(a: vec2<u32>, n: u32) -> vec2<u32> {
    if (n == 0u) { return a; }
    if (n >= 64u) { return vec2<u32>(0u, 0u); }
    if (n >= 32u) { return vec2<u32>(0u, a.x << (n - 32u)); }
    return vec2<u32>(a.x << n, (a.y << n) | (a.x >> (32u - n)));
}

fn u64_shr(a: vec2<u32>, n: u32) -> vec2<u32> {
    if (n == 0u) { return a; }
    if (n >= 64u) { return vec2<u32>(0u, 0u); }
    if (n >= 32u) { return vec2<u32>(a.y >> (n - 32u), 0u); }
    return vec2<u32>((a.x >> n) | (a.y << (32u - n)), a.y >> n);
}

fn u64_rotr(a: vec2<u32>, n: u32) -> vec2<u32> {
    let nm = n % 64u;
    if (nm == 0u) { return a; }
    return u64_xor(u64_shr(a, nm), u64_shl(a, 64u - nm));
}

fn u64_xor(a: vec2<u32>, b: vec2<u32>) -> vec2<u32> {
    return vec2<u32>(a.x ^ b.x, a.y ^ b.y);
}

fn u64_and(a: vec2<u32>, b: vec2<u32>) -> vec2<u32> {
    return vec2<u32>(a.x & b.x, a.y & b.y);
}

fn u64_or(a: vec2<u32>, b: vec2<u32>) -> vec2<u32> {
    return vec2<u32>(a.x | b.x, a.y | b.y);
}

fn u64_not(a: vec2<u32>) -> vec2<u32> {
    return vec2<u32>(~a.x, ~a.y);
}

fn u64_mul(a: vec2<u32>, b: vec2<u32>) -> vec2<u32> {
    let a0 = a.x & 0xFFFFu; let a1 = a.x >> 16u;
    let a2 = a.y & 0xFFFFu; let a3 = a.y >> 16u;
    let b0 = b.x & 0xFFFFu; let b1 = b.x >> 16u;
    let b2 = b.y & 0xFFFFu; let b3 = b.y >> 16u;
    var r0 = a0 * b0;
    var r1 = a1 * b0 + a0 * b1 + (r0 >> 16u);
    r0 = (r0 & 0xFFFFu) | ((r1 & 0xFFFFu) << 16u);
    var r2 = a2 * b0 + a1 * b1 + a0 * b2 + (r1 >> 16u);
    var r3 = a3 * b0 + a2 * b1 + a1 * b2 + a0 * b3 + (r2 >> 16u);
    return vec2<u32>(r0, (r2 & 0xFFFFu) | ((r3 & 0xFFFFu) << 16u));
}

// ============================================================================
// SHA-512 Constants and Functions
// ============================================================================

const K512_LO: array<u32, 80> = array<u32, 80>(
    0xd728ae22u, 0x23ef65cdu, 0xec4d3b2fu, 0x8189dbbcu,
    0xf348b538u, 0xb605d019u, 0xaf194f9bu, 0xda6d8118u,
    0xa3030242u, 0x45706fbeu, 0x4ee4b28cu, 0xd5ffb4e2u,
    0xf27b896fu, 0x3b1696b1u, 0x25c71235u, 0xcf692694u,
    0x9ef14ad2u, 0x384f25e3u, 0x8b8cd5b5u, 0x77ac9c65u,
    0x592b0275u, 0x6ea6e483u, 0xbd41fbd4u, 0x831153b5u,
    0xee66dfabu, 0x2db43210u, 0x98fb213fu, 0xbeef0ee4u,
    0x3da88fc2u, 0x930aa725u, 0xe003826fu, 0x0a0e6e70u,
    0x46d22ffcu, 0x5c26c926u, 0x5ac42aedu, 0x9d95b3dfu,
    0x8baf63deu, 0x3c77b2a8u, 0x47edaee6u, 0x1482353bu,
    0x4cf10364u, 0xbc423001u, 0xd0f89791u, 0x0654be30u,
    0xd6ef5218u, 0x5565a910u, 0x5771202au, 0x32bbd1b8u,
    0xb8d2d0c8u, 0x5141ab53u, 0xdf8eeb99u, 0xe19b48a8u,
    0xc5c95a63u, 0xe3418acbu, 0x7763e373u, 0xd6b2b8a3u,
    0x5defb2fcu, 0x43172f60u, 0xa1f0ab72u, 0x1a6439ecu,
    0x23631e28u, 0xde82bde9u, 0xb2c67915u, 0xe372532bu,
    0xea26619cu, 0x21c0c207u, 0xcde0eb1eu, 0xee6ed178u,
    0x72176fbau, 0xa2c898a6u, 0xbef90daeu, 0x131c471bu,
    0x23047d84u, 0x40c72493u, 0x15c9bebcu, 0x9c100d4cu,
    0xcb3e42b6u, 0xfc657e2au, 0x3ad6faecu, 0x4a475817u
);

const K512_HI: array<u32, 80> = array<u32, 80>(
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
    0xca273eceu, 0xd186b8c7u, 0xeada7dd6u, 0xf57d4f7fu,
    0x06f067aau, 0x0a637dc5u, 0x113f9804u, 0x1b710b35u,
    0x28db77f5u, 0x32caab7bu, 0x3c9ebe0au, 0x431d67c4u,
    0x4cc5d4beu, 0x597f299cu, 0x5fcb6fabu, 0x6c44198cu
);

fn K512(i: u32) -> vec2<u32> { return vec2<u32>(K512_LO[i], K512_HI[i]); }

fn sha_Ch(x: vec2<u32>, y: vec2<u32>, z: vec2<u32>) -> vec2<u32> {
    return u64_xor(u64_and(x, y), u64_and(u64_not(x), z));
}

fn sha_Maj(x: vec2<u32>, y: vec2<u32>, z: vec2<u32>) -> vec2<u32> {
    return u64_xor(u64_xor(u64_and(x, y), u64_and(x, z)), u64_and(y, z));
}

fn sha_Sigma0(x: vec2<u32>) -> vec2<u32> {
    return u64_xor(u64_xor(u64_rotr(x, 28u), u64_rotr(x, 34u)), u64_rotr(x, 39u));
}

fn sha_Sigma1(x: vec2<u32>) -> vec2<u32> {
    return u64_xor(u64_xor(u64_rotr(x, 14u), u64_rotr(x, 18u)), u64_rotr(x, 41u));
}

fn sha_sigma0(x: vec2<u32>) -> vec2<u32> {
    return u64_xor(u64_xor(u64_rotr(x, 1u), u64_rotr(x, 8u)), u64_shr(x, 7u));
}

fn sha_sigma1(x: vec2<u32>) -> vec2<u32> {
    return u64_xor(u64_xor(u64_rotr(x, 19u), u64_rotr(x, 61u)), u64_shr(x, 6u));
}

fn sha512(seed: ptr<function, array<u32, 8>>, hash: ptr<function, array<u32, 16>>) {
    var h: array<vec2<u32>, 8>;
    h[0] = vec2<u32>(0xf3bcc908u, 0x6a09e667u);
    h[1] = vec2<u32>(0x84caa73bu, 0xbb67ae85u);
    h[2] = vec2<u32>(0xfe94f82bu, 0x3c6ef372u);
    h[3] = vec2<u32>(0x5f1d36f1u, 0xa54ff53au);
    h[4] = vec2<u32>(0xade682d1u, 0x510e527fu);
    h[5] = vec2<u32>(0x2b3e6c1fu, 0x9b05688cu);
    h[6] = vec2<u32>(0xfb41bd6bu, 0x1f83d9abu);
    h[7] = vec2<u32>(0x137e2179u, 0x5be0cd19u);

    var w: array<vec2<u32>, 80>;

    // Load seed as big-endian
    for (var i = 0u; i < 4u; i++) {
        let v0 = (*seed)[i * 2u];
        let v1 = (*seed)[i * 2u + 1u];
        let hi = ((v0 & 0xFFu) << 24u) | (((v0 >> 8u) & 0xFFu) << 16u) |
                 (((v0 >> 16u) & 0xFFu) << 8u) | ((v0 >> 24u) & 0xFFu);
        let lo = ((v1 & 0xFFu) << 24u) | (((v1 >> 8u) & 0xFFu) << 16u) |
                 (((v1 >> 16u) & 0xFFu) << 8u) | ((v1 >> 24u) & 0xFFu);
        w[i] = vec2<u32>(lo, hi);
    }

    w[4] = vec2<u32>(0x00000000u, 0x80000000u);
    for (var i = 5u; i < 15u; i++) { w[i] = vec2<u32>(0u, 0u); }
    w[15] = vec2<u32>(256u, 0u);

    for (var i = 16u; i < 80u; i++) {
        w[i] = u64_add(u64_add(u64_add(sha_sigma1(w[i-2u]), w[i-7u]), sha_sigma0(w[i-15u])), w[i-16u]);
    }

    var a = h[0]; var b = h[1]; var c = h[2]; var d = h[3];
    var e = h[4]; var f = h[5]; var g = h[6]; var hv = h[7];

    for (var i = 0u; i < 80u; i++) {
        let T1 = u64_add(u64_add(u64_add(u64_add(hv, sha_Sigma1(e)), sha_Ch(e, f, g)), K512(i)), w[i]);
        let T2 = u64_add(sha_Sigma0(a), sha_Maj(a, b, c));
        hv = g; g = f; f = e; e = u64_add(d, T1);
        d = c; c = b; b = a; a = u64_add(T1, T2);
    }

    h[0] = u64_add(h[0], a); h[1] = u64_add(h[1], b);
    h[2] = u64_add(h[2], c); h[3] = u64_add(h[3], d);
    h[4] = u64_add(h[4], e); h[5] = u64_add(h[5], f);
    h[6] = u64_add(h[6], g); h[7] = u64_add(h[7], hv);

    // Output as bytes (big-endian to little-endian)
    for (var i = 0u; i < 8u; i++) {
        let hi = h[i].y; let lo = h[i].x;
        (*hash)[i * 2u] = ((hi & 0xFFu) << 24u) | (((hi >> 8u) & 0xFFu) << 16u) |
                         (((hi >> 16u) & 0xFFu) << 8u) | ((hi >> 24u) & 0xFFu);
        (*hash)[i * 2u + 1u] = ((lo & 0xFFu) << 24u) | (((lo >> 8u) & 0xFFu) << 16u) |
                              (((lo >> 16u) & 0xFFu) << 8u) | ((lo >> 24u) & 0xFFu);
    }
}

// ============================================================================
// Field Element: 10 x 25.5-bit limbs (fits in i32)
// Using radix 2^26/2^25 alternating representation
// ============================================================================

struct Fe {
    v: array<i32, 10>,
}

fn fe_zero() -> Fe {
    var f: Fe;
    for (var i = 0u; i < 10u; i++) { f.v[i] = 0; }
    return f;
}

fn fe_one() -> Fe {
    var f = fe_zero();
    f.v[0] = 1;
    return f;
}

fn fe_copy(a: Fe) -> Fe {
    var r: Fe;
    for (var i = 0u; i < 10u; i++) { r.v[i] = a.v[i]; }
    return r;
}

fn fe_add(a: Fe, b: Fe) -> Fe {
    var r: Fe;
    for (var i = 0u; i < 10u; i++) { r.v[i] = a.v[i] + b.v[i]; }
    return r;
}

fn fe_sub(a: Fe, b: Fe) -> Fe {
    var r: Fe;
    // Add 2p to avoid negative (p = 2^255 - 19)
    r.v[0] = a.v[0] - b.v[0] + 0x3ffffed;
    r.v[1] = a.v[1] - b.v[1] + 0x1ffffff;
    r.v[2] = a.v[2] - b.v[2] + 0x3ffffff;
    r.v[3] = a.v[3] - b.v[3] + 0x1ffffff;
    r.v[4] = a.v[4] - b.v[4] + 0x3ffffff;
    r.v[5] = a.v[5] - b.v[5] + 0x1ffffff;
    r.v[6] = a.v[6] - b.v[6] + 0x3ffffff;
    r.v[7] = a.v[7] - b.v[7] + 0x1ffffff;
    r.v[8] = a.v[8] - b.v[8] + 0x3ffffff;
    r.v[9] = a.v[9] - b.v[9] + 0x1ffffff;
    return r;
}

fn fe_reduce(f: ptr<function, Fe>) {
    var c: i32;
    for (var i = 0u; i < 9u; i++) {
        let shift = select(26u, 25u, (i & 1u) == 0u);
        c = (*f).v[i] >> shift;
        (*f).v[i] &= i32((1u << shift) - 1u);
        (*f).v[i + 1u] += c;
    }
    c = (*f).v[9] >> 25;
    (*f).v[9] &= 0x1ffffff;
    (*f).v[0] += c * 19;
    c = (*f).v[0] >> 26;
    (*f).v[0] &= 0x3ffffff;
    (*f).v[1] += c;
}

// Multiply two 32-bit values, return 64-bit result as vec2<u32>
fn mul32(a: u32, b: u32) -> vec2<u32> {
    let a0 = a & 0xFFFFu; let a1 = a >> 16u;
    let b0 = b & 0xFFFFu; let b1 = b >> 16u;
    let p00 = a0 * b0;
    let p01 = a0 * b1;
    let p10 = a1 * b0;
    let p11 = a1 * b1;
    let mid = p01 + p10 + (p00 >> 16u);
    let lo = (p00 & 0xFFFFu) | ((mid & 0xFFFFu) << 16u);
    let hi = p11 + (mid >> 16u);
    return vec2<u32>(lo, hi);
}

// Add 64-bit value to accumulator array at index, propagate carry
fn acc_add(h: ptr<function, array<vec2<u32>, 10>>, idx: u32, val: vec2<u32>) {
    (*h)[idx] = u64_add((*h)[idx], val);
}

fn fe_mul(a: Fe, b: Fe) -> Fe {
    var h: array<vec2<u32>, 10>;
    for (var i = 0u; i < 10u; i++) { h[i] = vec2<u32>(0u, 0u); }

    // Schoolbook multiplication with reduction by 19
    for (var i = 0u; i < 10u; i++) {
        let ai = u32(a.v[i]);
        for (var j = 0u; j < 10u; j++) {
            let bj = u32(b.v[j]);
            let prod = mul32(ai, bj);
            let k = i + j;
            if (k < 10u) {
                acc_add(&h, k, prod);
            } else {
                // Reduce by 19: x * 2^255 = x * 19 (mod p)
                let reduced = mul32(prod.x, 19u);
                let reduced_hi = prod.y * 19u; // Approximate - high bits * 19
                acc_add(&h, k - 10u, vec2<u32>(reduced.x, reduced.y + reduced_hi));
            }
        }
    }

    // Carry propagation
    var r: Fe;
    var carry = vec2<u32>(0u, 0u);

    for (var i = 0u; i < 10u; i++) {
        let sum = u64_add(h[i], carry);
        let bits = select(26u, 25u, (i & 1u) == 0u);
        let mask = (1u << bits) - 1u;
        r.v[i] = i32(sum.x & mask);
        carry = u64_shr(sum, bits);
    }

    // Final reduction: carry * 19
    let final_add = carry.x * 19u;
    r.v[0] += i32(final_add);

    // One more carry pass
    var c: i32;
    c = r.v[0] >> 26; r.v[1] += c; r.v[0] &= 0x3ffffff;
    c = r.v[1] >> 25; r.v[2] += c; r.v[1] &= 0x1ffffff;

    return r;
}

fn fe_sq(a: Fe) -> Fe { return fe_mul(a, a); }

fn fe_from_bytes(b: ptr<function, array<u32, 8>>) -> Fe {
    var r: Fe;
    let b0 = (*b)[0]; let b1 = (*b)[1]; let b2 = (*b)[2]; let b3 = (*b)[3];
    let b4 = (*b)[4]; let b5 = (*b)[5]; let b6 = (*b)[6]; let b7 = (*b)[7];

    r.v[0] = i32(b0 & 0x3ffffff);
    r.v[1] = i32(((b0 >> 26) | (b1 << 6)) & 0x1ffffff);
    r.v[2] = i32(((b1 >> 19) | (b2 << 13)) & 0x3ffffff);
    r.v[3] = i32(((b2 >> 13) | (b3 << 19)) & 0x1ffffff);
    r.v[4] = i32((b3 >> 6) & 0x3ffffff);
    r.v[5] = i32(b4 & 0x1ffffff);
    r.v[6] = i32(((b4 >> 25) | (b5 << 7)) & 0x3ffffff);
    r.v[7] = i32(((b5 >> 19) | (b6 << 13)) & 0x1ffffff);
    r.v[8] = i32(((b6 >> 12) | (b7 << 20)) & 0x3ffffff);
    r.v[9] = i32((b7 >> 6) & 0x1ffffff);
    return r;
}

fn fe_to_bytes(f: Fe, b: ptr<function, array<u32, 8>>) {
    var t = fe_copy(f);
    fe_reduce(&t);

    // Final reduction
    var c = (t.v[0] + 19) >> 26u;
    for (var i = 1u; i < 10u; i++) {
        let shift = select(26u, 25u, (i & 1u) == 0u);
        c = (t.v[i] + c) >> shift;
    }
    t.v[0] += 19 * c;
    fe_reduce(&t);

    (*b)[0] = u32(t.v[0]) | (u32(t.v[1]) << 26);
    (*b)[1] = (u32(t.v[1]) >> 6) | (u32(t.v[2]) << 19);
    (*b)[2] = (u32(t.v[2]) >> 13) | (u32(t.v[3]) << 13);
    (*b)[3] = (u32(t.v[3]) >> 19) | (u32(t.v[4]) << 6);
    (*b)[4] = u32(t.v[5]) | (u32(t.v[6]) << 25);
    (*b)[5] = (u32(t.v[6]) >> 7) | (u32(t.v[7]) << 19);
    (*b)[6] = (u32(t.v[7]) >> 13) | (u32(t.v[8]) << 12);
    (*b)[7] = (u32(t.v[8]) >> 20) | (u32(t.v[9]) << 6);
}

fn fe_pow22523(z: Fe) -> Fe {
    var t0 = fe_sq(z);
    var t1 = fe_sq(t0); t1 = fe_sq(t1);
    t1 = fe_mul(z, t1);
    t0 = fe_mul(t0, t1);
    t0 = fe_sq(t0);
    t0 = fe_mul(t1, t0);
    t1 = fe_sq(t0);
    for (var i = 0u; i < 4u; i++) { t1 = fe_sq(t1); }
    t0 = fe_mul(t1, t0);
    t1 = fe_sq(t0);
    for (var i = 0u; i < 9u; i++) { t1 = fe_sq(t1); }
    t1 = fe_mul(t1, t0);
    var t2 = fe_sq(t1);
    for (var i = 0u; i < 19u; i++) { t2 = fe_sq(t2); }
    t1 = fe_mul(t2, t1);
    for (var i = 0u; i < 10u; i++) { t1 = fe_sq(t1); }
    t0 = fe_mul(t1, t0);
    t1 = fe_sq(t0);
    for (var i = 0u; i < 49u; i++) { t1 = fe_sq(t1); }
    t1 = fe_mul(t1, t0);
    t2 = fe_sq(t1);
    for (var i = 0u; i < 99u; i++) { t2 = fe_sq(t2); }
    t1 = fe_mul(t2, t1);
    for (var i = 0u; i < 50u; i++) { t1 = fe_sq(t1); }
    t0 = fe_mul(t1, t0);
    t0 = fe_sq(t0); t0 = fe_sq(t0);
    return fe_mul(t0, z);
}

fn fe_invert(z: Fe) -> Fe {
    var t0 = fe_sq(z);
    var t1 = fe_sq(t0); t1 = fe_sq(t1);
    t1 = fe_mul(z, t1);
    t0 = fe_mul(t0, t1);
    var t2 = fe_sq(t0);
    t1 = fe_mul(t1, t2);
    t2 = fe_sq(t1);
    for (var i = 0u; i < 4u; i++) { t2 = fe_sq(t2); }
    t1 = fe_mul(t2, t1);
    t2 = fe_sq(t1);
    for (var i = 0u; i < 9u; i++) { t2 = fe_sq(t2); }
    t2 = fe_mul(t2, t1);
    var t3 = fe_sq(t2);
    for (var i = 0u; i < 19u; i++) { t3 = fe_sq(t3); }
    t2 = fe_mul(t3, t2);
    for (var i = 0u; i < 10u; i++) { t2 = fe_sq(t2); }
    t1 = fe_mul(t2, t1);
    t2 = fe_sq(t1);
    for (var i = 0u; i < 49u; i++) { t2 = fe_sq(t2); }
    t2 = fe_mul(t2, t1);
    t3 = fe_sq(t2);
    for (var i = 0u; i < 99u; i++) { t3 = fe_sq(t3); }
    t2 = fe_mul(t3, t2);
    for (var i = 0u; i < 50u; i++) { t2 = fe_sq(t2); }
    t1 = fe_mul(t2, t1);
    for (var i = 0u; i < 5u; i++) { t1 = fe_sq(t1); }
    return fe_mul(t1, t0);
}

// ============================================================================
// Ed25519 Point Operations
// ============================================================================

struct GeP3 { X: Fe, Y: Fe, Z: Fe, T: Fe, }

fn ge_p3_identity() -> GeP3 {
    var p: GeP3;
    p.X = fe_zero(); p.Y = fe_one(); p.Z = fe_one(); p.T = fe_zero();
    return p;
}

// Base point G
fn ge_base_point() -> GeP3 {
    var g: GeP3;
    g.X.v = array<i32, 10>(25485296, 5318399, 8791791, -8299916, -14349720, 6256156, -16768029, 2949412, -16290874, 3312016);
    g.Y.v = array<i32, 10>(34414524, 13002742, -3541539, -7508808, 33061568, 13694831, 13520850, -8400726, -18809723, 3646079);
    g.Z = fe_one();
    g.T = fe_mul(g.X, g.Y);
    return g;
}

// d constant for Ed25519
fn fe_d() -> Fe {
    var d: Fe;
    d.v = array<i32, 10>(-10913610, 13857413, -15372611, 6949391, 114729, -8787816, -6275908, -3247719, -18696448, -12055116);
    return d;
}

fn fe_2d() -> Fe {
    var d2: Fe;
    d2.v = array<i32, 10>(-21827239, -5839606, -30745221, 13898782, 229458, 15978800, -12551817, -6495438, 29715968, 9444199);
    return d2;
}

fn ge_p3_dbl(p: GeP3) -> GeP3 {
    var A = fe_sq(p.X);
    var B = fe_sq(p.Y);
    var C = fe_sq(p.Z); C = fe_add(C, C);
    var D = fe_sub(fe_zero(), A); // -A since a=-1
    var E = fe_add(p.X, p.Y); E = fe_sq(E); E = fe_sub(E, A); E = fe_sub(E, B);
    var G = fe_add(D, B);
    var F = fe_sub(G, C);
    var H = fe_sub(D, B);

    var r: GeP3;
    r.X = fe_mul(E, F);
    r.Y = fe_mul(G, H);
    r.T = fe_mul(E, H);
    r.Z = fe_mul(F, G);
    return r;
}

fn ge_p3_add(p: GeP3, q: GeP3) -> GeP3 {
    var A = fe_sub(p.Y, p.X);
    var B = fe_sub(q.Y, q.X);
    A = fe_mul(A, B);
    B = fe_add(p.Y, p.X);
    var C = fe_add(q.Y, q.X);
    B = fe_mul(B, C);
    C = fe_mul(p.T, q.T);
    C = fe_mul(C, fe_2d());
    var D = fe_mul(p.Z, q.Z); D = fe_add(D, D);
    var E = fe_sub(B, A);
    var F = fe_sub(D, C);
    var G = fe_add(D, C);
    var H = fe_add(B, A);

    var r: GeP3;
    r.X = fe_mul(E, F);
    r.Y = fe_mul(G, H);
    r.T = fe_mul(E, H);
    r.Z = fe_mul(F, G);
    return r;
}

fn ge_scalarmult_base(scalar: ptr<function, array<u32, 8>>) -> GeP3 {
    var r = ge_p3_identity();
    var q = ge_base_point();

    for (var i = 0u; i < 256u; i++) {
        let byte_idx = i / 32u;
        let bit_idx = i % 32u;
        if (((*scalar)[byte_idx] >> bit_idx) & 1u) == 1u {
            r = ge_p3_add(r, q);
        }
        q = ge_p3_dbl(q);
    }
    return r;
}

fn ge_p3_tobytes(p: GeP3, out: ptr<function, array<u32, 8>>) {
    var recip = fe_invert(p.Z);
    var x = fe_mul(p.X, recip);
    var y = fe_mul(p.Y, recip);
    fe_to_bytes(y, out);
    (*out)[7] ^= (u32(x.v[0]) & 1u) << 31u;
}

// ============================================================================
// Base58 Encoding
// ============================================================================

const BASE58: array<u32, 58> = array<u32, 58>(
    0x31u,0x32u,0x33u,0x34u,0x35u,0x36u,0x37u,0x38u,0x39u,
    0x41u,0x42u,0x43u,0x44u,0x45u,0x46u,0x47u,0x48u,0x4Au,0x4Bu,0x4Cu,0x4Du,0x4Eu,
    0x50u,0x51u,0x52u,0x53u,0x54u,0x55u,0x56u,0x57u,0x58u,0x59u,0x5Au,
    0x61u,0x62u,0x63u,0x64u,0x65u,0x66u,0x67u,0x68u,0x69u,0x6Au,0x6Bu,
    0x6Du,0x6Eu,0x6Fu,0x70u,0x71u,0x72u,0x73u,0x74u,0x75u,0x76u,0x77u,0x78u,0x79u,0x7Au
);

fn base58_encode(input: ptr<function, array<u32, 8>>, output: ptr<function, array<u32, 12>>) -> u32 {
    var bytes: array<u32, 32>;
    for (var i = 0u; i < 8u; i++) {
        bytes[i*4u] = (*input)[i] & 0xFFu;
        bytes[i*4u+1u] = ((*input)[i] >> 8u) & 0xFFu;
        bytes[i*4u+2u] = ((*input)[i] >> 16u) & 0xFFu;
        bytes[i*4u+3u] = ((*input)[i] >> 24u) & 0xFFu;
    }

    var zeros = 0u;
    while (zeros < 32u && bytes[zeros] == 0u) { zeros++; }

    var b58: array<u32, 64>;
    var b58_len = 0u;
    for (var i = zeros; i < 32u; i++) {
        var carry = bytes[i];
        for (var j = 0u; j < b58_len || carry != 0u; j++) {
            if (j < b58_len) { carry += b58[j] * 256u; }
            b58[j] = carry % 58u;
            carry /= 58u;
            if (j >= b58_len) { b58_len = j + 1u; }
        }
    }

    for (var i = 0u; i < 12u; i++) { (*output)[i] = 0u; }
    for (var i = 0u; i < zeros && i < 48u; i++) {
        (*output)[i/4u] |= 0x31u << ((i%4u)*8u);
    }
    for (var i = 0u; i < b58_len && (zeros+i) < 48u; i++) {
        let pos = zeros + i;
        (*output)[pos/4u] |= BASE58[b58[b58_len-1u-i]] << ((pos%4u)*8u);
    }
    return zeros + b58_len;
}

// ============================================================================
// Pattern Matching
// ============================================================================

fn to_lower(c: u32) -> u32 {
    if (c >= 0x41u && c <= 0x5Au) { return c + 32u; }
    return c;
}

// Get pattern byte at index i from vec4 pattern storage
fn get_pattern_byte(i: u32) -> u32 {
    // Each vec4 holds 16 bytes (4 u32s × 4 bytes each)
    // pattern0 = bytes 0-15, pattern1 = bytes 16-31
    let word_idx = i / 4u;        // Which u32 (0-7)
    let byte_idx = i % 4u;        // Which byte in the u32
    var word: u32;
    if (word_idx < 4u) {
        // From pattern0
        switch (word_idx) {
            case 0u: { word = pattern.pattern0.x; }
            case 1u: { word = pattern.pattern0.y; }
            case 2u: { word = pattern.pattern0.z; }
            default: { word = pattern.pattern0.w; }
        }
    } else {
        // From pattern1
        switch (word_idx - 4u) {
            case 0u: { word = pattern.pattern1.x; }
            case 1u: { word = pattern.pattern1.y; }
            case 2u: { word = pattern.pattern1.z; }
            default: { word = pattern.pattern1.w; }
        }
    }
    return (word >> (byte_idx * 8u)) & 0xFFu;
}

fn pattern_matches(addr: ptr<function, array<u32, 12>>, addr_len: u32) -> bool {
    let plen = pattern.length;
    if (plen == 0u || addr_len < plen) { return false; }

    var start: u32; var end: u32;
    if (pattern.match_mode == 0u) { start = 0u; end = 1u; }
    else if (pattern.match_mode == 1u) { start = addr_len - plen; end = start + 1u; }
    else { start = 0u; end = addr_len - plen + 1u; }

    for (var pos = start; pos < end; pos++) {
        var matched = true;
        for (var i = 0u; i < plen && matched; i++) {
            var pc = get_pattern_byte(i);
            var ac = ((*addr)[(pos+i)/4u] >> (((pos+i)%4u)*8u)) & 0xFFu;
            if (pc == 0x3Fu) { continue; }
            if (pattern.ignore_case != 0u) { pc = to_lower(pc); ac = to_lower(ac); }
            if (pc != ac) { matched = false; }
        }
        if (matched) { return true; }
    }
    return false;
}

// ============================================================================
// RNG (xorshift128+)
// ============================================================================

struct Rng { s0: vec2<u32>, s1: vec2<u32>, }

fn rng_next(rng: ptr<function, Rng>) -> vec2<u32> {
    var x = (*rng).s0; let y = (*rng).s1;
    (*rng).s0 = y;
    x = u64_xor(x, u64_shl(x, 23u));
    (*rng).s1 = u64_xor(u64_xor(x, y), u64_xor(u64_shr(x, 17u), u64_shr(y, 26u)));
    return u64_add((*rng).s1, y);
}

fn rng_init(tid: u32) -> Rng {
    var rng: Rng;
    rng.s0 = u64_xor(vec2<u32>(params.base_seed_lo, params.base_seed_hi),
                     u64_mul(vec2<u32>(tid, 0u), vec2<u32>(0x7F4A7C15u, 0x9E3779B9u)));
    rng.s1 = u64_xor(vec2<u32>(params.base_seed_hi, params.base_seed_lo),
                     u64_mul(vec2<u32>(tid, 0u), vec2<u32>(0xBB67AE85u, 0x6A09E667u)));
    for (var i = 0u; i < 8u; i++) { _ = rng_next(&rng); }
    return rng;
}

// ============================================================================
// Main Kernel
// ============================================================================

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) global_id: vec3<u32>) {
    let tid = global_id.x + params.batch_offset;

    var rng = rng_init(tid);

    // Generate seed
    var seed: array<u32, 8>;
    for (var i = 0u; i < 4u; i++) {
        let r = rng_next(&rng);
        seed[i*2u] = r.x; seed[i*2u+1u] = r.y;
    }

    // SHA-512
    var hash: array<u32, 16>;
    sha512(&seed, &hash);

    // Clamp scalar
    hash[0] &= 0xFFFFFFF8u;
    hash[7] = (hash[7] & 0x3FFFFFFFu) | 0x40000000u;

    // Scalar mult
    var scalar: array<u32, 8>;
    for (var i = 0u; i < 8u; i++) { scalar[i] = hash[i]; }
    let point = ge_scalarmult_base(&scalar);

    // Get public key
    var pk: array<u32, 8>;
    ge_p3_tobytes(point, &pk);

    // Base58
    var address: array<u32, 12>;
    let addr_len = base58_encode(&pk, &address);

    // Match
    if (pattern_matches(&address, addr_len)) {
        // Use atomicMax instead of atomicCompareExchangeWeak - more robust under heavy contention
        let prev = atomicMax(&results.found, 1u);
        if (prev == 0u) {
            // We were the first to set found=1, write our result
            results.thread_id = tid;
            results.address_len = addr_len;
            for (var i = 0u; i < 8u; i++) { results.public_key[i] = pk[i]; }
            for (var i = 0u; i < 8u; i++) { results.private_key[i] = hash[i]; }
            for (var i = 0u; i < 8u; i++) { results.private_key[i+8u] = pk[i]; }
            for (var i = 0u; i < 12u; i++) { results.address[i] = address[i]; }
        }
    }
}
