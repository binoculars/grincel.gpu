#include <metal_stdlib>
using namespace metal;

// ============================================================================
// SHA-512 Implementation
// ============================================================================

constant uint64_t K512[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

inline uint64_t rotr64(uint64_t x, uint32_t n) {
    return (x >> n) | (x << (64 - n));
}

inline uint64_t Ch(uint64_t x, uint64_t y, uint64_t z) {
    return (x & y) ^ (~x & z);
}

inline uint64_t Maj(uint64_t x, uint64_t y, uint64_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

inline uint64_t Sigma0(uint64_t x) {
    return rotr64(x, 28) ^ rotr64(x, 34) ^ rotr64(x, 39);
}

inline uint64_t Sigma1(uint64_t x) {
    return rotr64(x, 14) ^ rotr64(x, 18) ^ rotr64(x, 41);
}

inline uint64_t sigma0(uint64_t x) {
    return rotr64(x, 1) ^ rotr64(x, 8) ^ (x >> 7);
}

inline uint64_t sigma1(uint64_t x) {
    return rotr64(x, 19) ^ rotr64(x, 61) ^ (x >> 6);
}

// SHA-512 hash of 32-byte input, returns 64-byte hash
void sha512_32bytes(thread const uint8_t* input, thread uint8_t* output) {
    uint64_t h[8] = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
        0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
    };

    // Prepare message block (32 bytes + padding)
    uint64_t w[80];

    // Copy input as big-endian uint64
    for (int i = 0; i < 4; i++) {
        uint64_t val = 0;
        for (int j = 0; j < 8; j++) {
            val = (val << 8) | input[i * 8 + j];
        }
        w[i] = val;
    }

    // Padding: 1 bit, then zeros, then length
    w[4] = 0x8000000000000000ULL;  // 1 bit followed by zeros
    for (int i = 5; i < 15; i++) w[i] = 0;
    w[15] = 256;  // Length in bits (32 * 8 = 256)

    // Extend
    for (int i = 16; i < 80; i++) {
        w[i] = sigma1(w[i-2]) + w[i-7] + sigma0(w[i-15]) + w[i-16];
    }

    // Compress
    uint64_t a = h[0], b = h[1], c = h[2], d = h[3];
    uint64_t e = h[4], f = h[5], g = h[6], hh = h[7];

    for (int i = 0; i < 80; i++) {
        uint64_t T1 = hh + Sigma1(e) + Ch(e, f, g) + K512[i] + w[i];
        uint64_t T2 = Sigma0(a) + Maj(a, b, c);
        hh = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }

    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;

    // Output as big-endian bytes
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 8; j++) {
            output[i * 8 + j] = (h[i] >> (56 - j * 8)) & 0xFF;
        }
    }
}

// ============================================================================
// Curve25519 Field Arithmetic (mod 2^255 - 19)
// ============================================================================

// Field element: 5 x 51-bit limbs
struct Fe {
    int64_t v[5];
};

// Reduce a field element
void fe_reduce(thread Fe& f) {
    int64_t c;
    for (int i = 0; i < 4; i++) {
        c = f.v[i] >> 51;
        f.v[i] &= 0x7ffffffffffffLL;
        f.v[i + 1] += c;
    }
    c = f.v[4] >> 51;
    f.v[4] &= 0x7ffffffffffffLL;
    f.v[0] += c * 19;

    c = f.v[0] >> 51;
    f.v[0] &= 0x7ffffffffffffLL;
    f.v[1] += c;
}

void fe_from_bytes(thread Fe& f, thread const uint8_t* b) {
    uint64_t h0 = uint64_t(b[0]) | (uint64_t(b[1]) << 8) | (uint64_t(b[2]) << 16) |
                  (uint64_t(b[3]) << 24) | (uint64_t(b[4]) << 32) | (uint64_t(b[5]) << 40) |
                  ((uint64_t(b[6]) & 0x07) << 48);
    uint64_t h1 = (uint64_t(b[6]) >> 3) | (uint64_t(b[7]) << 5) | (uint64_t(b[8]) << 13) |
                  (uint64_t(b[9]) << 21) | (uint64_t(b[10]) << 29) | (uint64_t(b[11]) << 37) |
                  ((uint64_t(b[12]) & 0x3f) << 45);
    uint64_t h2 = (uint64_t(b[12]) >> 6) | (uint64_t(b[13]) << 2) | (uint64_t(b[14]) << 10) |
                  (uint64_t(b[15]) << 18) | (uint64_t(b[16]) << 26) | (uint64_t(b[17]) << 34) |
                  ((uint64_t(b[18]) & 0x01) << 42) | (uint64_t(b[19]) << 43);
    uint64_t h3 = (uint64_t(b[19]) >> 8) | (uint64_t(b[20])) | (uint64_t(b[21]) << 8) |
                  (uint64_t(b[22]) << 16) | (uint64_t(b[23]) << 24) | (uint64_t(b[24]) << 32) |
                  ((uint64_t(b[25]) & 0x0f) << 40);
    uint64_t h4 = (uint64_t(b[25]) >> 4) | (uint64_t(b[26]) << 4) | (uint64_t(b[27]) << 12) |
                  (uint64_t(b[28]) << 20) | (uint64_t(b[29]) << 28) | (uint64_t(b[30]) << 36) |
                  ((uint64_t(b[31]) & 0x7f) << 44);

    f.v[0] = h0 & 0x7ffffffffffffLL;
    f.v[1] = h1 & 0x7ffffffffffffLL;
    f.v[2] = h2 & 0x7ffffffffffffLL;
    f.v[3] = h3 & 0x7ffffffffffffLL;
    f.v[4] = h4 & 0x7ffffffffffffLL;
}

void fe_to_bytes(thread uint8_t* b, thread const Fe& f) {
    Fe t = f;
    fe_reduce(t);

    // Additional reduction if needed
    int64_t c = (t.v[0] + 19) >> 51;
    c = (t.v[1] + c) >> 51;
    c = (t.v[2] + c) >> 51;
    c = (t.v[3] + c) >> 51;
    c = (t.v[4] + c) >> 51;
    t.v[0] += 19 * c;

    c = t.v[0] >> 51; t.v[0] &= 0x7ffffffffffffLL; t.v[1] += c;
    c = t.v[1] >> 51; t.v[1] &= 0x7ffffffffffffLL; t.v[2] += c;
    c = t.v[2] >> 51; t.v[2] &= 0x7ffffffffffffLL; t.v[3] += c;
    c = t.v[3] >> 51; t.v[3] &= 0x7ffffffffffffLL; t.v[4] += c;
    t.v[4] &= 0x7ffffffffffffLL;

    uint64_t h0 = t.v[0] | (t.v[1] << 51);
    uint64_t h1 = (t.v[1] >> 13) | (t.v[2] << 38);
    uint64_t h2 = (t.v[2] >> 26) | (t.v[3] << 25);
    uint64_t h3 = (t.v[3] >> 39) | (t.v[4] << 12);

    b[0] = h0 & 0xff; b[1] = (h0 >> 8) & 0xff; b[2] = (h0 >> 16) & 0xff; b[3] = (h0 >> 24) & 0xff;
    b[4] = (h0 >> 32) & 0xff; b[5] = (h0 >> 40) & 0xff; b[6] = (h0 >> 48) & 0xff; b[7] = (h0 >> 56) & 0xff;
    b[8] = h1 & 0xff; b[9] = (h1 >> 8) & 0xff; b[10] = (h1 >> 16) & 0xff; b[11] = (h1 >> 24) & 0xff;
    b[12] = (h1 >> 32) & 0xff; b[13] = (h1 >> 40) & 0xff; b[14] = (h1 >> 48) & 0xff; b[15] = (h1 >> 56) & 0xff;
    b[16] = h2 & 0xff; b[17] = (h2 >> 8) & 0xff; b[18] = (h2 >> 16) & 0xff; b[19] = (h2 >> 24) & 0xff;
    b[20] = (h2 >> 32) & 0xff; b[21] = (h2 >> 40) & 0xff; b[22] = (h2 >> 48) & 0xff; b[23] = (h2 >> 56) & 0xff;
    b[24] = h3 & 0xff; b[25] = (h3 >> 8) & 0xff; b[26] = (h3 >> 16) & 0xff; b[27] = (h3 >> 24) & 0xff;
    b[28] = (h3 >> 32) & 0xff; b[29] = (h3 >> 40) & 0xff; b[30] = (h3 >> 48) & 0xff; b[31] = (h3 >> 56) & 0xff;
}

void fe_add(thread Fe& r, thread const Fe& a, thread const Fe& b) {
    for (int i = 0; i < 5; i++) r.v[i] = a.v[i] + b.v[i];
}

void fe_sub(thread Fe& r, thread const Fe& a, thread const Fe& b) {
    // Add 2p to avoid negative numbers
    r.v[0] = a.v[0] - b.v[0] + 0xfffffffffffda;
    r.v[1] = a.v[1] - b.v[1] + 0xffffffffffffe;
    r.v[2] = a.v[2] - b.v[2] + 0xffffffffffffe;
    r.v[3] = a.v[3] - b.v[3] + 0xffffffffffffe;
    r.v[4] = a.v[4] - b.v[4] + 0xffffffffffffe;
}

// 51-bit limb products do not fit in int64. Accumulate them in 128 bits.
struct U128 {
    uint64_t lo;
    uint64_t hi;
};

U128 u128_from_u64(uint64_t x) {
    U128 r;
    r.lo = x;
    r.hi = 0;
    return r;
}

U128 u128_mul_u64(uint64_t a, uint64_t b) {
    uint64_t a0 = a & 0xffffffffULL;
    uint64_t a1 = a >> 32;
    uint64_t b0 = b & 0xffffffffULL;
    uint64_t b1 = b >> 32;
    uint64_t p0 = a0 * b0;
    uint64_t p1 = a0 * b1;
    uint64_t p2 = a1 * b0;
    uint64_t p3 = a1 * b1;
    uint64_t mid = (p0 >> 32) + (p1 & 0xffffffffULL) + (p2 & 0xffffffffULL);
    U128 r;
    r.lo = (p0 & 0xffffffffULL) | (mid << 32);
    r.hi = p3 + (p1 >> 32) + (p2 >> 32) + (mid >> 32);
    return r;
}

U128 u128_add(U128 a, U128 b) {
    U128 r;
    r.lo = a.lo + b.lo;
    r.hi = a.hi + b.hi + ((r.lo < a.lo) ? 1ULL : 0ULL);
    return r;
}

uint64_t u128_shr51(U128 a) {
    return (a.lo >> 51) | (a.hi << 13);
}

void fe_mul(thread Fe& r, thread const Fe& a, thread const Fe& b) {
    uint64_t ax[5];
    uint64_t bx[5];
    for (int i = 0; i < 5; i++) {
        ax[i] = uint64_t(a.v[i]);
        bx[i] = uint64_t(b.v[i]);
    }
    uint64_t a19_1 = 19ULL * ax[1];
    uint64_t a19_2 = 19ULL * ax[2];
    uint64_t a19_3 = 19ULL * ax[3];
    uint64_t a19_4 = 19ULL * ax[4];

    U128 rr[5];
    rr[0] = u128_add(u128_add(u128_add(u128_add(
        u128_mul_u64(ax[0], bx[0]), u128_mul_u64(a19_1, bx[4])),
        u128_mul_u64(a19_2, bx[3])), u128_mul_u64(a19_3, bx[2])),
        u128_mul_u64(a19_4, bx[1]));
    rr[1] = u128_add(u128_add(u128_add(u128_add(
        u128_mul_u64(ax[0], bx[1]), u128_mul_u64(ax[1], bx[0])),
        u128_mul_u64(a19_2, bx[4])), u128_mul_u64(a19_3, bx[3])),
        u128_mul_u64(a19_4, bx[2]));
    rr[2] = u128_add(u128_add(u128_add(u128_add(
        u128_mul_u64(ax[0], bx[2]), u128_mul_u64(ax[1], bx[1])),
        u128_mul_u64(ax[2], bx[0])), u128_mul_u64(a19_3, bx[4])),
        u128_mul_u64(a19_4, bx[3]));
    rr[3] = u128_add(u128_add(u128_add(u128_add(
        u128_mul_u64(ax[0], bx[3]), u128_mul_u64(ax[1], bx[2])),
        u128_mul_u64(ax[2], bx[1])), u128_mul_u64(ax[3], bx[0])),
        u128_mul_u64(a19_4, bx[4]));
    rr[4] = u128_add(u128_add(u128_add(u128_add(
        u128_mul_u64(ax[0], bx[4]), u128_mul_u64(ax[1], bx[3])),
        u128_mul_u64(ax[2], bx[2])), u128_mul_u64(ax[3], bx[1])),
        u128_mul_u64(ax[4], bx[0]));

    const uint64_t MASK = 0x7ffffffffffffULL;
    uint64_t rs[5];
    for (int i = 0; i < 4; i++) {
        rs[i] = rr[i].lo & MASK;
        rr[i + 1] = u128_add(rr[i + 1], u128_from_u64(u128_shr51(rr[i])));
    }
    rs[4] = rr[4].lo & MASK;
    uint64_t carry = u128_shr51(rr[4]);
    rs[0] += 19ULL * carry;

    for (int i = 0; i < 4; i++) {
        carry = rs[i] >> 51;
        rs[i] &= MASK;
        rs[i + 1] += carry;
    }
    carry = rs[4] >> 51;
    rs[4] &= MASK;
    rs[0] += 19ULL * carry;
    for (int i = 0; i < 4; i++) {
        carry = rs[i] >> 51;
        rs[i] &= MASK;
        rs[i + 1] += carry;
    }
    rs[4] &= MASK;

    for (int i = 0; i < 5; i++) r.v[i] = int64_t(rs[i]);
}

void fe_sq(thread Fe& r, thread const Fe& a) {
    fe_mul(r, a, a);
}

void fe_pow22523(thread Fe& r, thread const Fe& z) {
    Fe t0, t1, t2;

    fe_sq(t0, z);
    fe_sq(t1, t0);
    fe_sq(t1, t1);
    fe_mul(t1, z, t1);
    fe_mul(t0, t0, t1);
    fe_sq(t0, t0);
    fe_mul(t0, t1, t0);
    fe_sq(t1, t0);
    for (int i = 0; i < 4; i++) fe_sq(t1, t1);
    fe_mul(t0, t1, t0);
    fe_sq(t1, t0);
    for (int i = 0; i < 9; i++) fe_sq(t1, t1);
    fe_mul(t1, t1, t0);
    fe_sq(t2, t1);
    for (int i = 0; i < 19; i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);
    for (int i = 0; i < 10; i++) fe_sq(t1, t1);
    fe_mul(t0, t1, t0);
    fe_sq(t1, t0);
    for (int i = 0; i < 49; i++) fe_sq(t1, t1);
    fe_mul(t1, t1, t0);
    fe_sq(t2, t1);
    for (int i = 0; i < 99; i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);
    for (int i = 0; i < 50; i++) fe_sq(t1, t1);
    fe_mul(t0, t1, t0);
    fe_sq(t0, t0);
    fe_sq(t0, t0);
    fe_mul(r, t0, z);
}

void fe_invert(thread Fe& r, thread const Fe& z) {
    Fe t0, t1, t2, t3;

    fe_sq(t0, z);
    fe_sq(t1, t0);
    fe_sq(t1, t1);
    fe_mul(t1, z, t1);
    fe_mul(t0, t0, t1);
    fe_sq(t2, t0);
    fe_mul(t1, t1, t2);
    fe_sq(t2, t1);
    for (int i = 0; i < 4; i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);
    fe_sq(t2, t1);
    for (int i = 0; i < 9; i++) fe_sq(t2, t2);
    fe_mul(t2, t2, t1);
    fe_sq(t3, t2);
    for (int i = 0; i < 19; i++) fe_sq(t3, t3);
    fe_mul(t2, t3, t2);
    for (int i = 0; i < 10; i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);
    fe_sq(t2, t1);
    for (int i = 0; i < 49; i++) fe_sq(t2, t2);
    fe_mul(t2, t2, t1);
    fe_sq(t3, t2);
    for (int i = 0; i < 99; i++) fe_sq(t3, t3);
    fe_mul(t2, t3, t2);
    for (int i = 0; i < 50; i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);
    for (int i = 0; i < 5; i++) fe_sq(t1, t1);
    fe_mul(r, t1, t0);
}

// ============================================================================
// Ed25519 Point Operations
// ============================================================================

// Edwards curve point in extended coordinates (X:Y:Z:T)
struct GeP3 {
    Fe X, Y, Z, T;
};

// Precomputed point for scalar multiplication
struct GePrecomp {
    Fe yplusx, yminusx, xy2d;
};

void ge_p3_0(thread GeP3& p) {
    for (int i = 0; i < 5; i++) {
        p.X.v[i] = 0;
        p.Y.v[i] = (i == 0) ? 1 : 0;
        p.Z.v[i] = (i == 0) ? 1 : 0;
        p.T.v[i] = 0;
    }
}

void ge_p3_dbl(thread GeP3& r, thread const GeP3& p) {
    Fe A, B, C, D, E, F, G, H;

    fe_sq(A, p.X);
    fe_sq(B, p.Y);
    fe_sq(C, p.Z);
    fe_add(C, C, C);

    // D = -A (because a = -1 in Ed25519)
    D.v[0] = 0xfffffffffffda - A.v[0];
    D.v[1] = 0xffffffffffffe - A.v[1];
    D.v[2] = 0xffffffffffffe - A.v[2];
    D.v[3] = 0xffffffffffffe - A.v[3];
    D.v[4] = 0xffffffffffffe - A.v[4];

    fe_add(E, p.X, p.Y);
    fe_sq(E, E);
    fe_sub(E, E, A);
    fe_sub(E, E, B);

    fe_add(G, D, B);
    fe_sub(F, G, C);
    fe_sub(H, D, B);

    fe_mul(r.X, E, F);
    fe_mul(r.Y, G, H);
    fe_mul(r.T, E, H);
    fe_mul(r.Z, F, G);
}

// base[i][j] = (j+1) * 256^i * B, as (y+x, y-x, 2*d*x*y), 5 canonical limbs each.
// Generated by tools/gen_base_table.zig.
constant int64_t BASE_PRECOMP[3840] = {
// BASE_PRECOMP_START
0x493c6f58c3b85L, 0xdf7181c325f7L, 0xf50b0b3e4cb7L, 0x5329385a44c32L, 0x7cf9d3a33d4bL, 0x3905d740913eL, 0xba2817d673a2L, 0x23e2827f4e67cL,
0x133d2e0c21a34L, 0x44fd2f9298f81L, 0x11205877aaa68L, 0x479955893d579L, 0x50d66309b67a0L, 0x2d42d0dbee5eeL, 0x6f117b689f0c6L, 0x4e7fc933c71d7L,
0x2cf41feb6b244L, 0x7581c0a7d1a76L, 0x7172d534d32f0L, 0x590c063fa87d2L, 0x1a56042b4d5a8L, 0x189cc159ed153L, 0x5b8deaa3cae04L, 0x2aaf04f11b5d8L,
0x6bb595a669c92L, 0x2a8b3a59b7a5fL, 0x3abb359ef087fL, 0x4f5a8c4db05afL, 0x5b9a807d04205L, 0x701af5b13ea50L, 0x5b0a84cee9730L, 0x61d10c97155e4L,
0x4059cc8096a10L, 0x47a608da8014fL, 0x7a164e1b9a80fL, 0x11fe8a4fcd265L, 0x7bcb8374faaccL, 0x52f5af4ef4d4fL, 0x5314098f98d10L, 0x2ab91587555bdL,
0x6933f0dd0d889L, 0x44386bb4c4295L, 0x3cb6d3162508cL, 0x26368b872a2c6L, 0x5a2826af12b9bL, 0x351b98efc099fL, 0x68fbfa4a7050eL, 0x42a49959d971bL,
0x393e51a469efdL, 0x680e910321e58L, 0x6050a056818bfL, 0x62acc1f5532bfL, 0x28141ccc9fa25L, 0x24d61f471e683L, 0x27933f4c7445aL, 0x3fbe9c476ff09L,
0xaf6b982e4b42L, 0xad1251ba78e5L, 0x715aeedee7c88L, 0x7f9d0cbf63553L, 0x2bc4408a5bb33L, 0x78ebdda05442L, 0x2ffb112354123L, 0x375ee8df5862dL,
0x2945ccf146e20L, 0x182c3a447d6baL, 0x22964e536eff2L, 0x192821f540053L, 0x2f9f19e788e5cL, 0x154a7e73eb1b5L, 0x3dbf1812a8285L, 0xfa17ba3f9797L,
0x6f69cb49c3820L, 0x34d5a0db3858dL, 0x43aabe696b3bbL, 0x4eeeb77157131L, 0x1201915f10741L, 0x1669cda6c9c56L, 0x45ec032db346dL, 0x51e57bb6a2cc3L,
0x6b67b7d8ca4L, 0x84fa44e72933L, 0x1154ee55d6f8aL, 0x4425d842e7390L, 0x38b64c41ae417L, 0x4326702ea4b71L, 0x6834376030b5L, 0xef0512f9c380L,
0xf1a9f2512584L, 0x10b8e91a9f0d6L, 0x25cd0944ea3bfL, 0x75673b81a4d63L, 0x150b925d1c0d4L, 0x13f38d9294114L, 0x461bea69283c9L, 0x72c9aaa3221b1L,
0x267774474f74dL, 0x64b0e9b28085L, 0x3f04ef53b27c9L, 0x1d6edd5d2e531L, 0x36dc801b8b3a2L, 0xe0a7d4935e30L, 0x1deb7cecc0d7dL, 0x53a94e20dd2cL,
0x7a9fbb1c6a0f9L, 0x7596604dd3e8fL, 0x6fc510e058b36L, 0x3670c8db2cc0dL, 0x297d899ce332fL, 0x915e76061bceL, 0x75dedf39234d9L, 0x1c36ab1f3c54L,
0xf08fee58f5daL, 0xe19613a0d637L, 0x3a9024a1320e0L, 0x1f5d9c9a2911aL, 0x7117994fafcf8L, 0x2d8a8cae28dc5L, 0x74ab1b2090c87L, 0x26907c5c2ecc4L,
0x4dd0e632f9c1dL, 0x2ced12622a5d9L, 0x18de9614742daL, 0x79ca96fdbb5d4L, 0x6dd37d49a00eeL, 0x3635449aa515eL, 0x3e178d0475dabL, 0x50b4712a19712L,
0x2dcc2860ff4adL, 0x30d76d6f03d31L, 0x444172106e4c7L, 0x1251afed2d88L, 0x534fc9bed4f5aL, 0x5d85a39cf5234L, 0x10c697112e864L, 0x62aa08358c805L,
0x46f440848e194L, 0x447b771a8f52bL, 0x377ba3269d31dL, 0x3bf9baf55080L, 0x3c4277dbe5fdeL, 0x5a335afd44c92L, 0xc1164099753eL, 0x70487006fe423L,
0x25e61cabed66fL, 0x3e128cc586604L, 0x5968b2e8fc7e2L, 0x49a3d5bd61cfL, 0x116505b1ef6e6L, 0x566d78634586eL, 0x54285c65a2fd0L, 0x55e62ccf87420L,
0x46bb961b19044L, 0x1153405712039L, 0x14fba5f34793bL, 0x7a49f9cc10834L, 0x2b513788a22c6L, 0x5ff4b6ef2395bL, 0x2ec8e5af607bfL, 0x33975bca5ecc3L,
0x746166985f7d4L, 0x9939000ae79aL, 0x5844c7964f97aL, 0x13617e1f95b3dL, 0x14829cea83fc5L, 0x70b2f4e71ecb8L, 0x728148efc643cL, 0x753e03995b76L,
0x5bf5fb2ab6767L, 0x5fc3bc4535d7L, 0x37b8497dd95c2L, 0x61549d6b4ffe8L, 0x217a22db1d138L, 0xb9cf062eb09eL, 0x2fd9c71e5f758L, 0xb3ae52afdeddL,
0x19da76619e497L, 0x6fa0654d2558eL, 0x78219d25e41d4L, 0x373767475c651L, 0x95cb14246590L, 0x2d82aa6ac68L, 0x442f183bc4851L, 0x6464f1c0a0644L,
0x6bf5905730907L, 0x299fd40d1add9L, 0x5f2de9a04e5f7L, 0x7c0eebacc1c59L, 0x4cca1b1f8290aL, 0x1fbea56c3b18fL, 0x778f1e1415b8aL, 0x6f75874efc1f4L,
0x28a694019027fL, 0x52b37a96bdc4dL, 0x2521cf67a635L, 0x46720772f5ee4L, 0x632c0f359d622L, 0x2b2092ba3e252L, 0x662257c112680L, 0x1753d9f7cd6L,
0x7ee0b0a9d5294L, 0x381fbeb4cca27L, 0x7841f3a3e639dL, 0x676ea30c3445fL, 0x3fa00a7e71382L, 0x1232d963ddb34L, 0x35692e70b078dL, 0x247ca14777a1fL,
0x6db556be8fcd0L, 0x12b5fe2fa048eL, 0x37c26ad6f1e92L, 0x46a0971227be5L, 0x4722f0d2d9b4cL, 0x3dc46204ee03aL, 0x6f7e93c20796cL, 0xfbc496fce34dL,
0x575be6b7dae3eL, 0x4a31585cee609L, 0x37e9023930ffL, 0x749b76f96fb12L, 0x2f604aea6ae05L, 0x637dc939323ebL, 0x3fdad9b048d47L, 0xa8b0d4045af7L,
0xfcec10f01e02L, 0x2d29dc4244e45L, 0x6927b1bc147beL, 0x308534ac0839L, 0x4853664033f41L, 0x413779166feabL, 0x558a649fe1e44L, 0x44635aeefcc89L,
0x1ff434887f2baL, 0xf981220e2d44L, 0x4901aa7183c51L, 0x1b7548c1af8f0L, 0x7848c53368116L, 0x1b64e7383de9L, 0x109fbb0587c8fL, 0x41bb887b726d1L,
0x34c597c6691aeL, 0x7a150b6990fc4L, 0x52beb9d922274L, 0x70eed7164861aL, 0xa871e070c6a9L, 0x7d44744346beL, 0x282b6a564a81dL, 0x4ed80f875236bL,
0x6fbbe1d450c50L, 0x4eb728c12fcdbL, 0x1b5994bbc8989L, 0x74b7ba84c0660L, 0x75678f1cdaeb8L, 0x23206b0d6f10cL, 0x3ee7300f2685dL, 0x27947841e7518L,
0x32c7388dae87fL, 0x414add3971be9L, 0x1850832f0ef1L, 0x7d47c6a2cfb89L, 0x255e49e7dd6b7L, 0x38c2163d59ebaL, 0x3861f2a005845L, 0x2e11e4ccbaec9L,
0x1381576297912L, 0x2d0148ef0d6e0L, 0x3522a8de787fbL, 0x2ee055e74f9d2L, 0x64038f6310813L, 0x148cf58d34c9eL, 0x72f7d9ae4756dL, 0x7711e690ffc4aL,
0x582a2355b0d16L, 0xdccfe885b6b4L, 0x278febad4eaeaL, 0x492f67934f027L, 0x7ded0815528d4L, 0x58461511a6612L, 0x5ea2e50de1544L, 0x3ff2fa1ebd5dbL,
0x2681f8c933966L, 0x3840521931635L, 0x674f14a308652L, 0x3bd9c88a94890L, 0x4104dd02fe9c6L, 0x14e06db096ab8L, 0x1219c89e6b024L, 0x278abd486a2dbL,
0x240b292609520L, 0x165b5a48efcaL, 0x2bf5e1124422aL, 0x673146756ae56L, 0x14ad99a87e830L, 0x1eaca65b080fdL, 0x2c863b00afaf5L, 0xa474a0846a76L,
0x99a5ef981e32L, 0x2a8ae3c4bbfe6L, 0x45c34af14832cL, 0x591b67d9bffecL, 0x1b3719f18b55dL, 0x754318c83d337L, 0x27c17b7919797L, 0x145b084089b61L,
0x489b4f8670301L, 0x70d1c80b49bfaL, 0x3d57e7d914625L, 0x3c0722165e545L, 0x5e5b93819e04fL, 0x3de02ec7ca8f7L, 0x2102d3aeb92efL, 0x68c22d50c3a46L,
0x42ea89385894eL, 0x75f9ebf55f38cL, 0x49f5fbba496cbL, 0x5628c1e9c572eL, 0x598b108e822abL, 0x55d8fae29361aL, 0xadc8d1a97b28L, 0x6a1a6c288675L,
0x49a108a5bcfd4L, 0x6178c8e7d6612L, 0x1f03473710375L, 0x73a49614a6098L, 0x5604a86dcbfa6L, 0xd1d47c1764b6L, 0x1c08316a2e51L, 0x2b3db45c95045L,
0x1634f818d300cL, 0x20989e89fe274L, 0x4278b85eaec2eL, 0xef59657be2ceL, 0x72fd169588770L, 0x2e9b205260b30L, 0x730b9950f7059L, 0x777fd3a2dcc7fL,
0x594a9fb124932L, 0x1f8e80ca15f0L, 0x714d13cec3269L, 0x403ed1d0ca67L, 0x32d35874ec552L, 0x1f3048df1b929L, 0x300d73b179b23L, 0x6e67be5a37d0bL,
0x5bd7454308303L, 0x4932115e7792aL, 0x457b9bbb930b8L, 0x68f5d8b193226L, 0x4164e8f1ed456L, 0x5bb7db123067fL, 0x2d19528b24cc2L, 0x4ac66b8302ff3L,
0x701c8d9fdad51L, 0x6c1b35c5b3727L, 0x133a78007380aL, 0x1f467c6ca62beL, 0x2c4232a5dc12cL, 0x7551dc013b087L, 0x690c11b03bcdL, 0x740dca6d58f0eL,
0x28c570478433cL, 0x1d8502873a463L, 0x7641e7eded49cL, 0x1ecedd54cf571L, 0x2c03f5256c2b0L, 0xee0752cfce4eL, 0x660dd8116fbe9L, 0x55167130fffebL,
0x1c682b885955cL, 0x161d25fa963eaL, 0x718757b53a47dL, 0x619e18b0f2f21L, 0x5fbdfe4c1ec04L, 0x5d798c81ebb92L, 0x699468bdbd96bL, 0x53de66aa91948L,
0x45f81a599b1bL, 0x3f7a8bd214193L, 0x71d4da412331aL, 0x293e1c4e6c4a2L, 0x72f46f4dafecfL, 0x2948ffadef7a3L, 0x11ecdfdf3bc04L, 0x3c2e98ffeed25L,
0x525219a473905L, 0x6134b925112e1L, 0x6bb942bb406edL, 0x70c445c0dde2L, 0x411d822c4d7a3L, 0x5b605c447f032L, 0x1fec6f0e7f04cL, 0x3cebc692c477dL,
0x77986a19a95eL, 0x6eaaaa1778b0fL, 0x2f12fef4cc5abL, 0x5805920c47c89L, 0x1924771f9972cL, 0x38bbddf9fc040L, 0x1f7000092b281L, 0x24a76dcea8aebL,
0x522b2dfc0c740L, 0x7e8193480e148L, 0x33fd9a04341b9L, 0x3c863678a20bcL, 0x5e607b2518a43L, 0x4431ca596cf14L, 0x15da7c801405L, 0x3c9b6f8f10b5L,
0x346922934017L, 0x201f33139e457L, 0x31d8f6cdf1818L, 0x1f86c4b144b16L, 0x39875b8d73e9dL, 0x2fbf0d9ffa7b3L, 0x5067acab6ccddL, 0x27f6b08039d51L,
0x4802f8000dfaaL, 0x9692a062c525L, 0x1baea91075817L, 0x397cba8862460L, 0x5c3fbc81379e7L, 0x41bbc255e2f02L, 0x6a3f756998650L, 0x1297fd4e07c42L,
0x771b4022c1e1cL, 0x13093f05959b2L, 0x1bd352f2ec618L, 0x75789b88ea86L, 0x61d1117ea48b9L, 0x2339d320766e6L, 0x5d986513a2fa7L, 0x63f3a99e11b0fL,
0x28a0ecfd6b26dL, 0x53b6835e18d8fL, 0x331a189219971L, 0x12f3a9d7572afL, 0x10d00e953c4caL, 0x603df116f2f8aL, 0x33dc276e0e088L, 0x1ac9619ff649aL,
0x66f45fb4f80c6L, 0x3cc38eeb9fea2L, 0x107647270db1fL, 0x710f1ea740dc8L, 0x31167c6b83bdfL, 0x33842524b1068L, 0x77dd39d30fe45L, 0x189432141a0d0L,
0x88fe4eb8c225L, 0x612436341f08bL, 0x349e31a2d2638L, 0x137a7fa6b16cL, 0x681ae92777edcL, 0x222bfc5f8dc51L, 0x1522aa3178d90L, 0x541db874e898dL,
0x62d80fb841b33L, 0x3e6ef027fa97L, 0x7a03c9e9633e8L, 0x46ebe2309e5efL, 0x2f5369614938L, 0x356e5ada20587L, 0x11bc89f6bf902L, 0x36746419c8dbL,
0x45fe70f505243L, 0x24920c8951491L, 0x107ec61944c5eL, 0x72752e017c01fL, 0x122b7dda2e97aL, 0x16619f6db57a2L, 0x75a6960c0b8cL, 0x6dde1c5e41b49L,
0x42e3f516da341L, 0x16a03fda8e79eL, 0x428d1623a0e39L, 0x74a4401a308fdL, 0x6ed4b9558109L, 0x746f1f6a08867L, 0x4636f5c6f2321L, 0x1d81592d60bd3L,
0x5b69f7b85c5e8L, 0x17a2d175650ecL, 0x4cc3e6dbfc19eL, 0x73e1d3873be0eL, 0x3a5f6d51b0af8L, 0x68756a60dac5fL, 0x55d757b8aec26L, 0x3383df45f80bdL,
0x6783f8c9f96a6L, 0x20234a7789ecdL, 0x20db67178b252L, 0x73aa3da2c0edaL, 0x79045c01c70d3L, 0x1b37b15251059L, 0x7cd682353cffeL, 0x5cd6068acf4f3L,
0x3079afc7a74ccL, 0x58097650b64b4L, 0x47fabac9c4e99L, 0x3ef0253b2b2cdL, 0x1a45bd887fab6L, 0x65748076dc17cL, 0x5b98000aa11a8L, 0x4a1ecc9080974L,
0x2838c8863bdc0L, 0x3b0cf4a465030L, 0x22b8aef57a2dL, 0x2ad0677e925adL, 0x4094167d7457aL, 0x21dcb8a606a82L, 0x500fabe7731baL, 0x7cc53c3113351L,
0x7cf65fe080d81L, 0x3c5d966011ba1L, 0x5d840dbf6c6f6L, 0x4468c9d9fc8L, 0x5da8554796b8cL, 0x3b8be70950025L, 0x6d5892da6a609L, 0xbc3d08194a31L,
0x6380d309fe18bL, 0x4d73c2cb8ee0dL, 0x6b882adbac0b6L, 0x36eabdddd4cbeL, 0x3a4276232ac19L, 0xc172db447ecbL, 0x3f8c505b7a77fL, 0x6a857f97f3f10L,
0x4fcc0567fe03aL, 0x770c9e824e1aL, 0x2432c8a7084faL, 0x47bf73ca8a968L, 0x1639176262867L, 0x5e8df4f8010ceL, 0x1ff177cea16deL, 0x1d99a45b5b5fdL,
0x523674f2499ecL, 0xf8fa26182613L, 0x58f7398048c98L, 0x39f264fd41500L, 0x34aabfe097be1L, 0x43bfc03253a33L, 0x29bc7fe91b7f3L, 0xa761e4844a16L,
0x65c621272c35fL, 0x53417dbe7e29cL, 0x54573827394f5L, 0x565eea6f650ddL, 0x42050748dc749L, 0x1712d73468889L, 0x389f8ce3193ddL, 0x2d424b8177ce5L,
0x73fa0d3440cdL, 0x139020cd49e97L, 0x22f9800ab19ceL, 0x29fdd9a6efdacL, 0x7c694a9282840L, 0x6f7cdeee44b3aL, 0x55a3207b25cc3L, 0x4171a4d38598cL,
0x2368a3e9ef8cbL, 0x454aa08e2ac0bL, 0x490923f8fa700L, 0x372aa9ea4582fL, 0x13f416cd64762L, 0x758aa99c94c8cL, 0x5f6001700ff44L, 0x7694e488c01bdL,
0xd5fde948eed6L, 0x508214fa574bdL, 0x215bb53d003d6L, 0x1179e792ca8c3L, 0x1a0e96ac840a2L, 0x22393e2bb3ab6L, 0x3a7758a4c86cbL, 0x269153ed6fe4bL,
0x72a23aef89840L, 0x52be5299699cL, 0x3a5e5ef132316L, 0x22f960ec6fabaL, 0x111f693ae5076L, 0x3e3bfaa94ca90L, 0x445799476b887L, 0x24a0912464879L,
0x5d9fd15f8de7fL, 0x44d2aeed7521eL, 0x50865d2c2a7e4L, 0x2705b5238ea40L, 0x46c70b25d3b97L, 0x3bc187fa47eb9L, 0x408d36d63727fL, 0x5faf8f6a66062L,
0x2bb892da8de6bL, 0x769d4f0c7e2e6L, 0x332f35914f8fbL, 0x70115ea86c20cL, 0x16d88da24ada8L, 0x1980622662adfL, 0x501ebbc195a9dL, 0x450d81ce906fbL,
0x4d8961cae743fL, 0x6bdc38c7dba0eL, 0x7d3b4a7e1b463L, 0x844bdee2adf3L, 0x4cbad279663abL, 0x3b6a1a6205275L, 0x2e82791d06dcfL, 0x23d72caa93c87L,
0x5f0b7ab68aaf4L, 0x2de25d4ba6345L, 0x19024a0d71fcdL, 0x15f65115f101aL, 0x4e99067149708L, 0x119d8d1cba5afL, 0x7d7fbcefe2007L, 0x45dc5f3c29094L,
0x3455220b579afL, 0x70c1631e068aL, 0x26bc0630e9b21L, 0x4f9cd196dcd8dL, 0x71e6a266b2801L, 0x9aae73e2df5dL, 0x40dd8b219b1a3L, 0x546fb4517de0dL,
0x5975435e87b75L, 0x297d86a7b3768L, 0x4835a2f4c6332L, 0x70305f434160L, 0x183dd014e56aeL, 0x7ccdd084387a0L, 0x484186760cc93L, 0x7435665533361L,
0x2f686336b801L, 0x5225446f64331L, 0x3593ca848190cL, 0x6422c6d260417L, 0x212904817bb94L, 0x5a319deb854f5L, 0x7a9d4e060da7dL, 0x428bd0ed61d0cL,
0x3189a5e849aa7L, 0x6acbb1f59b242L, 0x7f6ef4753630cL, 0x1f346292a2da9L, 0x27398308da2d6L, 0x10e4c0a702453L, 0x4daafa37bd734L, 0x49f6bdc3e8961L,
0x1feffdcecdae6L, 0x572c2945492c3L, 0x38d28435ed413L, 0x4064f19992858L, 0x7680fbef543cdL, 0x1aadd83d58d3cL, 0x269597aebe8c3L, 0x7c745d6cd30beL,
0x27c7755df78efL, 0x1776833937fa3L, 0x5405116441855L, 0x7f985498c05bcL, 0x615520fbf6363L, 0xb9e9bf74da6aL, 0x4fe8308201169L, 0x173f76127de43L,
0x30f2653cd69b1L, 0x1ce889f0be117L, 0x36f6a94510709L, 0x7f248720016b4L, 0x1821ed1e1cf91L, 0x76c2ec470a31fL, 0xc938aac10c85L, 0x41b64ed797141L,
0x1beb1c1185e6dL, 0x1ed5490600f07L, 0x2f1273f159647L, 0x8bd755a70bc0L, 0x49e3a885ce609L, 0x16585881b5ad6L, 0x3c27568d34f5eL, 0x38ac1997edc5fL,
0x1fc7c8ae01e11L, 0x2094d5573e8e7L, 0x5ca3cbbf549d2L, 0x4f920ecc54143L, 0x5d9e572ad85b6L, 0x6b517a751b13bL, 0xcfd370b180ccL, 0x5377925d1f41aL,
0x34e56566008a2L, 0x22dfcd9cbfe9eL, 0x459b4103be0a1L, 0x59a4b3f2d2addL, 0x7d734c8bb8eebL, 0x2393cbe594a09L, 0xfe9877824cdeL, 0x3d2e0c30d0cd9L,
0x3f597686671bbL, 0xaa587eb63999L, 0xe3c7b592c619L, 0x6b2916c05448cL, 0x334d10aba913bL, 0x45cdb581cfdbL, 0x5e3e0553a8f36L, 0x50bb3041effb2L,
0x4c303f307ff00L, 0x403580dd94500L, 0x48df77d92653fL, 0x38a9fe3b349eaL, 0xea89850aafe1L, 0x416b151ab706aL, 0x23bd617b28c85L, 0x6e72ee77d5a61L,
0x1a972ff174ddeL, 0x3e2636373c60fL, 0xd61b8f78b2abL, 0xd7efe9c136b0L, 0x1ab1c89640ad5L, 0x55f82aef41f97L, 0x46957f317ed0dL, 0x191a2af74277eL,
0x62b434f460efbL, 0x294c6c0fad3fcL, 0x68368937b4c0fL, 0x5c9f82910875bL, 0x237e7dbe00545L, 0x6f74bc53c1431L, 0x1c40e5dbbd9c2L, 0x6c8fb9cae5c97L,
0x4845c5ce1b7daL, 0x7e2e0e450b5ccL, 0x575ed6701b430L, 0x4d3e17fa20026L, 0x791fc888c4253L, 0x2f1ba99078ac1L, 0x71afa699b1115L, 0x23c1c473b50d6L,
0x3e7671de21d48L, 0x326fa5547a1e8L, 0x50e4dc25fafd9L, 0x731fbc78f89L, 0x66f9b3953b61dL, 0x555f4283cccb9L, 0x7dd67fb1960e7L, 0x14707a1affed4L,
0x21142e9c2b1cL, 0xc71848f81880L, 0x44bd9d8233c86L, 0x6e8578efe5830L, 0x4045b6d7041b5L, 0x4c4d6f3347e15L, 0x4ddfc988f1970L, 0x4f6173ea365e1L,
0x645daf9ae4588L, 0x7d43763db623bL, 0x38bf9500a88f9L, 0x7eccfc17d1fc9L, 0x4ca280782831eL, 0x7b8337db1d7d6L, 0x5116def3895fbL, 0x193fddaaa7e47L,
0x2c93c37e8876fL, 0x3431a28c583faL, 0x49049da8bd879L, 0x4b4a8407ac11cL, 0x6a6fb99ebf0d4L, 0x122b5b6e423c6L, 0x21e50dff1ddd6L, 0x73d76324e75c0L,
0x588485495418eL, 0x136fda9f42c5eL, 0x6c1bb560855ebL, 0x71f127e13ad48L, 0x5c6b304905aecL, 0x3756b8e889bc7L, 0x75f76914a3189L, 0x4dfb1a305bdd1L,
0x3b3ff05811f29L, 0x6ed62283cd92eL, 0x65d1543ec52e1L, 0x22183510be8dL, 0x2710143307a7fL, 0x3d88fb48bf3abL, 0x249eb4ec18f7aL, 0x136115dff295fL,
0x1387c441fd404L, 0x766385ead2d14L, 0x194f8b06095eL, 0x8478f6823b62L, 0x6018689d37308L, 0x6a071ce17b806L, 0x3c3d187978af8L, 0x7afe1c88276baL,
0x51df281c8ad68L, 0x64906bda4245dL, 0x3171b26aaf1edL, 0x5b7d8b28a47d1L, 0x2c2ee149e34c1L, 0x776f5629afc53L, 0x1f4ea50fc49a9L, 0x6c514a6334424L,
0x7319097564ca8L, 0x1844ebc233525L, 0x21d4543fdeee1L, 0x1ad27aaff1bd2L, 0x221fd4873cf08L, 0x2204f3a156341L, 0x537414065a464L, 0x43c0c3bedcf83L,
0x5557e706ea620L, 0x48daa596fb924L, 0x61d5dc84c9793L, 0x47de83040c29eL, 0x189deb26507e7L, 0x4d4e6fadc479aL, 0x58c837fa0e8a7L, 0x28e665ca59cc7L,
0x165c715940dd9L, 0x785f3aa11c95L, 0x57b98d7e38469L, 0x676dd6fccad84L, 0x1688596fc9058L, 0x66f6ad403619fL, 0x4d759a87772efL, 0x7856e6173bea4L,
0x1c4f73f2c6a57L, 0x6706efc7c3484L, 0x6987839ec366dL, 0x731f95cf7f26L, 0x3ae758ebce4bcL, 0x70459adb7daf6L, 0x24fbd305fa0bbL, 0x40a98cc75a1cfL,
0x78ce1220a7533L, 0x6217a10e1c197L, 0x795ac80d1bf64L, 0x1db4991b42bb3L, 0x469605b994372L, 0x631e3715c9a58L, 0x7e9cfefcf728fL, 0x5fe162848ce21L,
0x1852d5d7cb208L, 0x60d0fbe5ce50fL, 0x5a1e246e37b75L, 0x51aee05ffd590L, 0x2b44c043677daL, 0x1214fe194961aL, 0xe1ae39a9e9cbL, 0x543c8b526f9f7L,
0x119498067e91dL, 0x4789d446fc917L, 0x487ab074eb78eL, 0x1d33b5e8ce343L, 0x13e419feb1b46L, 0x2721f565de6a4L, 0x60c52eef2bb9aL, 0x3c5c27cae6d11L,
0x36a9491956e05L, 0x124bac9131da6L, 0x3b6f7de202b5dL, 0x70d77248d9b66L, 0x589bc3bfd8bf1L, 0x6f93e6aa3416bL, 0x4c0a3d6c1ae48L, 0x55587260b586aL,
0x10bc9c312ccfcL, 0x2e84b3ec2a05bL, 0x69da2f03c1551L, 0x23a174661a67bL, 0x209bca289f238L, 0x63755bd3a976fL, 0x7101897f1acb7L, 0x3d82cb77b07b8L,
0x684083d7769f5L, 0x52b28472dce07L, 0x2763751737c52L, 0x7a03e2ad10853L, 0x213dcc6ad36abL, 0x1a6e240d5bdd6L, 0x7c24ffcf8fedfL, 0xd8cc1c48bc16L,
0x402d36eb419a9L, 0x7cef68c14a052L, 0xf1255bc2d139L, 0x373e7d431186aL, 0x70c2dd8a7ad16L, 0x4967db8ed7e13L, 0x15aeed02f523aL, 0x6149591d094bcL,
0x672f204c17006L, 0x32b8613816a53L, 0x194509f6fec0eL, 0x528d8ca31acacL, 0x7826d73b8b9faL, 0x24acb99e0f9b3L, 0x2e0fac6363948L, 0x7f7bee448cd64L,
0x4e10f10da0f3cL, 0x3936cb9ab20e9L, 0x7a0fc4fea6cd0L, 0x4179215c735a4L, 0x633b9286bcd34L, 0x6cab3badb9c95L, 0x74e387edfbdfaL, 0x14313c58a0fd9L,
0x31fa85662241cL, 0x94e7d7dced2aL, 0x68fa738e118eL, 0x41b640a5fee2bL, 0x6bb709df019d4L, 0x700344a30cd99L, 0x26c422e3622f4L, 0xf3066a05b5f0L,
0x4e2448f0480a6L, 0x244cde0dbf095L, 0x24bb2312a9952L, 0xc2af5f85c6bL, 0x609f4cf2883fL, 0x6e86eb5a1ca13L, 0x68b44a2efccd1L, 0xd1d2af9ffeb5L,
0xed1732de67c3L, 0x308c369291635L, 0x33ef348f2d250L, 0x4475ea1a1bbL, 0xfee3e871e188L, 0x28aa132621edfL, 0x42b244caf353bL, 0x66b064cc2e08aL,
0x6bb20020cbdd3L, 0x16acd79718531L, 0x1c6c57887b6adL, 0x5abf21fd7592bL, 0x50bd41253867aL, 0x3800b71273151L, 0x164ed34b18161L, 0x772af2d9b1d3dL,
0x6d486448b4e5bL, 0x2ce58dd8d18a8L, 0x1849f67503c8bL, 0x123e0ef6b9302L, 0x6d94c192fe69aL, 0x5475222a2690fL, 0x693789d86b8b3L, 0x1f5c3bdfb69dcL,
0x78da0fc61073fL, 0x780f1680c3a94L, 0x2a35d3cfcd453L, 0x5e5cdc7ddf8L, 0x6ee888078ac24L, 0x54aa4b316b38L, 0x15d28e52bc66aL, 0x30e1e0351cb7eL,
0x30a2f74b11f8cL, 0x39d120cd7de03L, 0x2d25deeb256b1L, 0x468d19267cb8L, 0x38cdca9b5fbf9L, 0x1bbb05c2ca1e2L, 0x3b015758e9533L, 0x134610a6ab7daL,
0x265e777d1f515L, 0xf1f54c1e39a5L, 0x2f01b95522646L, 0x4fdd8db9dde6dL, 0x654878cba97ccL, 0x38ec78df6b0feL, 0x13caebea36a22L, 0x5ebc6e54e5f6aL,
0x32804903d0eb8L, 0x2102fdba2b20dL, 0x6e405055ce6a1L, 0x5024a35a532d3L, 0x1f69054daf29dL, 0x15d1d0d7a8bd5L, 0xad725db29ecbL, 0x7bc0c9b056f85L,
0x51cfebffaffd8L, 0x44abbe94df549L, 0x7ecbbd7e33121L, 0x4f675f5302399L, 0x267b1834e2457L, 0x6ae19c378bb88L, 0x7457b5ed9d512L, 0x3280d783d05fbL,
0x4aefcffb71a03L, 0x536360415171eL, 0x2313309077865L, 0x251444334afbcL, 0x2b0c3853756e8L, 0xbccbb72a2a86L, 0x55e4c50fe1296L, 0x5fdd13efc30dL,
0x1c0c6c380e5eeL, 0x3e11de3fb62a8L, 0x6678fd69108f3L, 0x6962feab1a9c8L, 0x6aca28fb9a30bL, 0x56db7ca1b9f98L, 0x39f58497018ddL, 0x4024f0ab59d6bL,
0x6fa31636863c2L, 0x10ae5a67e42b0L, 0x27abbf01fda31L, 0x380a7b9e64fbcL, 0x2d42e2108ead4L, 0x17b0d0f537593L, 0x16263c0c9842eL, 0x4ab827e4539a4L,
0x6370ddb43d73aL, 0x420bf3a79b423L, 0x5131594dfd29bL, 0x3a627e98d52feL, 0x1154041855661L, 0x19175d09f8384L, 0x676b2608b8d2dL, 0xba651c5b2b47L,
0x5862363701027L, 0xc4d6c219c6dbL, 0xf03dff8658deL, 0x745d2ffa9c0cfL, 0x6df5721d34e6aL, 0x4f32f767a0c06L, 0x1d5abeac76e20L, 0x41ce9e104e1e4L,
0x6e15be54c1dcL, 0x25a1e2bc9c8bdL, 0x104c8f3b037eaL, 0x405576fa96c98L, 0x2e86a88e3876fL, 0x1ae23ceb960cfL, 0x25d871932994aL, 0x6b9d63b560b6eL,
0x2df2814c8d472L, 0xfbbee20aa4edL, 0x58ded861278ecL, 0x35ba8b6c2c9a8L, 0x1dea58b3185bfL, 0x4b455cd23bbbeL, 0x5ec19c04883f8L, 0x8ba696b531d5L,
0x73793f266c55cL, 0xb988a9c93b02L, 0x9b0ea32325dbL, 0x37cae71c17c5eL, 0x2ff39de85485fL, 0x53eeec3efc57aL, 0x2fa9fe9022efdL, 0x699c72c138154L,
0x72a751ebd1ff8L, 0x120633b4947cfL, 0x531474912100aL, 0x5afcdf7c0d057L, 0x7a9e71b788dedL, 0x5ef708f3b0c88L, 0x7433be3cb393L, 0x4987891610042L,
0x79d9d7f5d0172L, 0x3c293013b9ec4L, 0xc2b85f39cacaL, 0x35d30a99b4d59L, 0x144c05ce997f4L, 0x4960b8a347fefL, 0x1da11f15d74f7L, 0x54fac19c0feadL,
0x2d873ede7af6dL, 0x202e14e5df981L, 0x2ea02bc3eb54cL, 0x38875b2883564L, 0x1298c513ae9ddL, 0x543618a01600L, 0x2316443373409L, 0x5de95503b22afL,
0x699201beae2dfL, 0x3db5849ff737aL, 0x2e773654707faL, 0x2bdf4974c23c1L, 0x4b3b9c8d261bdL, 0x26ae8b2a9bc28L, 0x3068210165c51L, 0x4b1443362d079L,
0x454e91c529ccbL, 0x24c98c6bf72cfL, 0x486594c3d89aL, 0x7ae13a3d7fa3cL, 0x17038418eaf66L, 0x4b7c7b66e1f7aL, 0x4bea185efd998L, 0x4fabc711055f8L,
0x1fb9f7836fe38L, 0x582f446752da6L, 0x17bd320324ce4L, 0x51489117898c6L, 0x1684d92a0410bL, 0x6e4d90f78c5a7L, 0xc2a1c4bcda28L, 0x4814869bd6945L,
0x7b7c391a45db8L, 0x57316ac35b641L, 0x641e31de9096aL, 0x5a6a9b30a314dL, 0x5c7d06f1f0447L, 0x7db70f80b3a49L, 0x6cb4a3ec89a78L, 0x43be8ad81397dL,
0x7c558bd1c6f64L, 0x41524d396463dL, 0x1586b449e1a1dL, 0x2f17e904aed8aL, 0x7e1d2861d3c8eL, 0x404a5ca0afbaL, 0x49e1b2a416fd1L, 0x51c6a0b316c57L,
0x575a59ed71bdcL, 0x74c021a1fec1eL, 0x39527516e7f8eL, 0x740070aa743d6L, 0x16b64cbdd1183L, 0x23f4b7b32eb43L, 0x319aba58235b3L, 0x46395bfdcadd9L,
0x7db2d1a5d9a9cL, 0x79a200b85422fL, 0x355bfaa71dd16L, 0xb77ea5f78aaL, 0x76579a29e822dL, 0x4b51352b434f2L, 0x1327bd01c2667L, 0x434d73b60c8a1L,
0x3e0daa89443baL, 0x2c514bb2a277L, 0x68e7e49c02a17L, 0x45795346fe8b6L, 0x89306c8f3546L, 0x6d89f6b2f88f6L, 0x43a384dc9e05bL, 0x3d5da8bf1b645L,
0x7ded6a96a6d09L, 0x6c3494fee2f4dL, 0x2c989c8b6bd4L, 0x1160920961548L, 0x5616369b4dcdL, 0x4ecab86ac6f47L, 0x3c60085d700b2L, 0x213ee10dfceaL,
0x2f637d7491e6eL, 0x5166929dacfaaL, 0x190826b31f689L, 0x4f55567694a7dL, 0x705f4f7b1e522L, 0x351e125bc5698L, 0x49b461af67bbeL, 0x75915712c3a96L,
0x69a67ef580c0dL, 0x54d38ef70cffcL, 0x7f182d06e7ce2L, 0x54b728e217522L, 0x69a90971b0128L, 0x51a40f2a963a3L, 0x10be9ac12a6bfL, 0x44acc043241c5L,
0x48e64ab0168ecL, 0x2a2bdb8a86f4fL, 0x7343b6b2d6929L, 0x1d804aa8ce9a3L, 0x67d4ac8c343e9L, 0x56bbb4f7a5777L, 0x29230627c238fL, 0x5ad1a122cd7fbL,
0xdea56e50e364L, 0x556d1c8312ad7L, 0x6756b11be821L, 0x462147e7bb03eL, 0x26519743ebfe0L, 0x782fc59682ab5L, 0x97abe38cc8c7L, 0x740e30c8d3982L,
0x7c2b47f4682fdL, 0x5cd91b8c7dc1cL, 0x77fa790f9e583L, 0x746c6c6d1d824L, 0x1c9877ea52da4L, 0x2b37b83a86189L, 0x733af49310da5L, 0x25e81161c04fbL,
0x577e14a34bee8L, 0x6cebebd4dd72bL, 0x340c1e442329fL, 0x32347ffd1a93fL, 0x14a89252cbbe0L, 0x705304b8fb009L, 0x268ac61a73b0aL, 0x206f234bebe1cL,
0x5b403a7cbebe8L, 0x7a160f09f4135L, 0x60fa7ee96fd78L, 0x51d354d296ec6L, 0x7cbf5a63b16c7L, 0x2f50bb3cf0c14L, 0x1feb385cac65aL, 0x21398e0ca1635L,
0xaaf9b4b75601L, 0x26b91b5ae44f3L, 0x6de808d7ab1c8L, 0x6a769675530b0L, 0x1bbfb284e98f7L, 0x5058a382b33f3L, 0x175a91816913eL, 0x4f6cdb96b8ae8L,
0x17347c9da81d2L, 0x5aa3ed9d95a23L, 0x777e9c7d96561L, 0x28e58f006ccacL, 0x541bbbb2cac49L, 0x3e63282994cecL, 0x4a07e14e5e895L, 0x358cdc477a49bL,
0x3cc88fe02e481L, 0x721aab7f4e36bL, 0x408cc9469953L, 0x50af7aed84afaL, 0x412cb980df999L, 0x5e78dd8ee29dcL, 0x171dff68c575dL, 0x2015dd2f6ef49L,
0x3f0bac391d313L, 0x7de0115f65be5L, 0x4242c21364dc9L, 0x6b75b64a66098L, 0x33c0102c085L, 0x1921a316baebdL, 0x2ad9ad9f3c18bL, 0x5ec1638339aebL,
0x5703b6559a83bL, 0x3fa9f4d05d612L, 0x7b049deca062cL, 0x22f7edfb870fcL, 0x569eed677b128L, 0x30937dcb0a5afL, 0x758039c78ea1bL, 0x6458df41e273aL,
0x3e37a35444483L, 0x661fdb7d27b99L, 0x317761dd621e4L, 0x7323c30026189L, 0x6093dccbc2950L, 0x6eebe6084034bL, 0x6cf01f70a8d7bL, 0xb41a54c6670aL,
0x6c84b99bb55dbL, 0x6e3180c98b647L, 0x39a8585e0706dL, 0x3167ce72663feL, 0x63d14ecdb4297L, 0x4be21dcf970b8L, 0x57d1ea084827aL, 0x2b6e7a128b071L,
0x5b27511755dcfL, 0x8584c2930565L, 0x68c7bda6f4159L, 0x363e999ddd97bL, 0x48dce24baec6L, 0x2b75795ec05e3L, 0x3bfa4c5da6dc9L, 0x1aac8659e371eL,
0x231f979bc6f9bL, 0x43c135ee1fc4L, 0x2a11c9919f2d5L, 0x6334cc25dbacdL, 0x295da17b400daL, 0x48ee9b78693a0L, 0x1de4bcc2af3c6L, 0x61fc411a3eb86L,
0x53ed19ac12ec0L, 0x209dbc6b804e0L, 0x79bfa9b08792L, 0x1ed80a2d54245L, 0x70efec72a5e79L, 0x42151d42a822dL, 0x1b5ebb6d631e8L, 0x1ef4fb1594706L,
0x3a51da300df4L, 0x467b52b561c72L, 0x4d5920210e590L, 0xca769e789685L, 0x38c77f684817L, 0x65ee65b167becL, 0x52da19b850a9L, 0x408665656429L,
0x7ab39596f9a4cL, 0x575ee92a4a0bfL, 0x6bc450aa4d801L, 0x4f4a6773b0ba8L, 0x6241b0b0ebc48L, 0x40d9c4f1d9315L, 0x200a1e7e382f5L, 0x80908a182fcfL,
0x532913b7ba98L, 0x3dccf78c385c3L, 0x68002dd5eaba9L, 0x43d4e7112cd3fL, 0x5b967eaf93ac5L, 0x360acca580a31L, 0x1c65fd5c6f262L, 0x71c7f15c2ecabL,
0x50eca52651e4L, 0x4397660e668eaL, 0x7c2a75692f2f5L, 0x3b29e7e6c66efL, 0x72ba658bcda9aL, 0x6151c09fa131aL, 0x31ade453f0c9cL, 0x3dfee07737868L,
0x611ecf7a7d411L, 0x2637e6cbd64f6L, 0x4b0ee6c21c58fL, 0x55c0dfdf05d96L, 0x405569dcf475eL, 0x5c5c277498bbL, 0x18588d95dc389L, 0x1fef24fa800f0L,
0x2aff530976b86L, 0xd85a48c0845aL, 0x796eb963642e0L, 0x60bee50c4b626L, 0x28005fe6c8340L, 0x653fb1aa73196L, 0x607faec8306faL, 0x4e85ec83e5254L,
0x9f56900584fdL, 0x544d49292fc86L, 0x7ba9f34528688L, 0x284a20fb42d5dL, 0x3652cd9706ffeL, 0x6fd7baddde6b3L, 0x72e472930f316L, 0x3f635d32a7627L,
0xcbecacde00feL, 0x3411141eaa936L, 0x21c1e42f3cb94L, 0x1fee7f000fe06L, 0x5208c9781084fL, 0x16468a1dc24d2L, 0x7bf780ac540a8L, 0x1a67eced75301L,
0x5a9d2e8c2733aL, 0x305da03dbf7e5L, 0x1228699b7aecaL, 0x12a23b2936bc9L, 0x2a1bda56ae6e9L, 0xf94051ee040L, 0x793bb07af9753L, 0x1e7b6ecd4fafdL,
0x2c7b1560fb43L, 0x2296734cc5fb7L, 0x47b7ffd25dd40L, 0x56b23c3d330b2L, 0x37608e360d1a6L, 0x10ae0f3c8722eL, 0x86d9b618b637L, 0x7d79c7e8beabL,
0x3fb9cbc08dd12L, 0x75c3dd85370ffL, 0x47f06fe2819acL, 0x5db06ab9215edL, 0x1c3520a35ea64L, 0x6f40216bc059L, 0x3a2579b0fd9b5L, 0x71c26407eec8cL,
0x72ada4ab54f0bL, 0x38750c3b66d12L, 0x253a6bccba34aL, 0x427070433701aL, 0x20b8e58f9870eL, 0x337c861db00ccL, 0x1c3d05775d0eeL, 0x6f1409422e51aL,
0x7856bbece2d25L, 0x13380a72f031cL, 0x43e1080a7f3baL, 0x621e2c7d3304L, 0x61796b0dbf0f3L, 0x73c2f9c32d6f5L, 0x6aa8ed1537ebeL, 0x74e92c91838f4L,
0x5d8e589ca1002L, 0x60cc8259838dL, 0x38d3f35b95f3L, 0x56078c243a923L, 0x2de3293241bb2L, 0x7d6097bd3aL, 0x71d950842a94bL, 0x46b11e5c7d817L,
0x5478bbecb4f0dL, 0x7c3054b0a1c5dL, 0x1583d7783c1cbL, 0x34704cc9d28c7L, 0x3dee598b1f200L, 0x16e1c98746d9eL, 0x4050b7095afdfL, 0x4958064e83c55L,
0x6a2ef5da27ae1L, 0x28aace02e9d9dL, 0x2459e965f0e8L, 0x7b864d3150933L, 0x252a5f2e81ed8L, 0x94265066e80dL, 0xa60f918d61a5L, 0x444bf7f30fdeL,
0x1c40da9ed3c06L, 0x79c170bd843bL, 0x6cd50c0d5d056L, 0x5b7606ae779baL, 0x70fbd226bdda1L, 0x5661e53391ff9L, 0x6768c0d7317b8L, 0x6ece464fa6fffL,
0x3cc40bca460a0L, 0x6e3a90afb8d0cL, 0x5801abca11228L, 0x6dec05e34ac9fL, 0x625e5f155c1b3L, 0x4f32f6f723296L, 0x5ac980105efceL, 0x17a61165eee36L,
0x51445e14ddcd5L, 0x147ab2bbea455L, 0x1f240f2253126L, 0xc3de9e314e89L, 0x21ea5a4fca45fL, 0x12e990086e4fdL, 0x2b4b3b144951L, 0x5688977966aeaL,
0x18e176e399ffdL, 0x2e45c5eb4938bL, 0x13186f31e3929L, 0x496b37fdfbb2eL, 0x3c2439d5f3e21L, 0x16e60fe7e6a4dL, 0x4d7ef889b621dL, 0x77b2e3f05d3e9L,
0x639c12ddb0a4L, 0x6180490cd7ab3L, 0x3f3918297467cL, 0x74568be1781acL, 0x7a195152e095L, 0x7a9c59c2ec4deL, 0x7e9f09e79652dL, 0x6a3e422f22d86L,
0x2ae8e3b836c8bL, 0x63b795fc7ad32L, 0x68f02389e5fc8L, 0x59f1bc877506L, 0x504990e410cecL, 0x9bd7d0feaee2L, 0x3e8fe83d032f0L, 0x4c8de8efd13cL,
0x1c67c06e6210eL, 0x183378f7f146aL, 0x64352ceaed289L, 0x22d60899a6258L, 0x315b90570a294L, 0x60ce108a925f1L, 0x6eff61253c909L, 0x3ef0e2d70b0L,
0x75ba3b797fac4L, 0x1dbc070cdd196L, 0x16d8fb1534c47L, 0x500498183fa2aL, 0x72f59c423de75L, 0x904d07b87779L, 0x22d6648f940b9L, 0x197a5a1873e86L,
0x207e4c41a54bcL, 0x5360b3b4bd6d0L, 0x6240aacebaf72L, 0x61fd4ddba919cL, 0x7d8e991b55699L, 0x61b31473cc76cL, 0x7039631e631d6L, 0x43e2143fbc1ddL,
0x4749c5ba295a0L, 0x37946fa4b5f06L, 0x724c5ab5a51f1L, 0x65633789dd3f3L, 0x56bdaf238db40L, 0xd36cc19d3bb2L, 0x6ec4470d72262L, 0x6853d7018a9aeL,
0x3aa3e4dc2c8ebL, 0x3aa31507e1e5L, 0x2b9e3f53533ebL, 0x2add727a806c5L, 0x56955c8ce15a3L, 0x18c4f070a290eL, 0x1d24a86d83741L, 0x47648ffd4ce1fL,
0x60a9591839e9dL, 0x424d5f38117abL, 0x42cc46912c10eL, 0x43b261dc9aeb4L, 0x13d8b6c951364L, 0x4c0017e8f632aL, 0x53e559e53f9c4L, 0x4b20146886eeaL,
0x2b4d5e242940L, 0x31e1988bb79bbL, 0x7b82f46b3bcabL, 0xf7a8ce827b41L, 0x5e15816177130L, 0x326055cf5b276L, 0x155cb28d18df2L, 0xc30d9ca11694L,
0x2090e27ab3119L, 0x208624e7a49b6L, 0x27a6c809ae5d3L, 0x4270ac43d6954L, 0x2ed4cd95659a5L, 0x75c0db37528f9L, 0x2ccbcfd2c9234L, 0x221503603d8c2L,
0x6ebcd1f0db188L, 0x74ceb4b7d1174L, 0x7d56168df4f5cL, 0xbf79176fd18aL, 0x2cb67174ff60aL, 0x6cdf9390be1d0L, 0x8e519c7e2b3dL, 0x253c3d2a50881L,
0x21b41448e333dL, 0x7b1df4b73890fL, 0x6221807f8f58cL, 0x3fa92813a8be5L, 0x6da98c38d5572L, 0x1ed95554468fL, 0x68698245d352eL, 0x2f2e0b3b2a224L,
0xc56aa22c1c92L, 0x5fdec39f1b278L, 0x4c90af5c7f106L, 0x61fcef2658fc5L, 0x15d852a18187aL, 0x270dbb59afb76L, 0x7db120bcf92abL, 0xe7a25d714087L,
0x46cf4c473daf0L, 0x46ea7f1498140L, 0x70725690a8427L, 0xa73ae9f079fbL, 0x2dd924461c62bL, 0x1065aae50d8ccL, 0x525ed9ec4e5f9L, 0x22d20660684cL,
0x7972b70397b68L, 0x7a03958d3f965L, 0x29387bcd14eb5L, 0x44525df200d57L, 0x2d7f94ce94385L, 0x60d00c170ecb7L, 0x38b0503f3d8f0L, 0x69a198e64f1ceL,
0x14434dcc5caedL, 0x2c7909f667c20L, 0x61a839d1fb576L, 0x4f23800cabb76L, 0x25b2697bd267fL, 0x2b2e0d91a78bcL, 0x3990a12ccf20cL, 0x141c2e11f2622L,
0xdfcefaa53320L, 0x7369e6a92493aL, 0x73ffb13986864L, 0x3282bb8f713acL, 0x49ced78f297efL, 0x6697027661defL, 0x1420683db54e4L, 0x6bb6fc1cc5ad0L,
0x532c8d591669dL, 0x1af794da86c33L, 0xe0e9d86d24d3L, 0x31e83b4161d08L, 0xbd1e249dd197L, 0xbcb1820568fL, 0x2eab1718830d4L, 0x396fd816997e6L,
0x60b63bebf508aL, 0xc7129e062b4fL, 0x1e526415b12fdL, 0x461a0fd27923dL, 0x18badf670a5b7L, 0x55cf1eb62d550L, 0x6b5e37df58c52L, 0x3bcf33986c60eL,
0x44fb8835ceae7L, 0x99dec18e71a4L, 0x1a56fbaa62ba0L, 0x1101065c23d58L, 0x5aa1290338b0fL, 0x3157e9e2e7421L, 0xea712017d489L, 0x669a656457089L,
0x66b505c9dc9ecL, 0x774ef86e35287L, 0x4d1d944c0955eL, 0x52e4c39d72b20L, 0x13c4836799c58L, 0x4fb6a5d8bd080L, 0x58ae34908589bL, 0x3954d977baf13L,
0x413ea597441dcL, 0x50bdc87dc8e5bL, 0x25d465ab3e1b9L, 0xf8fe27ec2847L, 0x2d6e6dbf04f06L, 0x3038cfc1b3276L, 0x66f80c93a637bL, 0x537836edfe111L,
0x2be02357b2c0dL, 0x6dcee58c8d4f8L, 0x2d732581d6192L, 0x1dd56444725fdL, 0x7e60008bac89aL, 0x23d5c387c1852L, 0x79e5df1f533a8L, 0x2e6f9f1c5f0cfL,
0x3a3a450f63a30L, 0x47ff83362127dL, 0x8e39af82b1f4L, 0x488322ef27dabL, 0x1973738a2a1a4L, 0xe645912219f7L, 0x72f31d8394627L, 0x7bd294a200f1L,
0x665be00e274c6L, 0x43de8f1b6368bL, 0x318c8d9393a9aL, 0x69e29ab1dd398L, 0x30685b3c76bacL, 0x565cf37f24859L, 0x57b2ac28efef9L, 0x509a41c325950L,
0x45d032afffe19L, 0x12fe49b6cde4eL, 0x21663bc327cf1L, 0x18a5e4c69f1ddL, 0x224c7c679a1d5L, 0x6edca6f925e9L, 0x68c8363e677b8L, 0x60cfa25e4fbcfL,
0x1c4c17609404eL, 0x5bff02328a11L, 0x1a0dd0dc512e4L, 0x10894bf5fcd10L, 0x52949013f9c37L, 0x1f50fba4735c7L, 0x576277cdee01aL, 0x2137023cae00bL,
0x15a3599eb26c6L, 0x687221512b3cL, 0x253cb3a0824e9L, 0x780b8cc3fa2a4L, 0x38abc234f305fL, 0x7a280bbc103deL, 0x398a836695dfeL, 0x3d0af41528a1aL,
0x5ff418726271bL, 0x347e813b69540L, 0x76864c21c3cbbL, 0x1e049dbcd74a8L, 0x5b4d60f93749cL, 0x29d4db8ca0a0cL, 0x6080c1789db9dL, 0x4be7cef1ea731L,
0x2f40d769d8080L, 0x35f7d4c44a603L, 0x106a03dc25a96L, 0x50aaf333353d0L, 0x4b59a613cbb35L, 0x223dfc0e19a76L, 0x77d1e2bb2c564L, 0x4ab38a51052cbL,
0x7d1ef5fddc09cL, 0x7beeaebb9dad9L, 0x58d30ba0acfbL, 0x5cd92eab5ae90L, 0x3041c6bb04ed2L, 0x42b256768d593L, 0x2e88459427b4fL, 0x2b3876630701L,
0x34878d405eae5L, 0x29cdd1adc088aL, 0x2f2f9d956e148L, 0x6b3e6ad65c1feL, 0x5b00972b79e5dL, 0x53d8d234c5dafL, 0x104bbd6814049L, 0x59a5fd67ff163L,
0x3a998ead0352bL, 0x83c95fa4af9aL, 0x6fadbfc01266fL, 0x204f2a20fb072L, 0xfd3168f1ed67L, 0x1bb0de7784a3eL, 0x34bcb78b20477L, 0xa4a26e2e2182L,
0x5be8cc57092a7L, 0x43b3d30ebb079L, 0x357aca5c61902L, 0x5b570c5d62455L, 0x30fb29e1e18c7L, 0x2570fb17c2791L, 0x6a9550bb8245aL, 0x511f20a1a2325L,
0x29324d7239beeL, 0x3343cc37516c4L, 0x241c5f91de018L, 0x2367f2cb61575L, 0x6c39ac04d87dfL, 0x6d4958bd7e5bdL, 0x566f4638a1532L, 0x3dcb65ea53030L,
0x172940de6caaL, 0x6045b2e67451bL, 0x56c07463efcb3L, 0x728b6bfe6e91L, 0x8420edd5fcdfL, 0xc34e04f410ceL, 0x344edc0d0a06bL, 0x6e45486d84d6dL,
0x44e2ecb3863f5L, 0x4d654f321db8L, 0x720ab8362fa4aL, 0x29c4347cdd9bfL, 0xe798ad5f8463L, 0x4fef18bcb0bfeL, 0xd9a53efbc176L, 0x5c116ddbdb5d5L,
0x6d1b4bba5abcfL, 0x4d28a48a5537aL, 0x56b8e5b040b99L, 0x4a7a4f2618991L, 0x3b291af372a4bL, 0x60e3028fe4498L, 0x2267bca4f6a09L, 0x719eec242b243L,
0x4a96314223e0eL, 0x718025fb15f95L, 0x68d6b8371fe94L, 0x3804448f7d97cL, 0x42466fe784280L, 0x11b50c4cddd31L, 0x274408a4ffd6L, 0x7d382aedb34ddL,
0x40acfc9ce385dL, 0x628bb99a45b1eL, 0x4f4bce4dce6bcL, 0x2616ec49d0b6fL, 0x1f95d8462e61cL, 0x1ad3e9b9159c6L, 0x79ba475a04df9L, 0x3042cee561595L,
0x7ce5ae2242584L, 0x2d25eb153d4e3L, 0x3a8f3d09ba9c9L, 0xf3690d04eb8eL, 0x73fcdd14b71c0L, 0x67079449bac41L, 0x5b79c4621484fL, 0x61069f2156b8dL,
0xeb26573b10afL, 0x389e740c9a9ceL, 0x578f6570eac28L, 0x644f2339c3937L, 0x66e47b7956c2cL, 0x34832fe1f55d0L, 0x25c425e5d6263L, 0x4b3ae34dcb9ceL,
0x47c691a15ac9fL, 0x318e06e5d400cL, 0x3c422d9f83eb1L, 0x61545379465a6L, 0x606a6f1d7de6eL, 0x4f1c0c46107e7L, 0x229b1dcfbe5d8L, 0x3acc60a7b1327L,
0x6539a08915484L, 0x4dbd414bb4a19L, 0x7930849f1dbb8L, 0x329c5a466caf0L, 0x6c824544feb9bL, 0xf65320ef019bL, 0x21f74c3d2f773L, 0x24b88d08bd3aL,
0x6e678cf054151L, 0x43631272e747cL, 0x11c5e4aac5cd1L, 0x6d1b1cafde0c6L, 0x462c76a303a90L, 0x3ca4e693cff9bL, 0x3952cd45786fdL, 0x4cabc7bdec330L,
0x7788f3f78d289L, 0x5942809b3f811L, 0x5973277f8c29cL, 0x10f93bc5fe67L, 0x7ee498165acb2L, 0x69624089c0a2eL, 0x75fc8e70473L, 0x13e84ab1d2313L,
0x2c10bedf6953bL, 0x639b93f0321c8L, 0x508e39111a1c3L, 0x290120e912f7aL, 0x1cbf464acae43L, 0x15373e9576157L, 0xedf493c85b60L, 0x7c4d284764113L,
0x7fefebf06acecL, 0x39afb7a824100L, 0x1b48e47e7fd65L, 0x4c00c54d1dfaL, 0x48158599b5a68L, 0x1fd75bc41d5d9L, 0x2d9fc1fa95d3cL, 0x7da27f20eba11L,
0x403b92e3019d4L, 0x22f818b465cf8L, 0x342901dff09b8L, 0x31f595dc683cdL, 0x37a57745fd682L, 0x355bb12ab2617L, 0x1dac75a8c7318L, 0x3b679d5423460L,
0x6b8fcb7b6400eL, 0x6c73783be5f9dL, 0x7518eaf8e052aL, 0x664cc7493bbf4L, 0x33d94761874e3L, 0x179e1796f613L, 0x1890535e2867dL, 0xf9b8132182ecL,
0x59c41b7f6c32L, 0x79e8706531491L, 0x6c747643cb582L, 0x2e20c0ad494e4L, 0x47c3871bbb175L, 0x65d50c85066b0L, 0x6167453361f7cL, 0x6ba3818bb312L,
0x6aff29baa7522L, 0x8fea02ce8d48L, 0x4539771ec4f48L, 0x7b9318badca28L, 0x70f19afe016c5L, 0x4ee7bb1608d23L, 0xb89b8576469L, 0x5dd7668deead0L,
0x4096d0ba47049L, 0x6275997219114L, 0x29bda8a67e6aeL, 0x473829a74f75dL, 0x1533aad3902c9L, 0x1dde06b11e47bL, 0x784bed1930b77L, 0x1c80a92b9c867L,
0x6c668b4d44e4dL, 0x2da754679c418L, 0x3164c31be105aL, 0x11fac2b98ef5fL, 0x35a1aaf779256L, 0x2078684c4833cL, 0xcf217a78820cL, 0x65024e7d2e769L,
0x23bb5efdda82aL, 0x19fd4b632d3c6L, 0x7411a6054f8a4L, 0x2e53d18b175b4L, 0x33e7254204af3L, 0x3bcd7d5a1c4c5L, 0x4c7c22af65d0fL, 0x1ec9a872458c3L,
0x59d32b99dc86dL, 0x6ac075e22a9acL, 0x30b9220113371L, 0x27fd9a638966eL, 0x7c136574fb813L, 0x6a4d400a2509bL, 0x41791056971cL, 0x655d5866e075cL,
0x2302bf3e64df8L, 0x3add88a5c7cd6L, 0x298d459393046L, 0x30bfecb3d90b8L, 0x3d9b8ea3df8d6L, 0x3900e96511579L, 0x61ba1131a406aL, 0x15770b635dcf2L,
0x59ecd83f79571L, 0x2db461c0b7fbdL, 0x73a42a981345fL, 0x249929fccc879L, 0xa0f116959029L, 0x5974fd7b1347aL, 0x1e0cc1c08edadL, 0x673bdf8ad1f13L,
0x5620310cbbd8eL, 0x6b5f477e285d6L, 0x4ed91ec326cc8L, 0x6d6537503a3fdL, 0x626d3763988d5L, 0x7ec846f3658ceL, 0x193434934d643L, 0xd4a2445eaa51L,
0x7d0708ae76fe0L, 0x39847b6c3c7e1L, 0x37676a2a4d9d9L, 0x68f3f1da22ec7L, 0x6ed8039a2736bL, 0x2627ee04c3c75L, 0x6ea90a647e7d1L, 0x6daaf723399b9L,
0x304bfacad8ea2L, 0x502917d108b07L, 0x43176ca6dd0fL, 0x5d5158f2c1d84L, 0x2b5449e58eb3bL, 0x27562eb3dbe47L, 0x291d7b4170be7L, 0x5d1ca67dfa8e1L,
0x2a88061f298a2L, 0x1304e9e71627dL, 0x14d26adc9cfeL, 0x7f1691ba16f13L, 0x5e71828f06eacL, 0x349ed07f0fffcL, 0x4468de2d7c2ddL, 0x2d8c6f86307ceL,
0x6286ba1850973L, 0x5e9dcb08444d4L, 0x1a96a543362b2L, 0x5da6427e63247L, 0x3355e9419469eL, 0x1847bb8ea8a37L, 0x1fe6588cf9b71L, 0x6b1c9d2db6b22L,
0x6cce7c6ffb44bL, 0x4c688deac22caL, 0x6f775c3ff0352L, 0x565603ee419bbL, 0x6544456c61c46L, 0x58f29abfe79f2L, 0x264bf710ecdf6L, 0x708c58527896bL,
0x42ceae6c53394L, 0x4381b21e82b6aL, 0x6af93724185b4L, 0x6cfab8de73e68L, 0x3e6efced4bd21L, 0x56609500dbeL, 0x71b7824ad85dfL, 0x577629c4a7f41L,
0x24509c6a888L, 0x2696ab12e6644L, 0xcca27f4b80d8L, 0xc7c1f11b119eL, 0x701f25bb0caecL, 0xf6d97cbec113L, 0x4ce97fb7c93a3L, 0x139835a11281bL,
0x728907ada9156L, 0x720a5bc050955L, 0xb0f8e4616cedL, 0x1d3c4b50fb875L, 0x2f29673dc0198L, 0x5f4b0f1830ffaL, 0x2e0c92bfbdc40L, 0x709439b805a35L,
0x6ec48557f8187L, 0x8a4d1ba13a2cL, 0x76348a0bf9aeL, 0xe9b9cbb144efL, 0x69bd55db1beeeL, 0x6e14e47f731bdL, 0x1a35e47270eacL, 0x66f225478df8eL,
0x366d44191cfd3L, 0x2d48ffb5720adL, 0x57b7f21a1df77L, 0x5550effba0645L, 0x5ec6a4098a931L, 0x221104eb3f337L, 0x41743f2bc8c14L, 0x796b0ad8773c7L,
0x29fee5cbb689bL, 0x122665c178734L, 0x4167a4e6bc593L, 0x62665f8ce8feeL, 0x29d101ac59857L, 0x4d93bbba59ffcL, 0x17b7897373f17L, 0x34b33370cb7edL,
0x39d2876f62700L, 0x1cecd1d6c87L, 0x7f01a11747675L, 0x2350da5a18190L, 0x7938bb7e22552L, 0x591ee8681d6ccL, 0x39db0b4ea79b8L, 0x202220f380842L,
0x2f276ba42e0acL, 0x1176fc6e2dfe6L, 0xe28949770eb8L, 0x5559e88147b72L, 0x35e1e6e63ef30L, 0x35b109aa7ff6fL, 0x1f6a3e54f2690L, 0x76cd05b9c619bL,
0x69654b0901695L, 0x7a53710b77f27L, 0x79a1ea7d28175L, 0x8fc3a4c677d5L, 0x4c199d30734eaL, 0x6c622cb9acc14L, 0x5660a55030216L, 0x68f1199f11fbL,
0x4f2fad0116b90L, 0x4d91db73bb638L, 0x55f82538112c5L, 0x6d85a279815deL, 0x740b7b0cd9cf9L, 0x3451995f2944eL, 0x6b24194ae4e54L, 0x2230afded8897L,
0x23412617d5071L, 0x3d5d30f35969bL, 0x445484a4972efL, 0x2fcd09fea7d7cL, 0x296126b9ed22aL, 0x4a171012a05b2L, 0x1db92c74d5523L, 0x10b89ca604289L,
0x141be5a45f06eL, 0x5adb38becaea7L, 0x3fd46db41f2bbL, 0x6d488bbb5ce39L, 0x17d2d1d9ef0d4L, 0x147499718289cL, 0xa48a67e4c7abL, 0x30fbc544bafe3L,
0xc701315fe58aL, 0x20b878d577b75L, 0x2af18073f3e6aL, 0x33aea420d24feL, 0x298008bf4ff94L, 0x3539171db961eL, 0x72214f63cc65cL, 0x5b7b9f43b29c9L,
0x149ea31eea3b3L, 0x4be7713581609L, 0x2d87960395e98L, 0x1f24ac855a154L, 0x37f405307a693L, 0x2e5e66cf2b69cL, 0x5d84266ae9c53L, 0x5e4eb7de853b9L,
0x5fdf48c58171cL, 0x608328e9505aaL, 0x22182841dc49aL, 0x3ec96891d2307L, 0x2f363fff22e03L, 0xba739e2ae39L, 0x426f5ea88bb26L, 0x33092e77f75c8L,
0x1a53940d819e7L, 0x1132e4f818613L, 0x72297de7d518dL, 0x698de5c8790d6L, 0x268b8545beb25L, 0x6d2648b96fedfL, 0x47988ad1db07cL, 0x3283a3e67ad7L,
0x41dc7be0cb939L, 0x1b16c66100904L, 0xa24c20cbc66dL, 0x4a2e9efe48681L, 0x5e1296846271L, 0x7bbc8242c4550L, 0x59a06103b35b7L, 0x7237e4af32033L,
0x726421ab3537aL, 0x78cf25d38258cL, 0x2eeb32d9c495aL, 0x79e25772f9750L, 0x6d747833bbf23L, 0x6cdd816d5d749L, 0x39c00c9c13698L, 0x66b8e31489d68L,
0x573857e10e2b5L, 0x13be816aa1472L, 0x41964d3ad4bf8L, 0x6b52076b3ffL, 0x37e16b9ce082dL, 0x1882f57853eb9L, 0x7d29eacd01fc5L, 0x2e76a59b5e715L,
0x7de2e9561a9f7L, 0xcfe19d95781cL, 0x312cc621c453cL, 0x145ace6da077cL, 0x912bef9ce9b8L, 0x4d57e3443bc76L, 0xd4f4b6a55ecbL, 0x7ebb0bb733bceL,
0x7ba6a05200549L, 0x4f6ede4e22069L, 0x6b2a90af1a602L, 0x3f3245bb2d80aL, 0xe5f720f36efdL, 0x3b9cccf60c06dL, 0x84e323f37926L, 0x465812c8276c2L,
0x3f4fc9ae61e97L, 0x3bc07ebfa2d24L, 0x3b744b55cd4a0L, 0x72553b25721f3L, 0x5fd8f4e9d12d3L, 0x3beb22a1062d9L, 0x6a7063b82c9a8L, 0xa5a35dc197edL,
0x3c80c06a53defL, 0x5b32c2b1cb16L, 0x4a42c7ad58195L, 0x5c8667e799effL, 0x2e5e74c850a1L, 0x3f0db614e869aL, 0x31771a4856730L, 0x5eccd24da8fdL,
0x580bbfdf07918L, 0x7e73586873c6aL, 0x74ceddf77f93eL, 0x3b5556a37b471L, 0xc524e14dd482L, 0x283457496c656L, 0xad6bcfb6cd45L, 0x375d1e8b02414L,
0x4fc079d27a733L, 0x48b440c86c50dL, 0x139929cca3b86L, 0xf8f2e44cdf2fL, 0x68432117ba6b2L, 0x241170c2bae3cL, 0x138b089bf2f7fL, 0x4a05bfd34ea39L,
0x203914c925ef5L, 0x7497fffe04e3cL, 0x124567cecaf98L, 0x1ab860ac473b4L, 0x5c0227c86a7ffL, 0x71b12bfc24477L, 0x6a573a83075L, 0x3f8612966c870L,
0xfcfa36048d13L, 0x66e7133bbb383L, 0x64b42a8a45676L, 0x4ea6e4f9a85cfL, 0x26f57eee878a1L, 0x20cc9782a0ddeL, 0x65d4e3070aab3L, 0x7bc8e31547736L,
0x9ebfb1432d98L, 0x504aa77679736L, 0x32cd55687efb1L, 0x4448f5e2f6195L, 0x568919d460345L, 0x34c2e0ad1a27L, 0x4041943d9dba3L, 0x17743a26caaddL,
0x48c9156f9c964L, 0x7ef278d1e9ad0L, 0xce58ea7bd01L, 0x12d931429800dL, 0xeeba43ebcc96L, 0x384dd5395f878L, 0x1df331a35d272L, 0x207ecfd4af70eL,
0x1420a1d976843L, 0x67799d337594fL, 0x1647548f6018L, 0x57fce5578f145L, 0x9220c142a71L, 0x1b4f92314359aL, 0x73030a49866b1L, 0x2442be90b2679L,
0x77bd3d8947dcfL, 0x1fb55c1552028L, 0x5ff191d56f9a2L, 0x4109d89150951L, 0x225bd2d2d47cbL, 0x57cc080e73beaL, 0x6d71075721fcbL, 0x239b572a7f132L,
0x6d433ac2d9068L, 0x72bf930a47033L, 0x64facf4a20eadL, 0x365f7a2b9402aL, 0x20c526a758f3L, 0x1ef59f042cc89L, 0x3b1c24976dd26L, 0x31d665cb16272L,
0x28656e470c557L, 0x452cfe0a5602cL, 0x34f89ed8dbbcL, 0x73b8f948d8ef3L, 0x786c1d323caabL, 0x43bd4a9266e51L, 0x2aacc4615313L, 0xf7a0647877dfL,
0x4e1cc0f93f0d4L, 0x7ec4726ef1190L, 0x3bdd58bf512f8L, 0x4cfb7d7b304b8L, 0x699c29789ef12L, 0x63beae321bc50L, 0x325c340adbb35L, 0x562e1a1e42bf6L,
0x5b1d4cbc434d3L, 0x43d6cb89b75feL, 0x3338d5b900e56L, 0x38d327d531a53L, 0x1b25c61d51b9fL, 0x14b4622b39075L, 0x32615cc0a9f26L, 0x57711b99cb6dfL,
0x5a69c14e93c38L, 0x6e88980a4c599L, 0x2f98f71258592L, 0x2ae444f54a701L, 0x615397afbc5c2L, 0x60d7783f3f8fbL, 0x2aa675fc486baL, 0x1d8062e9e7614L,
0x4a74cb50f9e56L, 0x531d1c2640192L, 0xc03d9d6c7fd2L, 0x57ccd156610c1L, 0x3a6ae249d806aL, 0x2da85a9907c5aL, 0x6b23721ec4cafL, 0x4d2d3a4683aa2L,
0x7f9c6870efdefL, 0x298b8ce8aef25L, 0x272ea0a2165deL, 0x68179ef3ed06fL, 0x4e2b9c0feac1eL, 0x3ee290b1b63bbL, 0x6ba6271803a7dL, 0x27953eff70cb2L,
0x54f22ae0ec552L, 0x29f3da92e2724L, 0x242ca0c22bd18L, 0x34b8a8404d5ceL, 0x6ecb583693335L, 0x3ec76bfdfb84dL, 0x2c895cf56a04fL, 0x6355149d54d52L,
0x71d62bdd465e1L, 0x5b5dab1f75ef5L, 0x1e2d60cbeb9a5L, 0x527c2175dfe57L, 0x59e8a2b8ff51fL, 0x1c333621262b2L, 0x3cc28d378df80L, 0x72141f4968ca6L,
0x407696bdb6d0dL, 0x5d271b22ffcfbL, 0x74d5f317f3172L, 0x7e55467d9ca81L, 0x6a5653186f50dL, 0x6b188ece62df1L, 0x4c66d36844971L, 0x4aebcc4547e9dL,
0x8d9e7354b610L, 0x26b750b6dc168L, 0x162881e01acc9L, 0x7966df31d01a5L, 0x173bd9ddc9a1dL, 0x71b276d01c9L, 0xb0d8918e025eL, 0x75beea79ee2ebL,
0x3c92984094db8L, 0x5d88fbf95a3dbL, 0xf1efe5872dfL, 0x5da872318256aL, 0x59ceb81635960L, 0x18cf37693c764L, 0x6e1cd13b19eaL, 0x3af629e5b0353L,
0x204f1a088e8e5L, 0x10efc9ceea82eL, 0x589863c2fa34bL, 0x7f3a6a1a8d837L, 0xad516f166f23L, 0x263f56d57c81aL, 0x13422384638caL, 0x1331ff1af0a50L,
0x3080603526e16L, 0x644395d3d800bL, 0x2b9203dbedefcL, 0x4b18ce656a355L, 0x3f3466bc182cL, 0x30d0fded2e513L, 0x4971e68b84750L, 0x52ccc9779f396L,
0x3e904ae8255c8L, 0x4ecae46f39339L, 0x4615084351c58L, 0x14d1af21233b3L, 0x1de1989b39c0bL, 0x52669dc6f6f9eL, 0x43434b28c3fc7L, 0xa9214202c099L,
0x19c0aeb9a02eL, 0x1a2c06995d792L, 0x664cbb1571c44L, 0x6ff0736fa80b2L, 0x3bca0d2895ca5L, 0x8eb69ecc01bfL, 0x5b4c8912df38dL, 0x5ea7f8bc2f20eL,
0x120e516caafafL, 0x4ea8b4038df28L, 0x31bc3c5d62a4L, 0x7d9fe0f4c081eL, 0x43ed51467f22cL, 0x1e6cc0c1ed109L, 0x5631deddae8f1L, 0x5460af1cad202L,
0xb4919dd0655dL, 0x7c4697d18c14cL, 0x231c890bba2a4L, 0x24ce0930542caL, 0x7a155fdf30b85L, 0x1c6c6e5d487f9L, 0x24be1134bdc5aL, 0x1405970326f32L,
0x549928a7324f4L, 0x90f5fd06c106L, 0x6abb1021e43fdL, 0x232bcfad711a0L, 0x3a5c13c047f37L, 0x41d4e3c28a06dL, 0x632a763ee1a2eL, 0x6fa4bffbd5e4dL,
0x5fd35a6ba4792L, 0x7b55e1de99de8L, 0x491b66dec0dcfL, 0x4a8ed0da64a1L, 0x5ecfc45096ebeL, 0x5edee93b488b2L, 0x5b3c11a51bc8fL, 0x4cf6b8b0b7018L,
0x5b13dc7ea32a7L, 0x18fc2db73131eL, 0x7e3651f8f57e3L, 0x25656055fa965L, 0x8f338d0c85eeL, 0x3a821991a73bdL, 0x3be6418f5870L, 0x1ddc18eac9ef0L,
0x54ce09e998dc2L, 0x530d4a82eb078L, 0x173456c9abf9eL, 0x7892015100dadL, 0x33ee14095fecbL, 0x6ad95d67a0964L, 0xdb3e7e00cbfbL, 0x43630e1f94825L,
0x4d1956a6b4009L, 0x213fe2df8b5e0L, 0x5ce3a41191e6L, 0x65ea753f10177L, 0x6fc3ee2096363L, 0x7ec36b96d67acL, 0x510ec6a0758b1L, 0xed87df022109L,
0x2a4ec1921e1aL, 0x6162f1cf795fL, 0x324ddcafe5eb9L, 0x18d5e0463218L, 0x7e78b9092428eL, 0x36d12b5dec067L, 0x6259a3b24b8a2L, 0x188b5f4170b9cL,
0x681c0dee15debL, 0x4dfe665f37445L, 0x3d143c5112780L, 0x5279179154557L, 0x39f8f0741424dL, 0x45e6eb357923dL, 0x42c9b5edb746fL, 0x2ef517885ba82L,
0x6bffb305b2f51L, 0x5b112b2d712ddL, 0x35774974fe4e2L, 0x4af87a96e3a3L, 0x57968290bb3a0L, 0x7974e8c58aedcL, 0x7757e083488c6L, 0x601c62ae7bc8bL,
0x45370c2ecab74L, 0x2f1b78fab143aL, 0x2b8430a20e101L, 0x1a49e1d88fee3L, 0x38bbb47ce4d96L, 0x1f0e7ba84d437L, 0x7dc43e35dc2aaL, 0x2a5c273e9718L,
0x32bc9dfb28b4fL, 0x48df4f8d5db1aL, 0x54c87976c028fL, 0x44fb81d82d50L, 0x66665887dd9c3L, 0x629760a6ab0b2L, 0x481e6c7243e6cL, 0x97e37046fc77L,
0x7ef72016758ccL, 0x718c5a907e3d9L, 0x3b9c98c6b383bL, 0x6ed255eccdcL, 0x6976538229a59L, 0x7f79823f9c30dL, 0x41ff068f587baL, 0x1c00a191bcd53L,
0x7b56f9c209e25L, 0x3781e5fccaabeL, 0x64a9b0431c06dL, 0x4d239a3b513e8L, 0x29723f51b1066L, 0x642f4cf04d9c3L, 0x4da095aa09b7aL, 0xa4e0373d784dL,
0x3d6a15b7d2919L, 0x41aa75046a5d6L, 0x691751ec2d3daL, 0x23638ab6721c4L, 0x71a7d0ace183L, 0x4355220e14431L, 0xe1362a283981L, 0x2757cd8359654L,
0x2e9cd7ab10d90L, 0x7c69bcf761775L, 0x72daac887ba0bL, 0xb7f4ac5dda60L, 0x3bdda2c0498a4L, 0x74e67aa180160L, 0x2c3bcc7146ea7L, 0xd7eb04e8295fL,
0x4a5ea1e6fa0feL, 0x45e635c436c60L, 0x28ef4a8d4d18bL, 0x6f5a9a7322acaL, 0x1d4eba3d944beL, 0x100f15f3dce5L, 0x61a700e367825L, 0x5922292ab3d23L,
0x2ab9680ee8d3L, 0x1000c2f41c6c5L, 0x219fdf737174L, 0x314727f127de7L, 0x7e5277d23b81eL, 0x494e21a2e147aL, 0x48a85dde50d9aL, 0x1c1f734493df4L,
0x47bdb64866889L, 0x59a7d048f8eecL, 0x6b5d76cbea46bL, 0x141171e782522L, 0x6806d26da7c1fL, 0x3f31d1bc79ab9L, 0x9f20459f5168L, 0x16fb869c03dd3L,
0x7556cec0cd994L, 0x5eb9a03b7510aL, 0x50ad1dd91cb71L, 0x1aa5780b48a47L, 0xae333f685277L, 0x6199733b60962L, 0x69b157c266511L, 0x64740f893f1caL,
0x3aa408fbf684L, 0x3f81e38b8f70dL, 0x37f355f17c824L, 0x7ae85334815bL, 0x7e3abddd2e48fL, 0x61eeabe1f45e5L, 0xad3e2d34cdedL, 0x10fcc7ed9affeL,
0x4248cb0e96ff2L, 0x4311c115172e2L, 0x4c9d41cbf6925L, 0x50510fc104f50L, 0x40fc5336e249dL, 0x3386639fb2de1L, 0x7bbf871d17b78L, 0x75f796b7e8004L,
0x127c158bf0fa1L, 0x28fc4ae51b974L, 0x26e89bfd2dbd4L, 0x4e122a07665cfL, 0x7cab1203405c3L, 0x4ed82479d167dL, 0x17c422e9879a2L, 0x28a5946c8fec3L,
0x53ab32e912b77L, 0x7b44da09fe0a5L, 0x354ef87d07ef4L, 0x3b52260c5d975L, 0x79d6836171fdcL, 0x7d994f140d4bbL, 0x1b6c404561854L, 0x302d92d205392L,
0x46fb6e4e0f177L, 0x53497ad5265b7L, 0x1ebdba01386fcL, 0x302f0cb36a3cL, 0xedc5f5eb426dL, 0x3c1a2bca4283dL, 0x23430c7bb2f02L, 0x1a3ea1bb58bc2L,
0x7265763de5c61L, 0x10e5d3b76f1caL, 0x3bfd653da8e67L, 0x584953ec82a8aL, 0x55e288fa7707bL, 0x5395fc3931d81L, 0x45b46c51361cbL, 0x54ddd8a7fe3e4L,
0x2cecc41c619d3L, 0x43a6562ac4d91L, 0x4efa5aca7bdd9L, 0x5c1c0aef32122L, 0x2abf314f7fa1L, 0x391d19e8a1528L, 0x6a2fa13895fc7L, 0x9d8eddeaa591L,
0x2177bfa36dcb7L, 0x1bbcfa79db8fL, 0x3d84beb3666e1L, 0x20c921d812204L, 0x2dd843d3b32ceL, 0x4ae619387d8abL, 0x17e44985bfb83L, 0x54e32c626cc22L,
0x96412ff38118L, 0x6b241d61a246aL, 0x75685abe5ba43L, 0x3f6aa5344a32eL, 0x69683680f11bbL, 0x4c3581f623aaL, 0x701af5875cba5L, 0x1a00d91b17bf3L,
0x60933eb61f2b2L, 0x5193fe92a4dd2L, 0x3d995a550f43eL, 0x3556fb93a883dL, 0x135529b623b0eL, 0x716bce22e83feL, 0x33d0130b83eb8L, 0x952abad0afacL,
0x309f64ed31b8aL, 0x5972ea051590aL, 0xdbd7add1d518L, 0x119f823e2231eL, 0x451d66e5e7de2L, 0x500c39970f838L, 0x79b5b81a65ca3L, 0x4ac20dc8f7811L,
0x29589a9f501faL, 0x4d810d26a6b4aL, 0x5ede00d96b259L, 0x4f7e9c95905f3L, 0x443d355299feL, 0x39b7d7d5aee39L, 0x692519a2f34ecL, 0x6e4404924cf78L,
0x1942eec4a144aL, 0x74bbc5781302eL, 0x73135bb81ec4cL, 0x7ef671b61483cL, 0x7264614ccd729L, 0x31993ad92e638L, 0x45319ae234992L, 0x2219d47d24fb5L,
0x4f04488b06cf6L, 0x53aaa9e724a12L, 0x2a0a65314ef9cL, 0x61acd3c1c793aL, 0x58b46b78779e6L, 0x3369aacbe7af2L, 0x509b0743074d4L, 0x55dc39b6dea1L,
0x7937ff7f927c2L, 0xc2fa14c6a5b6L, 0x556bddb6dd07cL, 0x6f6acc179d108L, 0x4cf6e218647c2L, 0x1227cc28d5bb6L, 0x78ee9bff57623L, 0x28cb2241f893aL,
0x25b541e3c6772L, 0x121a307710aa2L, 0x1713ec77483c9L, 0x6f70572d5facbL, 0x25ef34e22ff81L, 0x54d944f141188L, 0x527bb94a6ced3L, 0x35d5e9f034a97L,
0x126069785bc9bL, 0x5474ec7854ff0L, 0x296a302a348caL, 0x333fc76c7a40eL, 0x5992a995b482eL, 0x78dc707002ac7L, 0x5936394d01741L, 0x4fba4281aef17L,
0x6b89069b20a7aL, 0x2fa8cb5c7db77L, 0x718e6982aa810L, 0x39e95f81a1a1bL, 0x5e794f3646cfbL, 0x473d308a7639L, 0x2a0416270220dL, 0x75f248b69d025L,
0x1cbbc16656a27L, 0x5b9ffd6e26728L, 0x23bc2103aa73eL, 0x6792603589e05L, 0x248db9892595dL, 0x6a53cad2d08L, 0x20d0150f7ba73L, 0x102f73bfde043L,
0x4dae0b5511c9aL, 0x5257fffe0d456L, 0x54108d1eb2180L, 0x96cc0f9baefaL, 0x3f6bd725da4eaL, 0xb9ab7f5745c6L, 0x5caf0f8d21d63L, 0x7debea408ea2bL,
0x9edb93896d16L, 0x36597d25ea5c0L, 0x58d7b106058acL, 0x3cdf8d20bee69L, 0xa4cb765015eL, 0x36832337c7cc9L, 0x7b7ecc19da60dL, 0x64a51a77cfa9bL,
0x29cf470ca0db5L, 0x4b60b6e0898d9L, 0x55d04ddffe6c7L, 0x3bedc661bf5cL, 0x2373c695c690dL, 0x4c0c8520dcf18L, 0x384af4b7494b9L, 0x4ab4a8ea22225L,
0x4235ad7601743L, 0xcb0d078975f5L, 0x292313e530c4bL, 0x38dbb9124a509L, 0x350d0655a11f1L, 0xe7ce2b0cdf06L, 0x6fedfd94b70f9L, 0x2383f9745bfd4L,
0x4beae27c4c301L, 0x75aa4416a3f3fL, 0x615256138aeceL, 0x4643ac48c85a3L, 0x6878c2735b892L, 0x3a53523f4d877L, 0x3a504ed8bee9dL, 0x666e0a5d8fb46L,
0x3f64e4870cb0dL, 0x61548b16d6557L, 0x7a261773596f3L, 0x7724d5f275d3aL, 0x7f0bc810d514dL, 0x49dad737213a0L, 0x745dee5d31075L, 0x7b1a55e7fdbe2L,
0x5ba988f176ea1L, 0x1d3a907ddec5aL, 0x6ba426f4136fL, 0x3cafc0606b720L, 0x518f0a2359cdaL, 0x5fae5e46feca7L, 0xd1f8dbcf8eedL, 0x693313ed081dcL,
0x5b0a366901742L, 0x40c872ca4ca7eL, 0x6f18094009e01L, 0x11b44a31bfL, 0x61f696a0aa75cL, 0x38b0a57ad42caL, 0x1e59ab706fdc9L, 0x1308d46ebfcdL,
0x63d988a2d2851L, 0x7a06c3fc66c0cL, 0x1c9bac1ba47fbL, 0x23935c575038eL, 0x3f0bd71c59c13L, 0x3ac48d916e835L, 0x20753afbd232eL, 0x71fbb1ed06002L,
0x39cae47a4af3aL, 0x337c0b34d9c2L, 0x33fad52b2368aL, 0x4c8d0c422cfe8L, 0x760b4275971a5L, 0x3da95bc1cad3dL, 0xf151ff5b7376L, 0x3cc355ccb90a7L,
0x649c6c5e41e16L, 0x60667eee6aa80L, 0x4179d182be190L, 0x653d9567e6979L, 0x16c0f429a256dL, 0x69443903e9131L, 0x16f4ac6f9dd36L, 0x2ea4912e29253L,
0x2b4643e68d25dL, 0x631eaf426bae7L, 0x175b9a3700de8L, 0x77c5f00aa48fbL, 0x3917785ca0317L, 0x5aa9b2c79399L, 0x431f2c7f665f8L, 0x10410da66fe9fL,
0x24d82dcb4d67dL, 0x3e6fe0e17752dL, 0x4dade1ecbb08fL, 0x5599648b1ea91L, 0x26344858f7b19L, 0x5f43d4a295ac0L, 0x242a75c52acd4L, 0x5934480220d10L,
0x7b04715f91253L, 0x6c280c4e6bac6L, 0x3ada3b361766eL, 0x42fe5125c3b4fL, 0x111d84d4aac22L, 0x48d0acfa57cdeL, 0x5bd28acf6ae43L, 0x16fab8f56907dL,
0x7acb11218d5f2L, 0x41fe02023b4dbL, 0x59b37bf5c2f65L, 0x726e47dabe671L, 0x2ec45e746f6c1L, 0x6580e53c74686L, 0x5eda104673f74L, 0x16234191336d3L,
0x19cd61ff38640L, 0x60c6c4b41ba9L, 0x75cf70ca7366fL, 0x118a8f16c011eL, 0x4a25707a203b9L, 0x499def6267ff6L, 0x76e858108773cL, 0x693cac5ddcb29L,
0x311d00a9ff4L, 0x2cdfdfecd5d05L, 0x7668a53f6ed6aL, 0x303ba2e142556L, 0x3880584c10909L, 0x4fe20000a261dL, 0x5721896d248e4L, 0x55091a1d0da4eL,
0x4f6bfc7c1050bL, 0x64e4ecd2ea9beL, 0x7eb1f28bbe70L, 0x3c935afc4b03L, 0x65517fd181baeL, 0x3e5772c76816dL, 0x19189640898aL, 0x1ed2a84de7499L,
0x578edd74f63c1L, 0x276c6492b0c3dL, 0x9bfc40bf932eL, 0x588e8f11f330bL, 0x3d16e694dc26eL, 0x3ec2ab590288cL, 0x13a09ae32d1cbL, 0x3e81eb85ab4e4L,
0x7aaca43cae1fL, 0x62f05d7526374L, 0xe1bf66c6adbaL, 0xd27be4d87bb9L, 0x56c27235db434L, 0x72e6e0ea62d37L, 0x5674cd06ee839L, 0x2dd5c25a200fcL,
0x3d5e9792c887eL, 0x319724dabbc55L, 0x2b97c78680800L, 0x7afdfdd34e6ddL, 0x730548b35ae88L, 0x3094ba1d6e334L, 0x6e126a7e3300bL, 0x89c0aefcfbc5L,
0x2eea11f836583L, 0x585a2277d8784L, 0x551a3cba8b8eeL, 0x3b6422be2d886L, 0x630e1419689bcL, 0x4653b07a7a955L, 0x3043443b411dbL, 0x25f8233d48962L,
0x6bd8f04aff431L, 0x4f907fd9a6312L, 0x40fd3c737d29bL, 0x7656278950ef9L, 0x73a3ea86cf9dL, 0x6e0e2abfb9c2eL, 0x60e2a38ea33eeL, 0x30b2429f3fe18L,
0x28bbf484b613fL, 0x3cf59d51fc8c0L, 0x7a0a0d6de4718L, 0x55c3a3e6fb74bL, 0x353135f884fd5L, 0x3f4160a8c1b84L, 0x12f5c6f136c7cL, 0xfedba237de4cL,
0x779bccebfab44L, 0x3aea93f4d6909L, 0x1e79cb358188fL, 0x153d8f5e08181L, 0x8533bbdb2efdL, 0x1149796129431L, 0x17a6e36168643L, 0x478ab52d39d1fL,
0x436c3eef7e3f1L, 0x7ffd3c21f0026L, 0x3e77bf20a2da9L, 0x418bffc8472deL, 0x65d7951b3a3b3L, 0x6a4d39252d159L, 0x790e35900ecd4L, 0x30725bf977786L,
0x10a5c1635a053L, 0x16d87a411a212L, 0x4d5e2d54e0583L, 0x2e5d7b33f5f74L, 0x3a5de3f887ebfL, 0x6ef24bd6139b7L, 0x1f990b577a5a6L, 0x57e5a42066215L,
0x1a18b44983677L, 0x3e652de1e6f8fL, 0x6532be02ed8ebL, 0x28f87c8165f38L, 0x44ead1be8f7d6L, 0x5759d4f31f466L, 0x378149f47943L, 0x69f3be32b4f29L,
0x45882fe1534d6L, 0x49929943c6fe4L, 0x4347072545b15L, 0x3226bced7e7c5L, 0x3a134ced89dfL, 0x7dcf843ce405fL, 0x1345d757983d6L, 0x222f54234cccdL,
0x1784a3d8adbb4L, 0x36ebeee8c2bccL, 0x688fe5b8f626fL, 0xd6484a4732c0L, 0x7b94ac6532d92L, 0x5771b8754850fL, 0x48dd9df1461c8L, 0x6739687e73271L,
0x5cc9dc80c1ac0L, 0x683671486d4cdL, 0x76f5f1a5e8173L, 0x6d5d3f5f9df4aL, 0x7da0b8f68d7e7L, 0x2014385675a6L, 0x6155fb53d1defL, 0x37ea32e89927cL,
0x59a668f5a82eL, 0x46115aba1d4dcL, 0x71953c3b5da76L, 0x6642233d37a81L, 0x2c9658076b1bdL, 0x5a581e63010ffL, 0x5a5f887e83674L, 0x628d3a0a643b9L,
0x1cd8640c93d2L, 0xb7b0cad70f2cL, 0x3864da98144beL, 0x43e37ae2d5d1cL, 0x301cf70a13d11L, 0x2a6a1ba1891ecL, 0x2f291fb3f3ae0L, 0x21a7b814bea52L,
0x3669b656e44d1L, 0x63f06eda6e133L, 0x233342758070fL, 0x98e0459cc075L, 0x4df5ead6c7c1bL, 0x6a21e6cd4fd5eL, 0x129126699b2e3L, 0xee11a2603de8L,
0x60ac2f5c74c21L, 0x59b192a196808L, 0x45371b07001e8L, 0x6170a3046e65fL, 0x5401a46a49e38L, 0x20add5561c4a8L, 0x7abb4edde9e46L, 0x586bf9f1a195fL,
0x3088d5ef8790bL, 0x38c2126fcb4dbL, 0x685bae149e3c3L, 0xbcd601a4e930L, 0xeafb03790e52L, 0x805e0f75ae1dL, 0x464cc59860a28L, 0x248e5b7b00befL,
0x5d99675ef8f75L, 0x44ae3344c5435L, 0x555c13748042fL, 0x4d041754232c0L, 0x521b430866907L, 0x3308e40fb9c39L, 0x309acc675a02cL, 0x289b9bba543eeL,
0x3ab592e28539eL, 0x64d82abcdd83aL, 0x3c78ec172e327L, 0x62d5221b7f946L, 0x5d4263af77a3cL, 0x23fdd2289aeb0L, 0x7dc64f77eb9ecL, 0x1bd28338402cL,
0x14f29a5383922L, 0x4299c18d0936dL, 0x5914183418a49L, 0x52a18c721aed5L, 0x2b151ba82976dL, 0x5c0efde4bc754L, 0x17edc25b2d7f5L, 0x37336a6081beeL,
0x7b5318887e5c3L, 0x49f6d491a5be1L, 0x5e72365c7bee0L, 0x339062f08b33eL, 0x4bbf3e657cfb2L, 0x67af7f56e5967L, 0x4dbd67f9ed68fL, 0x70b20555cb734L,
0x3fc074571217fL, 0x3a0d29b2b6aebL, 0x6478ccdde59dL, 0x55e4d051bddfaL, 0x77f1104c47b4eL, 0x113c555112c4cL, 0x7535103f9b7caL, 0x140ed1d9a2108L,
0x2522333bc2afL, 0xe34398f4a064L, 0x30b093e4b1928L, 0x1ce7e7ec80312L, 0x4e575bdf78f84L, 0x61f7a190bed39L, 0x6f8aded6ca379L, 0x522d93ecebde8L,
0x24f045e0f6cfL, 0x16db63426cfa1L, 0x1b93a1fd30fd8L, 0x5e5405368a362L, 0x123dfdb7b29aL, 0x4344356523c68L, 0x79a527921ee5fL, 0x74bfccb3e817eL,
0x780de72ec8d3dL, 0x7eaf300f42772L, 0x5455188354ce3L, 0x4dcca4a3dcbacL, 0x3d314d0bfebcbL, 0x1defc6ad32b58L, 0x28545089ae7bcL, 0x1e38fe9a0c15cL,
0x12046e0e2377bL, 0x6721c560aa885L, 0xeb28bf671928L, 0x3be1aef5195a7L, 0x6f22f62bdb5ebL, 0x39768b8523049L, 0x43394c8fbfdbdL, 0x467d201bf8dd2L,
0x6f4bd567ae7a9L, 0x65ac89317b783L, 0x7d3b20fd8932L, 0xf208326916L, 0x2ef9c5a5ba384L, 0x6919a74ef4fadL, 0x59ed4611452bfL, 0x691ec04ea09efL,
0x3cbcb2700e984L, 0x71c43c4f5ba3cL, 0x56df6fa9e74cdL, 0x79c95e4cf56dfL, 0x7be643bc609e2L, 0x149c12ad9e878L, 0x5a758ca390c5fL, 0x918b1d61dc94L,
0xd350260cd19cL, 0x7a2ab4e37b4d9L, 0x21fea735414d7L, 0xa738027f639dL, 0x72710d9462495L, 0x25aafaa007456L, 0x2d21f28eaa31bL, 0x17671ea005fd0L,
0x2dbae244b3eb7L, 0x74a2f57ffe1ccL, 0x1bc3073087301L, 0x7ec57f4019c34L, 0x34e082e1fa524L, 0x2698ca635126aL, 0x5702f5e3dd90eL, 0x31c9a4a70c5c7L,
0x136a5aa78fc24L, 0x1992f3b9f7b01L, 0x3c004b0c4afa3L, 0x5318832b0ba78L, 0x6f24b9ff17cecL, 0xa47f30e060c7L, 0x58384540dc8d0L, 0x1fb43dcc49caeL,
0x146ac06f4b82bL, 0x4b500d89e7355L, 0x3351e1c728a12L, 0x10b9f69932fe3L, 0x6b43fd01cd1fdL, 0x742583e760ef3L, 0x73dc1573216b8L, 0x4ae48fdd7714aL,
0x4f85f8a13e103L, 0x73420b2d6ff0dL, 0x75d4b4697c544L, 0x11be1fff7f8f4L, 0x119e16857f7e1L, 0x38a14345cf5d5L, 0x5a68d7105b52fL, 0x4f6cb9e851e06L,
0x278c4471895e5L, 0x7efcdce3d64e4L, 0x64f6d455c4b4cL, 0x3db5632fea34bL, 0x190b1829825d5L, 0xe7d3513225c9L, 0x1c12be3b7abaeL, 0x58777781e9ca6L,
0x59197ea495df2L, 0x6ee2bf75dd9d8L, 0x6c72ceb34be8dL, 0x679c9cc345ec7L, 0x7898df96898a4L, 0x4321adf49d75L, 0x16019e4e55aaeL, 0x74fc5f25d209cL,
0x4566a939ded0dL, 0x66063e716e0b7L, 0x45eafdc1f4d70L, 0x64624cfccb1edL, 0x257ab8072b6c1L, 0x120725676f0aL, 0x4a018d04e8eeeL, 0x3f73ceea5d56dL,
0x401858045d72bL, 0x459e5e0ca2d30L, 0x488b719308beaL, 0x56f4a0d1b32b5L, 0x5a5eebc80362dL, 0x7bfd10a4e8dc6L, 0x7c899366736f4L, 0x55ebbeaf95c01L,
0x46db060903f8aL, 0x2605889126621L, 0x18e3cc676e542L, 0x26079d995a990L, 0x4a7c217908b2L, 0x1dc7603e6655aL, 0xdedfa10b2444L, 0x704a68360ff04L,
0x3cecc3cde8b3eL, 0x21cd5470f64ffL, 0x6abc18d953989L, 0x54ad0c2e4e615L, 0x367d5b82b522aL, 0xd3f4b83d7dc7L, 0x3067f4cdbc58dL, 0x20452da697937L,
0x62ecb2baa77a9L, 0x72836afb62874L, 0xaf3c2094b240L, 0xc285297f357aL, 0x7cc2d5680d6e3L, 0x61913d5075663L, 0x5795261152b3dL, 0x7a1dbbafa3cbdL,
0x5ad31c52588d5L, 0x45f3a4164685cL, 0x2e59f919a966dL, 0x62d361a3231daL, 0x65284004e01b8L, 0x656533be91d60L, 0x6ae016c00a89fL, 0x3ddbc2a131c05L,
0x257a22796bb14L, 0x6f360fb443e75L, 0x680e47220eaeaL, 0x2fcf2a5f10c18L, 0x5ee7fb38d8320L, 0x40ff9ce5ec54bL, 0x57185e261b35bL, 0x3e254540e70a9L,
0x1b5814003e3f8L, 0x78968314ac04bL, 0x5fdcb41446a8eL, 0x5286926ff2a71L, 0xf231e296b3f6L, 0x684a357c84693L, 0x61d0633c9bca0L, 0x328bcf8fc73dfL,
0x3b4de06ff95b4L, 0x30aa427ba11a5L, 0x5ee31bfda6d9cL, 0x5b23ac2df8067L, 0x44935ffdb2566L, 0x12f016d176c6eL, 0x4fbb00f16f5aeL, 0x3fab78d99402aL,
0x6e965fd847aedL, 0x2b953ee80527bL, 0x55f5bcdb1b35aL, 0x43a0b3fa23c66L, 0x76e07388b820aL, 0x79b9bbb9dd95dL, 0x17dae8e9f7374L, 0x719f76102da33L,
0x5117c2a80ca8bL, 0x41a66b65d0936L, 0x1ba811460accbL, 0x355406a3126c2L, 0x50d1918727d76L, 0x6e5ea0b498e0eL, 0xa3b6063214f2L, 0x5065f158c9fd2L,
0x169fb0c429954L, 0x59aedd9ecee10L, 0x39916eb851802L, 0x57917555cc538L, 0x3981f39e58a4fL, 0x5dfa56de66fdeL, 0x58809075908L, 0x6d3d8cb854a94L,
0x5b2f4e970b1e3L, 0x30f4452edcbc1L, 0x38a7559230a93L, 0x52c1cde8ba31fL, 0x2a4f2d4745a3dL, 0x7e9d42d4a28aL, 0x38dc083705acdL, 0x52782c5759740L,
0x53f3397d990adL, 0x3a939c7e84d15L, 0x234c4227e39e0L, 0x632d9a1a593f2L, 0x1fd11ed0c84a7L, 0x21b3ed2757e1L, 0x73e1de58fc1c6L, 0x5d110c84616abL,
0x3a5a7df28af64L, 0x36b15b807cba6L, 0x3f78a9e1afed7L, 0xa59c2c608f1fL, 0x52bdd8ecb81b7L, 0xb24f48847ed4L, 0x2d4be511beac7L, 0x6bda4d99e5b9bL,
0x17e6996914e01L, 0x7b1f0ce7fcf80L, 0x34fcf74475481L, 0x31dab78cfaa98L, 0x4e3216e5e54b7L, 0x249823973b689L, 0x2584984e48885L, 0x119a3042fb37L,
0x7e04c789767caL, 0x1671b28cfb832L, 0x7e57ea2e1c537L, 0x1fbaaef444141L, 0x3d3bdc164dfa6L, 0x2d89ce8c2177dL, 0x6cd12ba182cf4L, 0x20a8ac19a7697L,
0x539fab2cc72d9L, 0x56c088f1ede20L, 0x35fac24f38f02L, 0x7d75c6197ab03L, 0x33e4bc2a42fa7L, 0x1c7cd10b48145L, 0x38b7ea483590L, 0x53d1110a86e17L,
0x6416eb65f466dL, 0x41ca6235fce20L, 0x5c3fc8a99bb12L, 0x9674c6b99108L, 0x6f82199316ff8L, 0x5d54f1a9f3e9L, 0x3bcc5d0bd274aL, 0x5b284b8d2d5adL,
0x6e5e31025969eL, 0x4fb0e63066222L, 0x130f59747e660L, 0x41868fecd41aL, 0x3105e8c923bc6L, 0x3058ad43d1838L, 0x462f587e593fbL, 0x3d94ba7ce362dL,
0x330f9b52667b7L, 0x5d45a48e0f00aL, 0x8f5114789a8dL, 0x40ffde57663d0L, 0x71445d4c20647L, 0x2653e68170f7cL, 0x64cdee3c55ed6L, 0x26549fa4efe3dL,
0x68549af3f666eL, 0x9e2941d4bb68L, 0x2e8311f5dff3cL, 0x6429ef91ffbd2L, 0x3a10dfe132ce3L, 0x55a461e6bf9d6L, 0x78eeef4b02e83L, 0x1d34f648c16cfL,
0x7fea2aba5132L, 0x1926e1dc6401eL, 0x74e8aea17cea0L, 0xc743f83fbc0fL, 0x7cb03c4bf5455L, 0x68a8ba9917e98L, 0x1fa1d01d861e5L, 0x4ac00d1df94abL,
0x3ba2101bd271bL, 0x7578988b9c4afL, 0xf2bf89f49f7eL, 0x73fced18ee9a0L, 0x55947d599832L, 0x346fe2aa41990L, 0x164c8079195bL, 0x799ccfb7bba27L,
0x773563bc6a75cL, 0x1e90863139cb3L, 0x4f8b407d9a0d6L, 0x58e24ca924f69L, 0x7a246bbe76456L, 0x1f426b701b864L, 0x635c891a12552L, 0x26aebd38ede2fL,
0x66dc8faddae05L, 0x21c7d41a03786L, 0xb76bb1b3fa7eL, 0x1264c41911c01L, 0x702f44584bdf9L, 0x43c511fc68edeL, 0x482c3aed35f9L, 0x4e1af5271d31bL,
0xc1f97f92939bL, 0x17a88956dc117L, 0x6ee005ef99dc7L, 0x4aa9172b231ccL, 0x7b6dd61eb772aL, 0xabf9ab01d2c7L, 0x3880287630ae6L, 0x32eca045beddbL,
0x57f43365f32d0L, 0x53fa9b659bff6L, 0x5c1e850f33d92L, 0x1ec119ab9f6f5L, 0x7f16f6de663e9L, 0x7a7d6cb16dec6L, 0x703e9bceaf1d2L, 0x4c8e994885455L,
0x4ccb5da9cad82L, 0x3596bc610e975L, 0x7a80c0ddb9f5eL, 0x398d93e5c4c61L, 0x77c60d2e7e3f2L, 0x4061051763870L, 0x67bc4e0ecd2aaL, 0x2bb941f1373b9L,
0x699c9c9002c30L, 0x3d16733e248f3L, 0xe2b7e14be389L, 0x42c0ddaf6784aL, 0x589ea1fc67850L, 0x53b09b5ddf191L, 0x6a7235946f1ccL, 0x6b99cbb2fbe60L,
0x6d3a5d6485c62L, 0x4839466e923c0L, 0x51caf30c6fcddL, 0x2f99a18ac54c7L, 0x398a39661ee6fL, 0x384331e40cde3L, 0x4cd15c4de19a6L, 0x12ae29c189f8eL,
0x3a7427674e00aL, 0x6142f4f7e74c1L, 0x4cc93318c3a15L, 0x6d51bac2b1ee7L, 0x5504aa292383fL, 0x6c0cb1f0d01cfL, 0x187469ef5d533L, 0x27138883747bfL,
0x2f52ae53a90e8L, 0x5fd14fe958ebaL, 0x2fe5ebf93cb8eL, 0x226da8acbe788L, 0x10883a2fb7ea1L, 0x94707842cf44L, 0x7dd73f960725dL, 0x42ddf2845ab2cL,
0x6214ffd3276bbL, 0xb8d181a5246L, 0x268a6d579eb20L, 0x93ff26e58647L, 0x524fe68059829L, 0x65b75e47cb621L, 0x15eb0a5d5cc19L, 0x5209b3929d5aL,
0x2f59bcbc86b47L, 0x1d560b691c301L, 0x7f5bafce3ce08L, 0x4cd561614806cL, 0x4588b6170b188L, 0x2aa55e3d01082L, 0x47d429917135fL, 0x3eacfa07af070L,
0x1deab46b46e44L, 0x7a53f3ba46cdfL, 0x5458b42e2e51aL, 0x192e60c07444fL, 0x5ae8843a21daaL, 0x6d721910b1538L, 0x3321a95a6417eL, 0x13e9004a8a768L,
0x600c9193b877fL, 0x21c1b8a0d7765L, 0x379927fb38ea2L, 0x70d7679dbe01bL, 0x5f46040898de9L, 0x58845832fcedbL, 0x135cd7f0c6e73L, 0x53ffbdfe8e35bL,
0x22f195e06e55bL, 0x73937e8814bceL, 0x37116297bf48dL, 0x45a9e0d069720L, 0x25af71aa744ecL, 0x41af0cb8aaba3L, 0x2cf8a4e891d5eL, 0x5487e17d06ba2L,
0x3872a032d6596L, 0x65e28c09348e0L, 0x27b6bb2ce40c2L, 0x7a6f7f2891d6aL, 0x3fd8707110f67L, 0x26f8716a92db2L, 0x1cdaa1b753027L, 0x504be58b52661L,
0x2049bd6e58252L, 0x1fd8d6a9aef49L, 0x7cb67b7216fa1L, 0x67aff53c3b982L, 0x20ea610da9628L, 0x6011aadfc5459L, 0x6d0c802cbf890L, 0x141bfed554c7bL,
0x6dbb667ef4263L, 0x58f3126857edcL, 0x69ce18b779340L, 0x7926dcf95f83cL, 0x42e25120e2becL, 0x63de96df1fa15L, 0x4f06b50f3f9ccL, 0x6fc5cc1b0b62fL,
0x75528b29879cbL, 0x79a8fd2125a3dL, 0x27c8d4b746ab8L, 0xf8893f02210cL, 0x15596b3ae5710L, 0x731167e5124caL, 0x17b38e8bbe13fL, 0x3d55b942f9056L,
0x9c1495be913fL, 0x3aa4e241afb6dL, 0x739d23f9179a2L, 0x632fadbb9e8c4L, 0x7c8522bfe0c48L, 0x6ed0983ef5aa9L, 0xd2237687b5f4L, 0x138bf2a3305f5L,
0x1f45d24d86598L, 0x5274bad2160feL, 0x1b6041d58d12aL, 0x32fcaa6e4687aL, 0x7a4732787ccdfL, 0x11e427c7f0640L, 0x3659385f8c64L, 0x5f4ead9766bfbL,
0x746f6336c2600L, 0x56e8dc57d9af5L, 0x5b3be17be4f78L, 0x3bf928cf82f4bL, 0x52e55600a6f11L, 0x4627e9cefebd6L, 0x2f345ab6c971cL, 0x653286e63e7e9L,
0x51061b78a23adL, 0x14999acb54501L, 0x7b4917007ed66L, 0x41b28dd53a2ddL, 0x37be85f87ea86L, 0x74be3d2a85e41L, 0x1be87fac96ca6L, 0x1d03620fe08cdL,
0x5fb5cab84b064L, 0x2513e778285b0L, 0x457383125e043L, 0x6bda3b56e223dL, 0x122ba376f844fL, 0x232cda2b4e554L, 0x422ba30ff840L, 0x751e7667b43f5L,
0x6261755da5f3eL, 0x2c70bf52b68eL, 0x532bf458d72e1L, 0x40f96e796b59cL, 0x22ef79d6f9da3L, 0x501ab67beca77L, 0x6b0697e3feb43L, 0x7ec4b5d0b2fbbL,
0x200e910595450L, 0x742057105715eL, 0x2f07022530f60L, 0x26334f0a409efL, 0xf04adf62a3c0L, 0x5e0edb48bb6d9L, 0x7c34aa4fbc003L, 0x7d74e4e5cac24L,
0x1cc37f43441b2L, 0x656f1c9ceaeb9L, 0x7031cacad5aecL, 0x1308cd0716c57L, 0x41c1373941942L, 0x3a346f772f196L, 0x7565a5cc7324fL, 0x1ca0d5244a11L,
0x116b067418713L, 0xa57d8c55edaeL, 0x6c6809c103803L, 0x55112e2da6ac8L, 0x6363d0a3dba5aL, 0x319c98ba6f40cL, 0x2e84b03a36ec7L, 0x5911b9f6ef7cL,
0x1acf3512eeaefL, 0x2639839692a69L, 0x669a234830507L, 0x68b920c0603d4L, 0x555ef9d1c64b2L, 0x39983f5df0ebbL, 0x1ea2589959826L, 0x6ce638703cdd6L,
0x6311678898505L, 0x6b3cecf9aa270L, 0x770ba3b73bd08L, 0x11475f7e186d4L, 0x251bc9892bbcL, 0x24eab9bffcc5aL, 0x675f4de133817L, 0x7f6d93bdab31dL,
0x1f3aca5bfd425L, 0x2fa521c1c9760L, 0x62180ce27f9cdL, 0x60f450b882cd3L, 0x452036b1782fcL, 0x2d95b07681c5L, 0x5901cf99205b2L, 0x290686e5eecb4L,
0x13d99df70164cL, 0x35ec321e5c0caL, 0x13ae337f44029L, 0x4008e813f2da7L, 0x640272f8e0c3aL, 0x1c06de9e55edaL, 0x52b40ff6d69aaL, 0x31b8809377ffaL,
0x536625cd14c2cL, 0x516af252e17d1L, 0x78096f8e7d32bL, 0x77ad6a33ec4e2L, 0x717c5dc11d321L, 0x4a114559823e4L, 0x306ce50a1e2b1L, 0x4cf38a1fec2dbL,
0x2aa650dfa5ce7L, 0x54916a8f19415L, 0xdc96fe71278L, 0x55f2784e63eb8L, 0x373cad3a26091L, 0x6a8fb89ddbbadL, 0x78c35d5d97e37L, 0x66e3674ef2cb2L,
0x34347ac53dd8fL, 0x21547eda5112aL, 0x4634d82c9f57cL, 0x4249268a6d652L, 0x6336d687f2ff7L, 0x4fe4f4e26d9a0L, 0x40f3d945441L, 0x5e939fd5986d3L,
0x12a2147019bdfL, 0x4c466e7d09cb2L, 0x6fa5b95d203ddL, 0x63550a334a254L, 0x2584572547b49L, 0x75c58811c1377L, 0x4d3c637cc171bL, 0x33d30747d34e3L,
0x39a92bafaa7d7L, 0x7d6edb569cf37L, 0x60194a5dc2ca0L, 0x5af59745e10a6L, 0x7a8f53e004875L, 0x3eea62c7daf78L, 0x4c713e693274eL, 0x6ed1b7a6eb3a4L,
0x62ace697d8e15L, 0x266b8292ab075L, 0x68436a0665c9cL, 0x6d317e820107cL, 0x90815d2ca3caL, 0x3ff1eb1499a1L, 0x23960f050e319L, 0x5373669c91611L,
0x235e8202f3f27L, 0x44c9f2eb61780L, 0x630905b1d7003L, 0x4fcc8d274ead1L, 0x17b6e7f68ab78L, 0x14ab9a0e5257L, 0x9939567f8ba5L, 0x4b47b2a423c82L,
0x688d7e57ac42dL, 0x1cb4b5a678f87L, 0x4aa62a2a007e7L, 0x61e0e38f62d6eL, 0x2f888fcc4782L, 0x7562b83f21c00L, 0x2dc0fd2d82ef6L, 0x4c06b394afc6cL,
0x4931b4bf636ccL, 0x72b60d0322378L, 0x25127c6818b25L, 0x330bca78de743L, 0x6ff841119744eL, 0x2c560e8e49305L, 0x7254fefe5a57aL, 0x67ae2c560a7dfL,
0x3c31be1b369f1L, 0xbc93f9cb4272L, 0x3f8f9db73182dL, 0x2b235eabae1c4L, 0x2ddbf8729551aL, 0x41cec1097e7d5L, 0x4864d08948aeeL, 0x5d237438df61eL,
0x2b285601f7067L, 0x25dbcbae6d753L, 0x330b61134262dL, 0x619d7a26d808aL, 0x3c3b3c2adbef2L, 0x6877c9eec7f52L, 0x3beb9ebe1b66dL, 0x26b44cd91f287L,
0x7f29362730383L, 0x7fd7951459c36L, 0x7504c512d49e7L, 0x87ed7e3bc55fL, 0x7deb10149c726L, 0x48478f387475L, 0x69397d9678a3eL, 0x67c8156c976f3L,
0x2eb4d5589226cL, 0x2c709e6c1c10aL, 0x2af6a8766ee7aL, 0x8aaa79a1d96cL, 0x42f92d59b2fb0L, 0x1752c40009c07L, 0x8e68e9ff62ceL, 0x509d50ab8f2f9L,
0x1b8ab247be5e5L, 0x5d9b2e6b2e486L, 0x4faa5479a1339L, 0x4cb13bd738f71L, 0x5500a4bc130adL, 0x127a17a938695L, 0x2a26fa34e36dL, 0x584d12e1ecc28L,
0x2f1f3f87eeba3L, 0x48c75e515b64aL, 0x75b6952071ef0L, 0x5d46d42965406L, 0x7746106989f9fL, 0x19a1e353c0ae2L, 0x172cdd596bdbdL, 0x731ddf881684L,
0x10426d64f8115L, 0x71a4fd8a9a3daL, 0x736bd3990266aL, 0x47560bafa05c3L, 0x418dcabcc2fa3L, 0x35991cecf8682L, 0x24371a94b8c60L, 0x41546b11c20c3L,
0x32d509334b3b4L, 0x16c102cae70aaL, 0x1720dd51bf445L, 0x5ae662faf9821L, 0x412295a2b87faL, 0x55261e293eac6L, 0x6426759b65ccL, 0x40265ae116a48L,
0x6c02304bae5bcL, 0x760bb8d195adL, 0x19b88f57ed6e9L, 0x4cdbf1904a339L, 0x42b49cd4e4f2cL, 0x71a2e771909d9L, 0x14e153ebb52d2L, 0x61a17cde6818aL,
0x53dad34108827L, 0x32b32c55c55b6L, 0x2f9165f9347a3L, 0x6b34be9bc33acL, 0x469656571f2d3L, 0xaa61ce6f423fL, 0x3f940d71b27a1L, 0x185f19d73d16aL,
0x1b9c7b62e6ddL, 0x72f643a78c0b2L, 0x3de45c04f9e7bL, 0x706d68d30fa5cL, 0x696f63e8e2f24L, 0x2012c18f0922dL, 0x355e55ac89d29L, 0x3e8b414ec7101L,
0x39db07c520c90L, 0x6f41e9b77efe1L, 0x8af5b784e4baL, 0x314d289cc2c4bL, 0x23450e2f1bc4eL, 0xcd93392f92f4L, 0x1370c6a946b7dL, 0x6423c1d5afd98L,
0x499dc881f2533L, 0x34ef26476c506L, 0x4d107d2741497L, 0x346c4bd6efdb3L, 0x32b79d71163a1L, 0x5f8d9edfcb36aL, 0x1e6e8dcbf3990L, 0x7974f348af30aL,
0x6e6724ef19c7cL, 0x480a5efbc13e2L, 0x14ce442ce221fL, 0x18980a72516ccL, 0x72f80db86677L, 0x703331fda526eL, 0x24b31d47691c8L, 0x1e70b01622071L,
0x1f163b5f8a16aL, 0x56aaf341ad417L, 0x7989635d830f7L, 0x47aa27600cb7bL, 0x41eedc015f8c3L, 0x7cf8d27ef854aL, 0x289e3584693f9L, 0x4a7857b309a7L,
0x545b585d14ddaL, 0x4e4d0e3b321e1L, 0x7451fe3d2ac40L, 0x666f678eea98dL, 0x38858667feadL, 0x4d22dc3e64c8dL, 0x7275ea0d43a0fL, 0x681137dd7ccf7L,
0x1e79cbab79a38L, 0x22a214489a66aL, 0xf62f9c332ba5L, 0x46589d63b5f39L, 0x7eaf979ec3f96L, 0x4ebe81572b9a8L, 0x21b7f5d61694aL, 0x1c0fa01a36371L,
0x2b0e8c936a50L, 0x6b83b58b6cd21L, 0x37ed8d3e72680L, 0xa037db9f2a62L, 0x4005419b1d2bcL, 0x604b622943dffL, 0x1c899f6741a58L, 0x60219e2f232fbL,
0x35fae92a7f9cbL, 0xfa3614f3b1caL, 0x3febdb9be82f0L, 0x5e74895921400L, 0x553ea38822706L, 0x5a17c24cfc88cL, 0x1fba218aef40aL, 0x657043e7b0194L,
0x5c11b55efe9e7L, 0x7737bc6a074fbL, 0xeae41ce355ccL, 0x6c535d13ff776L, 0x49448fac8f53eL, 0x34f74c6e8356aL, 0xad780607dba2L, 0x7213a7eb63eb6L,
0x392e3acaa8c86L, 0x534e93e8a35afL, 0x8b10fd02c997L, 0x26ac2acb81e05L, 0x9d8c98ce3b79L, 0x25e17fe4d50acL, 0x77ff576f121a7L, 0x4e5f9b0fc722bL,
0x46f949b0d28c8L, 0x4cde65d17ef26L, 0x6bba828f89698L, 0x9bd71e04f676L, 0x25ac841f2a145L, 0x1a47eac823871L, 0x1a8a8c36c581aL, 0x255751442a9fbL,
0x1bc6690fe3901L, 0x314132f5abc5aL, 0x611835132d528L, 0x5f24b8eb48a57L, 0x559d504f7f6b7L, 0x91e7f6d266fdL, 0x36060ef037389L, 0x18788ec1d1286L,
0x287441c478eb0L, 0x123ea6a3354bdL, 0x38378b3eb54d5L, 0x4d4aaa78f94eeL, 0x4a002e875a74dL, 0x10b851367b17cL, 0x1ab12d5807e3L, 0x5189041e32d96L,
0x5b062b090231L, 0xc91766e7b78fL, 0xaa0f55a138ecL, 0x4a3961e2c918aL, 0x7d644f3233f1eL, 0x1c69f9e02c064L, 0x36ae5e5266898L, 0x8fc1dad38b79L,
0x68aceead9bd41L, 0x43be0f8e6bba0L, 0x68fdffc614e3bL, 0x4e91dab5b3be0L, 0x3b1d4c9212ff0L, 0x2cd6bce3fb1dbL, 0x4c90ef3d7c210L, 0x496f5a0818716L,
0x79cf88cc239b8L, 0x2cb9c306cf8dbL, 0x595760d5b508fL, 0x2cbebfd022790L, 0xb8822aec1105L, 0x4d1cfd226bcccL, 0x515b2fa4971beL, 0x2cb2c5df54515L,
0x1bfe104aa6397L, 0x11494ff996c25L, 0x64251623e5800L, 0xd49fc5e044beL, 0x709fa43edcb29L, 0x25d8c63fd2acaL, 0x4c5cd29dffd61L, 0x32ec0eb48af05L,
0x18f9391f9b77cL, 0x70f029ecf0c81L, 0x2afaa5e10b0b9L, 0x61de08355254dL, 0xeb587de3c28dL, 0x4f0bb9f7dbbd5L, 0x44eca5a2a74bdL, 0x307b32eed3e33L,
0x6748ab03ce8c2L, 0x57c0d9ab810bcL, 0x42c64a224e98cL, 0xb7d5d8a6c314L, 0x448327b95d543L, 0x146681e3a4baL, 0x38714adc34e0cL, 0x4f26f0e298e30L,
0x272224512c7deL, 0x3bb8a42a975fcL, 0x6f2d5b46b17efL, 0x7b6a9223170e5L, 0x53713fe3b7e6L, 0x19735fd7f6bc2L, 0x492af49c5342eL, 0x2365cdf5a0357L,
0x32138a7ffbb60L, 0x2a1f7d14646feL, 0x11b5df18a44ccL, 0x390d042c84266L, 0x1efe32a8fdc75L, 0x6925ee7ae1238L, 0x4af9281d0e832L, 0xfef911191df8L
// BASE_PRECOMP_END
};

void fe_neg(thread Fe& r, thread const Fe& a) {
    r.v[0] = 0xfffffffffffda - a.v[0];
    r.v[1] = 0xffffffffffffe - a.v[1];
    r.v[2] = 0xffffffffffffe - a.v[2];
    r.v[3] = 0xffffffffffffe - a.v[3];
    r.v[4] = 0xffffffffffffe - a.v[4];
}

// r = p + q, where q is an affine precomputed point.
void ge_madd(thread GeP3& r, thread const GeP3& p, thread const GePrecomp& q) {
    Fe ypx, ymx, xy2, z2, X, Y, Z, T;
    fe_add(ypx, p.Y, p.X);
    fe_sub(ymx, p.Y, p.X);
    fe_mul(ypx, ypx, q.yplusx);
    fe_mul(ymx, ymx, q.yminusx);
    fe_mul(xy2, q.xy2d, p.T);
    fe_add(z2, p.Z, p.Z);
    fe_sub(X, ypx, ymx);
    fe_add(Y, ypx, ymx);
    fe_add(Z, z2, xy2);
    fe_sub(T, z2, xy2);
    fe_mul(r.X, X, T);
    fe_mul(r.Y, Y, Z);
    fe_mul(r.Z, Z, T);
    fe_mul(r.T, X, Y);
}

void ge_select(thread GePrecomp& t, int pos, int b) {
    if (b == 0) {
        for (int i = 0; i < 5; i++) {
            t.yplusx.v[i] = (i == 0) ? 1 : 0;
            t.yminusx.v[i] = (i == 0) ? 1 : 0;
            t.xy2d.v[i] = 0;
        }
        return;
    }
    int absb = b;
    int neg = 0;
    if (b < 0) {
        absb = -b;
        neg = 1;
    }
    int base = (pos * 8 + (absb - 1)) * 15;
    for (int i = 0; i < 5; i++) {
        t.yplusx.v[i] = BASE_PRECOMP[base + i];
        t.yminusx.v[i] = BASE_PRECOMP[base + 5 + i];
        t.xy2d.v[i] = BASE_PRECOMP[base + 10 + i];
    }
    if (neg != 0) {
        Fe swap = t.yplusx;
        t.yplusx = t.yminusx;
        t.yminusx = swap;
        fe_neg(t.xy2d, t.xy2d);
    }
}

// R = s * B. s[31] <= 127, which the clamped Ed25519 scalar satisfies.
// Signed radix-16 digits, then the ref10 fixed-base addition chain:
// odd digits, four doublings, even digits.
void ge_scalarmult_base(thread GeP3& r, thread const uint8_t* s) {
    int e[64];
    for (int i = 0; i < 32; i++) {
        e[2 * i] = s[i] & 15;
        e[2 * i + 1] = (s[i] >> 4) & 15;
    }
    int carry = 0;
    for (int i = 0; i < 63; i++) {
        e[i] += carry;
        carry = (e[i] + 8) >> 4;
        e[i] -= carry << 4;
    }
    e[63] += carry;

    ge_p3_0(r);
    GePrecomp t;
    for (int i = 1; i < 64; i += 2) {
        ge_select(t, i / 2, e[i]);
        GeP3 acc = r;
        ge_madd(r, acc, t);
    }
    for (int i = 0; i < 4; i++) {
        GeP3 acc = r;
        ge_p3_dbl(r, acc);
    }
    for (int i = 0; i < 64; i += 2) {
        ge_select(t, i / 2, e[i]);
        GeP3 acc = r;
        ge_madd(r, acc, t);
    }
}

// Convert point to bytes (compressed Edwards Y coordinate with sign bit)
void ge_p3_tobytes(thread uint8_t* out, thread const GeP3& p) {
    Fe recip, x, y;

    fe_invert(recip, p.Z);
    fe_mul(x, p.X, recip);
    fe_mul(y, p.Y, recip);

    fe_to_bytes(out, y);
    uint8_t xbytes[32];
    fe_to_bytes(xbytes, x);
    out[31] |= (xbytes[0] & 1) << 7;
}

// ============================================================================
// Base58 Encoding
// ============================================================================

constant char BASE58_ALPHABET[58] = {
    '1','2','3','4','5','6','7','8','9',
    'A','B','C','D','E','F','G','H','J','K','L','M','N','P','Q','R','S','T','U','V','W','X','Y','Z',
    'a','b','c','d','e','f','g','h','i','j','k','m','n','o','p','q','r','s','t','u','v','w','x','y','z'
};

// Encode 32-byte public key to Base58 (returns length, max 44 chars)
int base58_encode(thread const uint8_t* input, thread char* output) {
    // Count leading zeros
    int zeros = 0;
    while (zeros < 32 && input[zeros] == 0) zeros++;

    // Convert to base58
    uint8_t b58[64];
    int b58_len = 0;

    for (int i = zeros; i < 32; i++) {
        uint32_t carry = input[i];
        for (int j = 0; j < b58_len || carry != 0; j++) {
            if (j < b58_len) carry += uint32_t(b58[j]) * 256;
            b58[j] = carry % 58;
            carry /= 58;
            if (j >= b58_len) b58_len = j + 1;
        }
    }

    // Output
    int out_len = zeros + b58_len;
    for (int i = 0; i < zeros; i++) output[i] = '1';
    for (int i = 0; i < b58_len; i++) {
        output[zeros + i] = BASE58_ALPHABET[b58[b58_len - 1 - i]];
    }

    return out_len;
}

// ============================================================================
// Pattern Matching
// ============================================================================

struct PatternConfig {
    uint32_t length;
    uint32_t match_mode;  // 0=prefix, 1=suffix, 2=anywhere
    uint32_t ignore_case;
    char pattern[32];
};

bool pattern_matches(thread const char* address, int addr_len, device const PatternConfig* config) {
    uint32_t plen = config->length;
    if (plen == 0 || addr_len < int(plen)) return false;

    int start, end;

    if (config->match_mode == 0) {  // prefix
        start = 0;
        end = 1;
    } else if (config->match_mode == 1) {  // suffix
        start = addr_len - plen;
        end = start + 1;
    } else {  // anywhere
        start = 0;
        end = addr_len - plen + 1;
    }

    for (int pos = start; pos < end; pos++) {
        bool match = true;
        for (uint32_t i = 0; i < plen && match; i++) {
            char pc = config->pattern[i];
            char ac = address[pos + i];

            if (pc == '?') continue;  // wildcard

            if (config->ignore_case) {
                // Convert to lowercase
                if (pc >= 'A' && pc <= 'Z') pc += 32;
                if (ac >= 'A' && ac <= 'Z') ac += 32;
            }

            if (pc != ac) match = false;
        }
        if (match) return true;
    }
    return false;
}

// ============================================================================
// xorshift128+ PRNG
// ============================================================================

struct Rng {
    uint64_t s0;
    uint64_t s1;

    uint64_t next() {
        uint64_t x = s0;
        uint64_t y = s1;
        s0 = y;
        x ^= x << 23;
        s1 = x ^ y ^ (x >> 17) ^ (y >> 26);
        return s1 + y;
    }
};

// ============================================================================
// Main Kernel: Full vanity address generation pipeline
// ============================================================================

struct ResultBuffer {
    uint32_t found;           // 1 if match found
    uint32_t thread_id;       // Thread that found match
    uint8_t public_key[32];   // Public key bytes
    uint8_t private_key[64];  // Solana keypair: raw seed || public key
    char address[48];         // Base58 address
    uint32_t address_len;     // Address length
};

kernel void vanity_search(
    device const uint64_t* base_state [[buffer(0)]],
    device const PatternConfig* pattern [[buffer(1)]],
    device ResultBuffer* results [[buffer(2)]],
    device atomic_uint* found_flag [[buffer(3)]],
    uint tid [[thread_position_in_grid]]
) {
    // Check if another thread already found a match
    if (atomic_load_explicit(found_flag, memory_order_relaxed) != 0) return;

    // Initialize RNG with unique state per thread
    Rng rng;
    rng.s0 = base_state[0] ^ (uint64_t(tid) * 0x9E3779B97F4A7C15ULL);
    rng.s1 = base_state[1] ^ (uint64_t(tid) * 0x6A09E667BB67AE85ULL);

    // Generate random 32-byte seed
    uint8_t seed[32];
    for (int i = 0; i < 4; i++) {
        uint64_t r = rng.next();
        seed[i*8 + 0] = r & 0xFF;
        seed[i*8 + 1] = (r >> 8) & 0xFF;
        seed[i*8 + 2] = (r >> 16) & 0xFF;
        seed[i*8 + 3] = (r >> 24) & 0xFF;
        seed[i*8 + 4] = (r >> 32) & 0xFF;
        seed[i*8 + 5] = (r >> 40) & 0xFF;
        seed[i*8 + 6] = (r >> 48) & 0xFF;
        seed[i*8 + 7] = (r >> 56) & 0xFF;
    }

    // SHA-512 hash the seed
    uint8_t hash[64];
    sha512_32bytes(seed, hash);

    // Clamp scalar for Ed25519
    hash[0] &= 0xF8;
    hash[31] &= 0x7F;
    hash[31] |= 0x40;

    // Scalar multiplication to get public key
    GeP3 A;
    ge_scalarmult_base(A, hash);

    // Convert to compressed Edwards format
    uint8_t public_key[32];
    ge_p3_tobytes(public_key, A);

    // Base58 encode
    char address[48];
    int addr_len = base58_encode(public_key, address);

    // Pattern match
    if (pattern_matches(address, addr_len, pattern)) {
        // Try to claim the result
        uint expected = 0;
        if (atomic_compare_exchange_weak_explicit(found_flag, &expected, 1,
                                                   memory_order_relaxed,
                                                   memory_order_relaxed)) {
            // We won the race - store result
            results->found = 1;
            results->thread_id = tid;
            results->address_len = addr_len;

            for (int i = 0; i < 32; i++) {
                results->public_key[i] = public_key[i];
                // solana-keygen treats the first 32 bytes as the seed, not the clamped scalar.
                results->private_key[i] = seed[i];
                results->private_key[32 + i] = public_key[i];
            }
            for (int i = 0; i < addr_len; i++) {
                results->address[i] = address[i];
            }
        }
    }
}

// ============================================================================
// Simple seed generation kernel (fallback)
// ============================================================================

struct SeedBuffer {
    uint32_t seeds[8];
};

kernel void generate_seeds(
    device SeedBuffer* seeds [[buffer(0)]],
    device const uint64_t* base_state [[buffer(1)]],
    uint tid [[thread_position_in_grid]]
) {
    Rng rng;
    rng.s0 = base_state[0] ^ (uint64_t(tid) * 0x9E3779B97F4A7C15ULL);
    rng.s1 = base_state[1] ^ (uint64_t(tid) * 0x6A09E667BB67AE85ULL);

    device SeedBuffer& out = seeds[tid];
    for (uint i = 0; i < 8; i += 2) {
        uint64_t r = rng.next();
        out.seeds[i] = uint32_t(r);
        out.seeds[i + 1] = uint32_t(r >> 32);
    }
}
