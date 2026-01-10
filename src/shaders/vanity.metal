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

void fe_mul(thread Fe& r, thread const Fe& a, thread const Fe& b) {
    int64_t a0 = a.v[0], a1 = a.v[1], a2 = a.v[2], a3 = a.v[3], a4 = a.v[4];
    int64_t b0 = b.v[0], b1 = b.v[1], b2 = b.v[2], b3 = b.v[3], b4 = b.v[4];

    int64_t r0 = a0*b0 + 19*(a1*b4 + a2*b3 + a3*b2 + a4*b1);
    int64_t r1 = a0*b1 + a1*b0 + 19*(a2*b4 + a3*b3 + a4*b2);
    int64_t r2 = a0*b2 + a1*b1 + a2*b0 + 19*(a3*b4 + a4*b3);
    int64_t r3 = a0*b3 + a1*b2 + a2*b1 + a3*b0 + 19*a4*b4;
    int64_t r4 = a0*b4 + a1*b3 + a2*b2 + a3*b1 + a4*b0;

    r.v[0] = r0; r.v[1] = r1; r.v[2] = r2; r.v[3] = r3; r.v[4] = r4;
    fe_reduce(r);
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

// Base point for Ed25519
constant int64_t GX[5] = {
    0x62d608f25d51a, 0x412a4b4f6592a, 0x75b7171a4b31d, 0x1ff60527118fe, 0x216936d3cd6e5
};
constant int64_t GY[5] = {
    0x6666666666658, 0x4cccccccccccc, 0x1999999999999, 0x3333333333333, 0x6666666666666
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

// d constant for Ed25519: -121665/121666
constant int64_t D_CONST[5] = {
    0x34dca135978a3, 0x1a8283b156ebd, 0x5e7a26001c029, 0x739c663a03cbb, 0x52036cee2b6ff
};

void ge_p3_add(thread GeP3& r, thread const GeP3& p, thread const GeP3& q) {
    Fe A, B, C, D, E, F, G, H;
    Fe d2;

    // d2 = 2*d
    for (int i = 0; i < 5; i++) d2.v[i] = D_CONST[i] * 2;

    fe_sub(A, p.Y, p.X);
    Fe qyminusx;
    fe_sub(qyminusx, q.Y, q.X);
    fe_mul(A, A, qyminusx);

    fe_add(B, p.Y, p.X);
    Fe qyplusx;
    fe_add(qyplusx, q.Y, q.X);
    fe_mul(B, B, qyplusx);

    fe_mul(C, p.T, q.T);
    fe_mul(C, C, d2);

    fe_mul(D, p.Z, q.Z);
    fe_add(D, D, D);

    fe_sub(E, B, A);
    fe_sub(F, D, C);
    fe_add(G, D, C);
    fe_add(H, B, A);

    fe_mul(r.X, E, F);
    fe_mul(r.Y, G, H);
    fe_mul(r.T, E, H);
    fe_mul(r.Z, F, G);
}

// Scalar multiplication: R = s * G (base point multiplication)
void ge_scalarmult_base(thread GeP3& r, thread const uint8_t* s) {
    // Initialize result to identity
    ge_p3_0(r);

    // Set up base point
    GeP3 G;
    for (int i = 0; i < 5; i++) {
        G.X.v[i] = GX[i];
        G.Y.v[i] = GY[i];
        G.Z.v[i] = (i == 0) ? 1 : 0;
    }
    fe_mul(G.T, G.X, G.Y);

    // Double-and-add (simple but not constant-time - OK for key generation)
    GeP3 Q = G;

    for (int i = 0; i < 256; i++) {
        int byte_idx = i / 8;
        int bit_idx = i % 8;

        if ((s[byte_idx] >> bit_idx) & 1) {
            ge_p3_add(r, r, Q);
        }
        ge_p3_dbl(Q, Q);
    }
}

// Convert point to bytes (compressed Edwards Y coordinate with sign bit)
void ge_p3_tobytes(thread uint8_t* out, thread const GeP3& p) {
    Fe recip, x, y;

    fe_invert(recip, p.Z);
    fe_mul(x, p.X, recip);
    fe_mul(y, p.Y, recip);

    fe_to_bytes(out, y);
    out[31] ^= (x.v[0] & 1) << 7;  // Encode sign of x in high bit
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
    uint8_t private_key[64];  // Private key (hash + public)
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
                results->private_key[i] = hash[i];
                results->private_key[32 + i] = public_key[i];
            }
            for (int i = 32; i < 64; i++) {
                results->private_key[i] = (i < 32 + addr_len) ? public_key[i - 32] : 0;
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
