// MD5 hash compute shader
//
// Computes MD5 hashes for batches of pre-padded input blocks.
// Each thread processes one input message.
// Note: MD5 produces 16 bytes, which is duplicated to fill 32 bytes.

// MD5 constants (sine-based)
const K: array<u32, 64> = array<u32, 64>(
    0xd76aa478u, 0xe8c7b756u, 0x242070dbu, 0xc1bdceeeu,
    0xf57c0fafu, 0x4787c62au, 0xa8304613u, 0xfd469501u,
    0x698098d8u, 0x8b44f7afu, 0xffff5bb1u, 0x895cd7beu,
    0x6b901122u, 0xfd987193u, 0xa679438eu, 0x49b40821u,
    0xf61e2562u, 0xc040b340u, 0x265e5a51u, 0xe9b6c7aau,
    0xd62f105du, 0x02441453u, 0xd8a1e681u, 0xe7d3fbc8u,
    0x21e1cde6u, 0xc33707d6u, 0xf4d50d87u, 0x455a14edu,
    0xa9e3e905u, 0xfcefa3f8u, 0x676f02d9u, 0x8d2a4c8au,
    0xfffa3942u, 0x8771f681u, 0x6d9d6122u, 0xfde5380cu,
    0xa4beea44u, 0x4bdecfa9u, 0xf6bb4b60u, 0xbebfbc70u,
    0x289b7ec6u, 0xeaa127fau, 0xd4ef3085u, 0x04881d05u,
    0xd9d4d039u, 0xe6db99e5u, 0x1fa27cf8u, 0xc4ac5665u,
    0xf4292244u, 0x432aff97u, 0xab9423a7u, 0xfc93a039u,
    0x655b59c3u, 0x8f0ccc92u, 0xffeff47du, 0x85845dd1u,
    0x6fa87e4fu, 0xfe2ce6e0u, 0xa3014314u, 0x4e0811a1u,
    0xf7537e82u, 0xbd3af235u, 0x2ad7d2bbu, 0xeb86d391u,
);

// Shift amounts
const S: array<u32, 64> = array<u32, 64>(
    7u, 12u, 17u, 22u, 7u, 12u, 17u, 22u, 7u, 12u, 17u, 22u, 7u, 12u, 17u, 22u,
    5u, 9u, 14u, 20u, 5u, 9u, 14u, 20u, 5u, 9u, 14u, 20u, 5u, 9u, 14u, 20u,
    4u, 11u, 16u, 23u, 4u, 11u, 16u, 23u, 4u, 11u, 16u, 23u, 4u, 11u, 16u, 23u,
    6u, 10u, 15u, 21u, 6u, 10u, 15u, 21u, 6u, 10u, 15u, 21u, 6u, 10u, 15u, 21u,
);

// Initial values
const A0: u32 = 0x67452301u;
const B0: u32 = 0xefcdab89u;
const C0: u32 = 0x98badcfeu;
const D0: u32 = 0x10325476u;

struct Params {
    input_count: u32,
    input_stride: u32,  // bytes per input (padded block size)
    _pad0: u32,
    _pad1: u32,
}

@group(0) @binding(0) var<uniform> params: Params;
@group(0) @binding(1) var<storage, read> inputs: array<u32>;
@group(0) @binding(2) var<storage, read_write> outputs: array<u32>;

fn rotl(x: u32, n: u32) -> u32 {
    return (x << n) | (x >> (32u - n));
}

fn f_func(x: u32, y: u32, z: u32) -> u32 {
    return (x & y) | (~x & z);
}

fn g_func(x: u32, y: u32, z: u32) -> u32 {
    return (x & z) | (y & ~z);
}

fn h_func(x: u32, y: u32, z: u32) -> u32 {
    return x ^ y ^ z;
}

fn i_func(x: u32, y: u32, z: u32) -> u32 {
    return y ^ (x | ~z);
}

// Process a single 512-bit (64 byte) block
fn md5_transform(state: ptr<function, array<u32, 4>>, block_offset: u32) {
    var m: array<u32, 16>;

    // Load message block (16 words, little-endian - MD5 uses LE)
    for (var i = 0u; i < 16u; i++) {
        m[i] = inputs[block_offset + i];
    }

    var a = (*state)[0];
    var b = (*state)[1];
    var c = (*state)[2];
    var d = (*state)[3];

    // Round 1 (F function)
    for (var i = 0u; i < 16u; i++) {
        let f = f_func(b, c, d);
        let g = i;
        let temp = d;
        d = c;
        c = b;
        b = b + rotl(a + f + K[i] + m[g], S[i]);
        a = temp;
    }

    // Round 2 (G function)
    for (var i = 16u; i < 32u; i++) {
        let f = g_func(b, c, d);
        let g = (5u * (i - 16u) + 1u) % 16u;
        let temp = d;
        d = c;
        c = b;
        b = b + rotl(a + f + K[i] + m[g], S[i]);
        a = temp;
    }

    // Round 3 (H function)
    for (var i = 32u; i < 48u; i++) {
        let f = h_func(b, c, d);
        let g = (3u * (i - 32u) + 5u) % 16u;
        let temp = d;
        d = c;
        c = b;
        b = b + rotl(a + f + K[i] + m[g], S[i]);
        a = temp;
    }

    // Round 4 (I function)
    for (var i = 48u; i < 64u; i++) {
        let f = i_func(b, c, d);
        let g = (7u * (i - 48u)) % 16u;
        let temp = d;
        d = c;
        c = b;
        b = b + rotl(a + f + K[i] + m[g], S[i]);
        a = temp;
    }

    (*state)[0] += a;
    (*state)[1] += b;
    (*state)[2] += c;
    (*state)[3] += d;
}

@compute @workgroup_size(256)
fn main(@builtin(global_invocation_id) global_id: vec3<u32>) {
    let idx = global_id.x;

    if idx >= params.input_count {
        return;
    }

    // Initialize hash state
    var state: array<u32, 4>;
    state[0] = A0;
    state[1] = B0;
    state[2] = C0;
    state[3] = D0;

    // Calculate input offset (in u32s)
    let input_offset = idx * (params.input_stride / 4u);

    // Process single block (assuming pre-padded 64-byte input)
    md5_transform(&state, input_offset);

    // Write output (MD5 = 16 bytes, duplicate to 32 bytes)
    let output_offset = idx * 8u;
    // First 16 bytes
    outputs[output_offset + 0u] = state[0];
    outputs[output_offset + 1u] = state[1];
    outputs[output_offset + 2u] = state[2];
    outputs[output_offset + 3u] = state[3];
    // Duplicate to fill 32 bytes
    outputs[output_offset + 4u] = state[0];
    outputs[output_offset + 5u] = state[1];
    outputs[output_offset + 6u] = state[2];
    outputs[output_offset + 7u] = state[3];
}
