// SHA256 hash compute shader
//
// Computes SHA256 hashes for batches of pre-padded input blocks.
// Each thread processes one input message.

// SHA256 round constants
const K: array<u32, 64> = array<u32, 64>(
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
);

// Initial hash values
const H0: u32 = 0x6a09e667u;
const H1: u32 = 0xbb67ae85u;
const H2: u32 = 0x3c6ef372u;
const H3: u32 = 0xa54ff53au;
const H4: u32 = 0x510e527fu;
const H5: u32 = 0x9b05688cu;
const H6: u32 = 0x1f83d9abu;
const H7: u32 = 0x5be0cd19u;

struct Params {
    input_count: u32,
    input_stride: u32,  // bytes per input (padded block size)
    _pad0: u32,
    _pad1: u32,
}

@group(0) @binding(0) var<uniform> params: Params;
@group(0) @binding(1) var<storage, read> inputs: array<u32>;
@group(0) @binding(2) var<storage, read_write> outputs: array<u32>;

fn rotr(x: u32, n: u32) -> u32 {
    return (x >> n) | (x << (32u - n));
}

// Reverse byte order (for big-endian <-> little-endian conversion)
fn reverse_bytes(x: u32) -> u32 {
    return ((x & 0x000000ffu) << 24u) |
           ((x & 0x0000ff00u) << 8u) |
           ((x & 0x00ff0000u) >> 8u) |
           ((x & 0xff000000u) >> 24u);
}

fn ch(x: u32, y: u32, z: u32) -> u32 {
    return (x & y) ^ (~x & z);
}

fn maj(x: u32, y: u32, z: u32) -> u32 {
    return (x & y) ^ (x & z) ^ (y & z);
}

fn sigma0(x: u32) -> u32 {
    return rotr(x, 2u) ^ rotr(x, 13u) ^ rotr(x, 22u);
}

fn sigma1(x: u32) -> u32 {
    return rotr(x, 6u) ^ rotr(x, 11u) ^ rotr(x, 25u);
}

fn gamma0(x: u32) -> u32 {
    return rotr(x, 7u) ^ rotr(x, 18u) ^ (x >> 3u);
}

fn gamma1(x: u32) -> u32 {
    return rotr(x, 17u) ^ rotr(x, 19u) ^ (x >> 10u);
}

// Process a single 512-bit (64 byte) block
fn sha256_transform(state: ptr<function, array<u32, 8>>, block_offset: u32) {
    var w: array<u32, 64>;

    // Load message block and convert from little-endian (native) to big-endian (SHA256 spec)
    for (var i = 0u; i < 16u; i++) {
        w[i] = reverse_bytes(inputs[block_offset + i]);
    }

    // Extend to 64 words
    for (var i = 16u; i < 64u; i++) {
        w[i] = gamma1(w[i - 2u]) + w[i - 7u] + gamma0(w[i - 15u]) + w[i - 16u];
    }

    // Working variables
    var a = (*state)[0];
    var b = (*state)[1];
    var c = (*state)[2];
    var d = (*state)[3];
    var e = (*state)[4];
    var f = (*state)[5];
    var g = (*state)[6];
    var h = (*state)[7];

    // Compression function
    for (var i = 0u; i < 64u; i++) {
        let t1 = h + sigma1(e) + ch(e, f, g) + K[i] + w[i];
        let t2 = sigma0(a) + maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    // Update state
    (*state)[0] += a;
    (*state)[1] += b;
    (*state)[2] += c;
    (*state)[3] += d;
    (*state)[4] += e;
    (*state)[5] += f;
    (*state)[6] += g;
    (*state)[7] += h;
}

@compute @workgroup_size(256)
fn main(@builtin(global_invocation_id) global_id: vec3<u32>) {
    let idx = global_id.x;

    if idx >= params.input_count {
        return;
    }

    // Initialize hash state
    var state: array<u32, 8>;
    state[0] = H0;
    state[1] = H1;
    state[2] = H2;
    state[3] = H3;
    state[4] = H4;
    state[5] = H5;
    state[6] = H6;
    state[7] = H7;

    // Calculate input offset (in u32s)
    let input_offset = idx * (params.input_stride / 4u);

    // Process single block (assuming pre-padded 64-byte input)
    sha256_transform(&state, input_offset);

    // Write output (8 u32s = 32 bytes), converting from big-endian to little-endian (native)
    let output_offset = idx * 8u;
    for (var i = 0u; i < 8u; i++) {
        outputs[output_offset + i] = reverse_bytes(state[i]);
    }
}
