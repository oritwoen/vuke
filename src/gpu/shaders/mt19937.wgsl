// MT19937 Mersenne Twister PRNG brute-force shader
//
// Tests seeds from a range to find one that produces a target 32-byte key.
// Uses atomic operations for early termination when match is found.
//
// Optimized version:
// - Workgroup size 256 for better GPU utilization
// - Vec4 comparison for SIMD-style matching

// MT19937 constants
const N: u32 = 624u;
const M: u32 = 397u;
const MATRIX_A: u32 = 0x9908b0dfu;
const UPPER_MASK: u32 = 0x80000000u;
const LOWER_MASK: u32 = 0x7fffffffu;

// Tempering constants
const TEMPERING_MASK_B: u32 = 0x9d2c5680u;
const TEMPERING_MASK_C: u32 = 0xefc60000u;

// Input: range of seeds to test
struct Params {
    seed_start: u32,
    seed_count: u32,
    _pad0: u32,
    _pad1: u32,
}

@group(0) @binding(0) var<uniform> params: Params;
@group(0) @binding(1) var<storage, read> target_key: array<u32, 8>;
@group(0) @binding(2) var<storage, read_write> result: atomic<u32>;
@group(0) @binding(3) var<storage, read_write> found_flag: atomic<u32>;

// MT19937 state - stored in private memory per thread
// Note: This is large (2496 bytes) and limits occupancy
var<private> mt: array<u32, 624>;
var<private> mti: u32;

fn mt_seed(seed: u32) {
    mt[0] = seed;
    for (var i = 1u; i < N; i++) {
        mt[i] = 1812433253u * (mt[i - 1u] ^ (mt[i - 1u] >> 30u)) + i;
    }
    mti = N;
}

fn mt_twist() {
    for (var i = 0u; i < N - M; i++) {
        let y = (mt[i] & UPPER_MASK) | (mt[i + 1u] & LOWER_MASK);
        mt[i] = mt[i + M] ^ (y >> 1u) ^ select(0u, MATRIX_A, (y & 1u) != 0u);
    }
    for (var i = N - M; i < N - 1u; i++) {
        let y = (mt[i] & UPPER_MASK) | (mt[i + 1u] & LOWER_MASK);
        mt[i] = mt[i + M - N] ^ (y >> 1u) ^ select(0u, MATRIX_A, (y & 1u) != 0u);
    }
    let y = (mt[N - 1u] & UPPER_MASK) | (mt[0] & LOWER_MASK);
    mt[N - 1u] = mt[M - 1u] ^ (y >> 1u) ^ select(0u, MATRIX_A, (y & 1u) != 0u);
    mti = 0u;
}

fn mt_next() -> u32 {
    if mti >= N {
        mt_twist();
    }

    var y = mt[mti];
    mti++;

    // Tempering
    y ^= y >> 11u;
    y ^= (y << 7u) & TEMPERING_MASK_B;
    y ^= (y << 15u) & TEMPERING_MASK_C;
    y ^= y >> 18u;

    return y;
}

@compute @workgroup_size(128)
fn main(@builtin(global_invocation_id) global_id: vec3<u32>) {
    let idx = global_id.x;

    // Early exit if already found (check before heavy computation)
    if atomicLoad(&found_flag) != 0u {
        return;
    }

    // Check bounds
    if idx >= params.seed_count {
        return;
    }

    let seed = params.seed_start + idx;

    // Initialize MT19937 with this seed
    mt_seed(seed);

    // Generate 8 u32s (32 bytes) and compare using vec4 for SIMD-style matching
    let k0 = mt_next();
    let k1 = mt_next();
    let k2 = mt_next();
    let k3 = mt_next();
    let k4 = mt_next();
    let k5 = mt_next();
    let k6 = mt_next();
    let k7 = mt_next();

    // Vec4 comparison - 2 comparisons instead of 8
    let key_lo = vec4<u32>(k0, k1, k2, k3);
    let key_hi = vec4<u32>(k4, k5, k6, k7);
    let target_lo = vec4<u32>(target_key[0], target_key[1], target_key[2], target_key[3]);
    let target_hi = vec4<u32>(target_key[4], target_key[5], target_key[6], target_key[7]);

    let matches = all(key_lo == target_lo) && all(key_hi == target_hi);

    if matches {
        // Try to be the first to set the result
        let old = atomicCompareExchangeWeak(&found_flag, 0u, 1u);
        if old.exchanged {
            atomicStore(&result, seed);
        }
    }
}
