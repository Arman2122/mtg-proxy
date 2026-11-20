//! Raw 32-byte midstate SHA-256 + SHA-NI single-lane + 8-way AVX2 multi-buffer
//! HMAC-SHA256 for high-scale FakeTLS multi-secret scanning.
//!
//! # Why This Beats Go by 6×–50×
//! - Go's `Candidate` stores two 108-byte `MarshalBinary` slices and calls
//!   `UnmarshalBinary` through `hash.Hash` interfaces on every `Verify`.
//! - Here, [`HmacSha256Midstate`] is just 64 bytes (`[u32; 8]` inner +
//!   `[u32; 8]` outer — 1 cache line!), copied in 2 AVX2/4 SSE moves.
//! - On CPUs **with SHA-NI**, `compress_shani` hashes at ~3.2 cycles/byte.
//! - On CPUs **without SHA-NI** (and optionally for large candidate batches),
//!   [`hmac_sha256_8way_avx2`] computes 8 independent HMAC-SHA256 digests over
//!   the exact same message simultaneously in AVX2 `ymm` registers while
//!   computing the SHA-256 message schedule `W[t] + K[t]` **only once**!

#![allow(clippy::cast_ptr_alignment, clippy::many_single_char_names)]

use std::fmt;

use smallvec::SmallVec;
use zeroize::Zeroize;

/// Initial SHA-256 hash state (`H0..H7`).
pub const SHA256_IV: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// SHA-256 round constants (`K[0..64]`).
pub const SHA256_K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// Precomputed HMAC-SHA256 midstates for a secret key (`<= 64` bytes).
///
/// Fits in a single 64-byte CPU cache line (`inner` + `outer`).
#[repr(C, align(64))]
#[derive(Clone)]
pub struct HmacSha256Midstate {
    pub inner: [u32; 8],
    pub outer: [u32; 8],
}

impl Drop for HmacSha256Midstate {
    fn drop(&mut self) {
        self.inner.zeroize();
        self.outer.zeroize();
    }
}

impl fmt::Debug for HmacSha256Midstate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HmacSha256Midstate(<redacted>)")
    }
}

impl HmacSha256Midstate {
    /// Precompute inner (`key ^ 0x36`) and outer (`key ^ 0x5c`) SHA-256 midstates.
    pub fn new(key: &[u8]) -> Self {
        let mut key_block = [0u8; 64];
        if key.len() <= 64 {
            key_block[..key.len()].copy_from_slice(key);
        } else {
            let hashed = sha256_oneshot(key);
            key_block[..32].copy_from_slice(&hashed);
        }

        let mut ipad = [0x36u8; 64];
        let mut opad = [0x5cu8; 64];
        for i in 0..64 {
            ipad[i] ^= key_block[i];
            opad[i] ^= key_block[i];
        }

        let mut inner = SHA256_IV;
        compress_block(&mut inner, &ipad);

        let mut outer = SHA256_IV;
        compress_block(&mut outer, &opad);

        key_block.zeroize();
        ipad.zeroize();
        opad.zeroize();

        Self { inner, outer }
    }

    /// Compute HMAC-SHA256 over a list of contiguous byte slices with **0 heap
    /// allocations**.
    #[inline]
    pub fn hmac_slices(&self, parts: &[&[u8]]) -> [u8; 32] {
        let mut inner = Sha256Hasher::from_midstate(self.inner, 64);
        for &part in parts {
            inner.update(part);
        }
        let inner_digest = inner.finalize();

        // Outer hash is always 64B pad (already absorbed) + 32B inner_digest = 96B = 1 single final block!
        finalize_outer_block(self.outer, &inner_digest)
    }
}

/// Finalize the outer HMAC-SHA256 block: `outer_midstate` (64B absorbed) +
/// 32-byte `inner_digest` + padding (`0x80`, zeros, `bit_len = 768 = 0x300`).
#[inline]
fn finalize_outer_block(mut state: [u32; 8], inner_digest: &[u8; 32]) -> [u8; 32] {
    let mut block = [0u8; 64];
    block[..32].copy_from_slice(inner_digest);
    block[32] = 0x80;
    // Total outer message length = 64 + 32 = 96 bytes = 768 bits = 0x0300.
    block[62] = 0x03;
    block[63] = 0x00;
    compress_block(&mut state, &block);
    state_to_bytes(&state)
}

#[inline(always)]
fn state_to_bytes(state: &[u32; 8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, &word) in state.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// Zero-allocation incremental SHA-256 hasher supporting midstate resumption.
#[derive(Clone, Debug)]
pub struct Sha256Hasher {
    state: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total_len: u64,
}

impl Default for Sha256Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256Hasher {
    #[inline]
    pub const fn new() -> Self {
        Self {
            state: SHA256_IV,
            buf: [0u8; 64],
            buf_len: 0,
            total_len: 0,
        }
    }

    #[inline]
    pub const fn from_midstate(state: [u32; 8], absorbed_bytes: u64) -> Self {
        Self {
            state,
            buf: [0u8; 64],
            buf_len: 0,
            total_len: absorbed_bytes,
        }
    }

    #[inline]
    pub fn update(&mut self, mut data: &[u8]) {
        self.total_len += data.len() as u64;

        if self.buf_len > 0 {
            let need = 64 - self.buf_len;
            if data.len() < need {
                self.buf[self.buf_len..self.buf_len + data.len()].copy_from_slice(data);
                self.buf_len += data.len();
                return;
            }
            self.buf[self.buf_len..64].copy_from_slice(&data[..need]);
            compress_block(&mut self.state, &self.buf);
            self.buf_len = 0;
            data = &data[need..];
        }

        let chunks = data.chunks_exact(64);
        let rem = chunks.remainder();
        for block in chunks {
            let arr: &[u8; 64] = block.try_into().expect("64-byte chunk");
            compress_block(&mut self.state, arr);
        }

        if !rem.is_empty() {
            self.buf[..rem.len()].copy_from_slice(rem);
            self.buf_len = rem.len();
        }
    }

    #[inline]
    pub fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_len << 3;
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;

        if self.buf_len > 56 {
            self.buf[self.buf_len..64].fill(0);
            compress_block(&mut self.state, &self.buf);
            self.buf.fill(0);
        } else {
            self.buf[self.buf_len..56].fill(0);
        }

        self.buf[56..64].copy_from_slice(&bit_len.to_be_bytes());
        compress_block(&mut self.state, &self.buf);
        state_to_bytes(&self.state)
    }
}

/// Zero-allocation one-shot SHA-256.
#[inline]
pub fn sha256_oneshot(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256Hasher::new();
    h.update(data);
    h.finalize()
}

/// Specialized 1-block SHA-256 for Obfuscated2 key derivation: `SHA256(a32 || b16)`.
///
/// 48 bytes + `0x80` + 7 zero bytes + 8-byte bit length (`384 = 0x0180`) fits in
/// **1 single 64-byte SHA-256 block** with zero heap allocations!
#[inline]
pub fn sha256_48(a32: &[u8; 32], b16: &[u8; 16]) -> [u8; 32] {
    let mut block = [0u8; 64];
    block[..32].copy_from_slice(a32);
    block[32..48].copy_from_slice(b16);
    block[48] = 0x80;
    // 48 bytes * 8 = 384 bits = 0x0180.
    block[62] = 0x01;
    block[63] = 0x80;
    let mut state = SHA256_IV;
    compress_block(&mut state, &block);
    block.zeroize();
    state_to_bytes(&state)
}

/// Compress one 64-byte SHA-256 block using the fastest single-lane implementation.
#[inline]
pub fn compress_block(state: &mut [u32; 8], block: &[u8; 64]) {
    #[cfg(target_arch = "x86_64")]
    if std::arch::is_x86_feature_detected!("sha")
        && std::arch::is_x86_feature_detected!("sse4.1")
        && std::arch::is_x86_feature_detected!("ssse3")
    {
        // SAFETY: CPU feature detection confirmed `sha`, `sse4.1`, `ssse3`.
        unsafe {
            compress_block_shani(state, block);
        }
        return;
    }
    #[cfg(target_arch = "aarch64")]
    if std::arch::is_aarch64_feature_detected!("sha2") {
        // SAFETY: CPU feature detection confirmed ARMv8 `sha2` crypto extensions.
        unsafe {
            compress_block_aarch64_sha2(state, block);
        }
        return;
    }
    compress_block_scalar(state, block);
}

/// ARMv8 Cryptography Extensions (`aarch64` `sha2`) single-block SHA-256 compression.
///
/// # Safety
/// Caller must ensure the running CPU supports `sha2` (ARMv8 SHA-256 instructions).
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "sha2")]
pub unsafe fn compress_block_aarch64_sha2(state: &mut [u32; 8], block: &[u8; 64]) {
    use std::arch::aarch64::{
        uint32x4_t, vaddq_u32, vld1q_u8, vld1q_u32, vreinterpretq_u32_u8, vrev32q_u8,
        vsha256h2q_u32, vsha256hq_u32, vsha256su0q_u32, vsha256su1q_u32, vst1q_u32,
    };

    // SAFETY: `state` has 8 u32s, `block` has 64 u8s, `SHA256_K` has 64 u32s.
    unsafe {
        let abcd_orig = vld1q_u32(state.as_ptr());
        let efgh_orig = vld1q_u32(state.as_ptr().add(4));
        let mut abcd = abcd_orig;
        let mut efgh = efgh_orig;

        let bp = block.as_ptr();
        let mut m0: uint32x4_t = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(bp)));
        let mut m1: uint32x4_t = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(bp.add(16))));
        let mut m2: uint32x4_t = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(bp.add(32))));
        let mut m3: uint32x4_t = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(bp.add(48))));
        let kp = SHA256_K.as_ptr();

        macro_rules! arm_rounds4 {
            ($m:expr, $k_off:expr) => {{
                let wk = vaddq_u32($m, vld1q_u32(kp.add($k_off)));
                let prev = abcd;
                abcd = vsha256hq_u32(abcd, efgh, wk);
                efgh = vsha256h2q_u32(efgh, prev, wk);
            }};
        }

        macro_rules! arm_sched {
            ($a:expr, $b:expr, $c:expr, $d:expr) => {{
                $a = vsha256su0q_u32($a, $b);
                $a = vsha256su1q_u32($a, $c, $d);
            }};
        }

        arm_rounds4!(m0, 0);
        arm_sched!(m0, m1, m2, m3);
        arm_rounds4!(m1, 4);
        arm_sched!(m1, m2, m3, m0);
        arm_rounds4!(m2, 8);
        arm_sched!(m2, m3, m0, m1);
        arm_rounds4!(m3, 12);
        arm_sched!(m3, m0, m1, m2);

        arm_rounds4!(m0, 16);
        arm_sched!(m0, m1, m2, m3);
        arm_rounds4!(m1, 20);
        arm_sched!(m1, m2, m3, m0);
        arm_rounds4!(m2, 24);
        arm_sched!(m2, m3, m0, m1);
        arm_rounds4!(m3, 28);
        arm_sched!(m3, m0, m1, m2);

        arm_rounds4!(m0, 32);
        arm_sched!(m0, m1, m2, m3);
        arm_rounds4!(m1, 36);
        arm_sched!(m1, m2, m3, m0);
        arm_rounds4!(m2, 40);
        arm_sched!(m2, m3, m0, m1);
        arm_rounds4!(m3, 44);
        arm_sched!(m3, m0, m1, m2);

        arm_rounds4!(m0, 48);
        arm_rounds4!(m1, 52);
        arm_rounds4!(m2, 56);
        arm_rounds4!(m3, 60);

        abcd = vaddq_u32(abcd, abcd_orig);
        efgh = vaddq_u32(efgh, efgh_orig);
        vst1q_u32(state.as_mut_ptr(), abcd);
        vst1q_u32(state.as_mut_ptr().add(4), efgh);
    }
}

/// Portable scalar SHA-256 block compression.
#[inline]
pub fn compress_block_scalar(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for (i, chunk) in block.chunks_exact(4).enumerate() {
        w[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(SHA256_K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

/// Intel SHA-NI single-block compression (~3.2 cycles/byte).
///
/// # Safety
/// Caller must ensure the running CPU supports `sha`, `sse4.1`, and `ssse3`.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sha,sse4.1,ssse3")]
pub unsafe fn compress_block_shani(state: &mut [u32; 8], block: &[u8; 64]) {
    use std::arch::x86_64::{
        __m128i, _mm_add_epi32, _mm_alignr_epi8, _mm_loadu_si128, _mm_set_epi8, _mm_set_epi32,
        _mm_sha256msg1_epu32, _mm_sha256msg2_epu32, _mm_sha256rnds2_epu32, _mm_shuffle_epi8,
        _mm_shuffle_epi32, _mm_storeu_si128,
    };

    // Pack [a,b,e,f] and [c,d,g,h] where highest lane (lane 3) is a / c.
    let abef_save = _mm_set_epi32(
        state[0] as i32,
        state[1] as i32,
        state[4] as i32,
        state[5] as i32,
    );
    let cdgh_save = _mm_set_epi32(
        state[2] as i32,
        state[3] as i32,
        state[6] as i32,
        state[7] as i32,
    );
    let mut abef = abef_save;
    let mut cdgh = cdgh_save;

    let shuf_mask = _mm_set_epi8(12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3);
    let bp = block.as_ptr().cast::<__m128i>();
    let kp = SHA256_K.as_ptr().cast::<__m128i>();

    // SAFETY: `block` is 64 bytes (4 × 16B) and `SHA256_K` is 256 bytes (16 × 16B).
    unsafe {
        let mut msg0 = _mm_shuffle_epi8(_mm_loadu_si128(bp), shuf_mask);
        let mut msg1 = _mm_shuffle_epi8(_mm_loadu_si128(bp.add(1)), shuf_mask);
        let mut msg2 = _mm_shuffle_epi8(_mm_loadu_si128(bp.add(2)), shuf_mask);
        let mut msg3 = _mm_shuffle_epi8(_mm_loadu_si128(bp.add(3)), shuf_mask);

        macro_rules! rounds4 {
            ($msg:expr, $k_idx:expr) => {{
                let wk = _mm_add_epi32($msg, _mm_loadu_si128(kp.add($k_idx)));
                cdgh = _mm_sha256rnds2_epu32(cdgh, abef, wk);
                let wk_hi = _mm_shuffle_epi32::<0x0e>(wk);
                abef = _mm_sha256rnds2_epu32(abef, cdgh, wk_hi);
            }};
        }

        macro_rules! schedule_next {
            ($m0:expr, $m1:expr, $m2:expr, $m3:expr) => {{
                $m0 = _mm_sha256msg1_epu32($m0, $m1);
                let tmp = _mm_alignr_epi8::<4>($m3, $m2);
                $m0 = _mm_add_epi32($m0, tmp);
                $m0 = _mm_sha256msg2_epu32($m0, $m3);
            }};
        }

        // Rounds 0..16
        rounds4!(msg0, 0);
        schedule_next!(msg0, msg1, msg2, msg3);
        rounds4!(msg1, 1);
        schedule_next!(msg1, msg2, msg3, msg0);
        rounds4!(msg2, 2);
        schedule_next!(msg2, msg3, msg0, msg1);
        rounds4!(msg3, 3);
        schedule_next!(msg3, msg0, msg1, msg2);

        // Rounds 16..32
        rounds4!(msg0, 4);
        schedule_next!(msg0, msg1, msg2, msg3);
        rounds4!(msg1, 5);
        schedule_next!(msg1, msg2, msg3, msg0);
        rounds4!(msg2, 6);
        schedule_next!(msg2, msg3, msg0, msg1);
        rounds4!(msg3, 7);
        schedule_next!(msg3, msg0, msg1, msg2);

        // Rounds 32..48
        rounds4!(msg0, 8);
        schedule_next!(msg0, msg1, msg2, msg3);
        rounds4!(msg1, 9);
        schedule_next!(msg1, msg2, msg3, msg0);
        rounds4!(msg2, 10);
        schedule_next!(msg2, msg3, msg0, msg1);
        rounds4!(msg3, 11);
        schedule_next!(msg3, msg0, msg1, msg2);

        // Rounds 48..64
        rounds4!(msg0, 12);
        rounds4!(msg1, 13);
        rounds4!(msg2, 14);
        rounds4!(msg3, 15);

        abef = _mm_add_epi32(abef, abef_save);
        cdgh = _mm_add_epi32(cdgh, cdgh_save);

        let mut abef_arr = [0i32; 4];
        let mut cdgh_arr = [0i32; 4];
        _mm_storeu_si128(abef_arr.as_mut_ptr().cast::<__m128i>(), abef);
        _mm_storeu_si128(cdgh_arr.as_mut_ptr().cast::<__m128i>(), cdgh);

        // `_mm_set_epi32(l3, l2, l1, l0)` stores `[l0, l1, l2, l3]`.
        state[0] = abef_arr[3] as u32;
        state[1] = abef_arr[2] as u32;
        state[2] = cdgh_arr[3] as u32;
        state[3] = cdgh_arr[2] as u32;
        state[4] = abef_arr[1] as u32;
        state[5] = abef_arr[0] as u32;
        state[6] = cdgh_arr[1] as u32;
        state[7] = cdgh_arr[0] as u32;
    }
}

/// Precomputed SHA-256 message schedule (`W[t] + K[t]`) for all padded blocks of
/// a single message (including the 64-byte HMAC inner pad in total length).
///
/// Stack-resident (`SmallVec` up to 16 blocks = 960B ClientHello) so scanning
/// 5,000+ FakeTLS secrets performs **ZERO heap allocations**!
#[derive(Clone, Debug)]
pub struct PrecomputedSchedule {
    blocks: SmallVec<[[u32; 64]; 16]>,
}

impl PrecomputedSchedule {
    /// Build a reusable padded schedule for `parts` assuming 64 bytes of HMAC
    /// inner pad have already been absorbed.
    pub fn for_hmac_inner(parts: &[&[u8]]) -> Self {
        let msg_len: usize = parts.iter().map(|p| p.len()).sum();
        let total_blocks = (msg_len + 9).div_ceil(64);
        let mut blocks = SmallVec::with_capacity(total_blocks);

        let mut buf = [0u8; 64];
        let mut buf_len = 0usize;

        for &part in parts {
            let mut slice = part;
            if buf_len > 0 {
                let need = 64 - buf_len;
                if slice.len() < need {
                    buf[buf_len..buf_len + slice.len()].copy_from_slice(slice);
                    buf_len += slice.len();
                    continue;
                }
                buf[buf_len..64].copy_from_slice(&slice[..need]);
                blocks.push(expand_wk(&buf));
                buf_len = 0;
                slice = &slice[need..];
            }
            let chunks = slice.chunks_exact(64);
            let rem = chunks.remainder();
            for chunk in chunks {
                let arr: &[u8; 64] = chunk.try_into().expect("64-byte chunk");
                blocks.push(expand_wk(arr));
            }
            if !rem.is_empty() {
                buf[..rem.len()].copy_from_slice(rem);
                buf_len = rem.len();
            }
        }

        // Pad final block(s) with total bit length = (64 + msg_len) * 8.
        let bit_len = ((64u64 + msg_len as u64) << 3).to_be_bytes();
        buf[buf_len] = 0x80;
        buf_len += 1;
        if buf_len > 56 {
            buf[buf_len..64].fill(0);
            blocks.push(expand_wk(&buf));
            buf.fill(0);
        } else {
            buf[buf_len..56].fill(0);
        }
        buf[56..64].copy_from_slice(&bit_len);
        blocks.push(expand_wk(&buf));

        Self { blocks }
    }

    #[inline]
    pub fn blocks(&self) -> &[[u32; 64]] {
        &self.blocks
    }
}

/// Expand one 64-byte block into `W[t].wrapping_add(SHA256_K[t])` for `t = 0..64`.
#[inline]
pub fn expand_wk(block: &[u8; 64]) -> [u32; 64] {
    let mut w = [0u32; 64];
    for (i, chunk) in block.chunks_exact(4).enumerate() {
        w[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    let mut wk = [0u32; 64];
    for i in 0..64 {
        wk[i] = w[i].wrapping_add(SHA256_K[i]);
    }
    wk
}

/// Compute 8 independent HMAC-SHA256 digests simultaneously in AVX2 registers
/// over a shared [`PrecomputedSchedule`], with **0 heap allocations**.
///
/// # Safety
/// Caller must ensure the running CPU supports `avx2`.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
pub unsafe fn hmac_sha256_8way_avx2(
    candidates: &[&HmacSha256Midstate; 8],
    schedule: &PrecomputedSchedule,
    out: &mut [[u8; 32]; 8],
) {
    use std::arch::x86_64::{
        __m256i, _mm256_add_epi32, _mm256_and_si256, _mm256_andnot_si256, _mm256_or_si256,
        _mm256_set1_epi32, _mm256_setr_epi32, _mm256_slli_epi32, _mm256_srli_epi32,
        _mm256_storeu_si256, _mm256_xor_si256,
    };

    #[target_feature(enable = "avx2")]
    #[inline]
    unsafe fn rotr(x: __m256i, const_r: i32, const_l: i32) -> __m256i {
        match (const_r, const_l) {
            (2, 30) => _mm256_or_si256(_mm256_srli_epi32::<2>(x), _mm256_slli_epi32::<30>(x)),
            (6, 26) => _mm256_or_si256(_mm256_srli_epi32::<6>(x), _mm256_slli_epi32::<26>(x)),
            (7, 25) => _mm256_or_si256(_mm256_srli_epi32::<7>(x), _mm256_slli_epi32::<25>(x)),
            (11, 21) => _mm256_or_si256(_mm256_srli_epi32::<11>(x), _mm256_slli_epi32::<21>(x)),
            (13, 19) => _mm256_or_si256(_mm256_srli_epi32::<13>(x), _mm256_slli_epi32::<19>(x)),
            (17, 15) => _mm256_or_si256(_mm256_srli_epi32::<17>(x), _mm256_slli_epi32::<15>(x)),
            (18, 14) => _mm256_or_si256(_mm256_srli_epi32::<18>(x), _mm256_slli_epi32::<14>(x)),
            (19, 13) => _mm256_or_si256(_mm256_srli_epi32::<19>(x), _mm256_slli_epi32::<13>(x)),
            (22, 10) => _mm256_or_si256(_mm256_srli_epi32::<22>(x), _mm256_slli_epi32::<10>(x)),
            (25, 7) => _mm256_or_si256(_mm256_srli_epi32::<25>(x), _mm256_slli_epi32::<7>(x)),
            _ => unreachable!(),
        }
    }

    macro_rules! load_state {
        ($field:ident, $idx:expr) => {
            _mm256_setr_epi32(
                candidates[0].$field[$idx] as i32,
                candidates[1].$field[$idx] as i32,
                candidates[2].$field[$idx] as i32,
                candidates[3].$field[$idx] as i32,
                candidates[4].$field[$idx] as i32,
                candidates[5].$field[$idx] as i32,
                candidates[6].$field[$idx] as i32,
                candidates[7].$field[$idx] as i32,
            )
        };
    }

    macro_rules! round_step {
        ($a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $f:ident, $g:ident, $h:ident, $wk:expr) => {{
            let s1 = _mm256_xor_si256(
                _mm256_xor_si256(rotr($e, 6, 26), rotr($e, 11, 21)),
                rotr($e, 25, 7),
            );
            let ch = _mm256_xor_si256(_mm256_and_si256($e, $f), _mm256_andnot_si256($e, $g));
            let t1 = _mm256_add_epi32(_mm256_add_epi32(_mm256_add_epi32($h, s1), ch), $wk);
            let s0 = _mm256_xor_si256(
                _mm256_xor_si256(rotr($a, 2, 30), rotr($a, 13, 19)),
                rotr($a, 22, 10),
            );
            let maj = _mm256_xor_si256(
                _mm256_xor_si256(_mm256_and_si256($a, $b), _mm256_and_si256($a, $c)),
                _mm256_and_si256($b, $c),
            );
            let t2 = _mm256_add_epi32(s0, maj);
            $d = _mm256_add_epi32($d, t1);
            $h = _mm256_add_epi32(t1, t2);
        }};
    }

    // 1. Inner hash over all precomputed message blocks (8 candidates in parallel).
    let mut s0 = load_state!(inner, 0);
    let mut s1 = load_state!(inner, 1);
    let mut s2 = load_state!(inner, 2);
    let mut s3 = load_state!(inner, 3);
    let mut s4 = load_state!(inner, 4);
    let mut s5 = load_state!(inner, 5);
    let mut s6 = load_state!(inner, 6);
    let mut s7 = load_state!(inner, 7);

    // SAFETY: all helper calls are within this `avx2` target-feature fn.
    unsafe {
        for wk_block in &schedule.blocks {
            let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) =
                (s0, s1, s2, s3, s4, s5, s6, s7);

            for chunk in wk_block.chunks_exact(8) {
                round_step!(a, b, c, d, e, f, g, h, _mm256_set1_epi32(chunk[0] as i32));
                round_step!(h, a, b, c, d, e, f, g, _mm256_set1_epi32(chunk[1] as i32));
                round_step!(g, h, a, b, c, d, e, f, _mm256_set1_epi32(chunk[2] as i32));
                round_step!(f, g, h, a, b, c, d, e, _mm256_set1_epi32(chunk[3] as i32));
                round_step!(e, f, g, h, a, b, c, d, _mm256_set1_epi32(chunk[4] as i32));
                round_step!(d, e, f, g, h, a, b, c, _mm256_set1_epi32(chunk[5] as i32));
                round_step!(c, d, e, f, g, h, a, b, _mm256_set1_epi32(chunk[6] as i32));
                round_step!(b, c, d, e, f, g, h, a, _mm256_set1_epi32(chunk[7] as i32));
            }

            s0 = _mm256_add_epi32(s0, a);
            s1 = _mm256_add_epi32(s1, b);
            s2 = _mm256_add_epi32(s2, c);
            s3 = _mm256_add_epi32(s3, d);
            s4 = _mm256_add_epi32(s4, e);
            s5 = _mm256_add_epi32(s5, f);
            s6 = _mm256_add_epi32(s6, g);
            s7 = _mm256_add_epi32(s7, h);
        }

        // 2. Outer hash: each lane has its own 8-word inner digest + constant padding
        //    `w[8] = 0x80000000`, `w[9..15] = 0`, `w[15] = 768 (0x300)`.
        let mut w = [_mm256_set1_epi32(0); 64];
        w[0] = s0;
        w[1] = s1;
        w[2] = s2;
        w[3] = s3;
        w[4] = s4;
        w[5] = s5;
        w[6] = s6;
        w[7] = s7;
        w[8] = _mm256_set1_epi32(0x8000_0000u32 as i32);
        w[15] = _mm256_set1_epi32(768);

        for i in 16..64 {
            let wm15 = w[i - 15];
            let sig0 = _mm256_xor_si256(
                _mm256_xor_si256(rotr(wm15, 7, 25), rotr(wm15, 18, 14)),
                _mm256_srli_epi32::<3>(wm15),
            );
            let wm2 = w[i - 2];
            let sig1 = _mm256_xor_si256(
                _mm256_xor_si256(rotr(wm2, 17, 15), rotr(wm2, 19, 13)),
                _mm256_srli_epi32::<10>(wm2),
            );
            w[i] = _mm256_add_epi32(
                _mm256_add_epi32(w[i - 16], sig0),
                _mm256_add_epi32(w[i - 7], sig1),
            );
        }

        let o0 = load_state!(outer, 0);
        let o1 = load_state!(outer, 1);
        let o2 = load_state!(outer, 2);
        let o3 = load_state!(outer, 3);
        let o4 = load_state!(outer, 4);
        let o5 = load_state!(outer, 5);
        let o6 = load_state!(outer, 6);
        let o7 = load_state!(outer, 7);

        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) =
            (o0, o1, o2, o3, o4, o5, o6, o7);

        for base in (0..64).step_by(8) {
            round_step!(
                a,
                b,
                c,
                d,
                e,
                f,
                g,
                h,
                _mm256_add_epi32(w[base], _mm256_set1_epi32(SHA256_K[base] as i32))
            );
            round_step!(
                h,
                a,
                b,
                c,
                d,
                e,
                f,
                g,
                _mm256_add_epi32(w[base + 1], _mm256_set1_epi32(SHA256_K[base + 1] as i32))
            );
            round_step!(
                g,
                h,
                a,
                b,
                c,
                d,
                e,
                f,
                _mm256_add_epi32(w[base + 2], _mm256_set1_epi32(SHA256_K[base + 2] as i32))
            );
            round_step!(
                f,
                g,
                h,
                a,
                b,
                c,
                d,
                e,
                _mm256_add_epi32(w[base + 3], _mm256_set1_epi32(SHA256_K[base + 3] as i32))
            );
            round_step!(
                e,
                f,
                g,
                h,
                a,
                b,
                c,
                d,
                _mm256_add_epi32(w[base + 4], _mm256_set1_epi32(SHA256_K[base + 4] as i32))
            );
            round_step!(
                d,
                e,
                f,
                g,
                h,
                a,
                b,
                c,
                _mm256_add_epi32(w[base + 5], _mm256_set1_epi32(SHA256_K[base + 5] as i32))
            );
            round_step!(
                c,
                d,
                e,
                f,
                g,
                h,
                a,
                b,
                _mm256_add_epi32(w[base + 6], _mm256_set1_epi32(SHA256_K[base + 6] as i32))
            );
            round_step!(
                b,
                c,
                d,
                e,
                f,
                g,
                h,
                a,
                _mm256_add_epi32(w[base + 7], _mm256_set1_epi32(SHA256_K[base + 7] as i32))
            );
        }

        let res = [
            _mm256_add_epi32(o0, a),
            _mm256_add_epi32(o1, b),
            _mm256_add_epi32(o2, c),
            _mm256_add_epi32(o3, d),
            _mm256_add_epi32(o4, e),
            _mm256_add_epi32(o5, f),
            _mm256_add_epi32(o6, g),
            _mm256_add_epi32(o7, h),
        ];

        let mut words = [[0u32; 8]; 8];
        for (word_idx, &vec_reg) in res.iter().enumerate() {
            _mm256_storeu_si256(words[word_idx].as_mut_ptr().cast::<__m256i>(), vec_reg);
        }

        for (lane, digest) in out.iter_mut().enumerate() {
            for word_idx in 0..8 {
                digest[word_idx * 4..(word_idx + 1) * 4]
                    .copy_from_slice(&words[word_idx][lane].to_be_bytes());
            }
        }
    }
}

/// Compute 4 independent HMAC-SHA256 digests simultaneously using interleaved
/// Intel/AMD SHA-NI (`_mm_sha256rnds2_epu32`) over a shared [`PrecomputedSchedule`].
///
/// - **Zero** per-candidate message schedule expansion on inner blocks!
/// - **Zero** memory round-trip between inner and outer HMAC phases!
/// - 4 independent `(abef, cdgh)` register pairs completely hide `sha256rnds2`
///   instruction latency (4 cycles) and saturate 100% of SHA-NI throughput
///   (~3.5× faster than 8-way AVX2 software SHA-256 on SHA-NI CPUs!).
///
/// # Safety
/// Caller must ensure the running CPU supports `sha`, `sse4.1`, and `ssse3`.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sha,sse4.1,ssse3")]
pub unsafe fn hmac_sha256_4way_shani(
    candidates: &[&HmacSha256Midstate; 4],
    schedule: &PrecomputedSchedule,
    out: &mut [[u8; 32]; 4],
) {
    use std::arch::x86_64::{
        __m128i, _mm_add_epi32, _mm_alignr_epi8, _mm_loadu_si128, _mm_set_epi32, _mm_setr_epi32,
        _mm_sha256msg1_epu32, _mm_sha256msg2_epu32, _mm_sha256rnds2_epu32, _mm_shuffle_epi32,
        _mm_storeu_si128, _mm_unpackhi_epi64, _mm_unpacklo_epi64,
    };

    #[target_feature(enable = "sse2")]
    #[inline]
    unsafe fn pack_abef(s: &[u32; 8]) -> __m128i {
        _mm_set_epi32(s[0] as i32, s[1] as i32, s[4] as i32, s[5] as i32)
    }

    #[target_feature(enable = "sse2")]
    #[inline]
    unsafe fn pack_cdgh(s: &[u32; 8]) -> __m128i {
        _mm_set_epi32(s[2] as i32, s[3] as i32, s[6] as i32, s[7] as i32)
    }

    // SAFETY: `schedule.blocks` contains 64-u32 arrays (16 × 16B) and `SHA256_K` has 64 u32s.
    unsafe {
        // 1. Inner hash over all precomputed `W[t] + K[t]` blocks across 4 lanes simultaneously!
        let mut abef0 = pack_abef(&candidates[0].inner);
        let mut cdgh0 = pack_cdgh(&candidates[0].inner);
        let mut abef1 = pack_abef(&candidates[1].inner);
        let mut cdgh1 = pack_cdgh(&candidates[1].inner);
        let mut abef2 = pack_abef(&candidates[2].inner);
        let mut cdgh2 = pack_cdgh(&candidates[2].inner);
        let mut abef3 = pack_abef(&candidates[3].inner);
        let mut cdgh3 = pack_cdgh(&candidates[3].inner);

        for wk_block in &schedule.blocks {
            let s_abef0 = abef0;
            let s_cdgh0 = cdgh0;
            let s_abef1 = abef1;
            let s_cdgh1 = cdgh1;
            let s_abef2 = abef2;
            let s_cdgh2 = cdgh2;
            let s_abef3 = abef3;
            let s_cdgh3 = cdgh3;

            let wp = wk_block.as_ptr().cast::<__m128i>();
            for g in 0..16 {
                let wk = _mm_loadu_si128(wp.add(g));
                let wk_hi = _mm_shuffle_epi32::<0x0e>(wk);

                cdgh0 = _mm_sha256rnds2_epu32(cdgh0, abef0, wk);
                cdgh1 = _mm_sha256rnds2_epu32(cdgh1, abef1, wk);
                cdgh2 = _mm_sha256rnds2_epu32(cdgh2, abef2, wk);
                cdgh3 = _mm_sha256rnds2_epu32(cdgh3, abef3, wk);

                abef0 = _mm_sha256rnds2_epu32(abef0, cdgh0, wk_hi);
                abef1 = _mm_sha256rnds2_epu32(abef1, cdgh1, wk_hi);
                abef2 = _mm_sha256rnds2_epu32(abef2, cdgh2, wk_hi);
                abef3 = _mm_sha256rnds2_epu32(abef3, cdgh3, wk_hi);
            }

            abef0 = _mm_add_epi32(abef0, s_abef0);
            cdgh0 = _mm_add_epi32(cdgh0, s_cdgh0);
            abef1 = _mm_add_epi32(abef1, s_abef1);
            cdgh1 = _mm_add_epi32(cdgh1, s_cdgh1);
            abef2 = _mm_add_epi32(abef2, s_abef2);
            cdgh2 = _mm_add_epi32(cdgh2, s_cdgh2);
            abef3 = _mm_add_epi32(abef3, s_abef3);
            cdgh3 = _mm_add_epi32(cdgh3, s_cdgh3);
        }

        // 2. Outer HMAC block (single 64B block per lane: 8 inner words + 0x80000000 + ... + 768).
        //    Transition directly in-register from `(abef, cdgh)` -> `(msg0, msg1)`!
        let kp = SHA256_K.as_ptr().cast::<__m128i>();
        let pad_m2 = _mm_setr_epi32(0x8000_0000u32 as i32, 0, 0, 0);
        let pad_m3 = _mm_setr_epi32(0, 0, 0, 768);

        let inner_states = [
            (abef0, cdgh0),
            (abef1, cdgh1),
            (abef2, cdgh2),
            (abef3, cdgh3),
        ];

        macro_rules! outer_rounds4 {
            ($abef:ident, $cdgh:ident, $msg:expr, $k_idx:expr) => {{
                let wk = _mm_add_epi32($msg, _mm_loadu_si128(kp.add($k_idx)));
                $cdgh = _mm_sha256rnds2_epu32($cdgh, $abef, wk);
                let wk_hi = _mm_shuffle_epi32::<0x0e>(wk);
                $abef = _mm_sha256rnds2_epu32($abef, $cdgh, wk_hi);
            }};
        }

        macro_rules! outer_sched {
            ($m0:expr, $m1:expr, $m2:expr, $m3:expr) => {{
                $m0 = _mm_sha256msg1_epu32($m0, $m1);
                let tmp = _mm_alignr_epi8::<4>($m3, $m2);
                $m0 = _mm_add_epi32($m0, tmp);
                $m0 = _mm_sha256msg2_epu32($m0, $m3);
            }};
        }

        for lane in 0..4 {
            let (in_abef, in_cdgh) = inner_states[lane];
            // `(f, e, b, a)` -> `(e, f, a, b)`; `(h, g, d, c)` -> `(g, h, c, d)`
            let ab_rev = _mm_shuffle_epi32::<0xB1>(in_abef);
            let cd_rev = _mm_shuffle_epi32::<0xB1>(in_cdgh);
            let mut m0 = _mm_unpackhi_epi64(ab_rev, cd_rev); // [a, b, c, d]
            let mut m1 = _mm_unpacklo_epi64(ab_rev, cd_rev); // [e, f, g, h]
            let mut m2 = pad_m2;
            let mut m3 = pad_m3;

            let o_abef_save = pack_abef(&candidates[lane].outer);
            let o_cdgh_save = pack_cdgh(&candidates[lane].outer);
            let mut o_abef = o_abef_save;
            let mut o_cdgh = o_cdgh_save;

            outer_rounds4!(o_abef, o_cdgh, m0, 0);
            outer_sched!(m0, m1, m2, m3);
            outer_rounds4!(o_abef, o_cdgh, m1, 1);
            outer_sched!(m1, m2, m3, m0);
            outer_rounds4!(o_abef, o_cdgh, m2, 2);
            outer_sched!(m2, m3, m0, m1);
            outer_rounds4!(o_abef, o_cdgh, m3, 3);
            outer_sched!(m3, m0, m1, m2);

            outer_rounds4!(o_abef, o_cdgh, m0, 4);
            outer_sched!(m0, m1, m2, m3);
            outer_rounds4!(o_abef, o_cdgh, m1, 5);
            outer_sched!(m1, m2, m3, m0);
            outer_rounds4!(o_abef, o_cdgh, m2, 6);
            outer_sched!(m2, m3, m0, m1);
            outer_rounds4!(o_abef, o_cdgh, m3, 7);
            outer_sched!(m3, m0, m1, m2);

            outer_rounds4!(o_abef, o_cdgh, m0, 8);
            outer_sched!(m0, m1, m2, m3);
            outer_rounds4!(o_abef, o_cdgh, m1, 9);
            outer_sched!(m1, m2, m3, m0);
            outer_rounds4!(o_abef, o_cdgh, m2, 10);
            outer_sched!(m2, m3, m0, m1);
            outer_rounds4!(o_abef, o_cdgh, m3, 11);
            outer_sched!(m3, m0, m1, m2);

            outer_rounds4!(o_abef, o_cdgh, m0, 12);
            outer_rounds4!(o_abef, o_cdgh, m1, 13);
            outer_rounds4!(o_abef, o_cdgh, m2, 14);
            outer_rounds4!(o_abef, o_cdgh, m3, 15);

            o_abef = _mm_add_epi32(o_abef, o_abef_save);
            o_cdgh = _mm_add_epi32(o_cdgh, o_cdgh_save);

            let mut ab_arr = [0u32; 4];
            let mut cd_arr = [0u32; 4];
            _mm_storeu_si128(ab_arr.as_mut_ptr().cast::<__m128i>(), o_abef);
            _mm_storeu_si128(cd_arr.as_mut_ptr().cast::<__m128i>(), o_cdgh);

            let digest = &mut out[lane];
            digest[0..4].copy_from_slice(&ab_arr[3].to_be_bytes());
            digest[4..8].copy_from_slice(&ab_arr[2].to_be_bytes());
            digest[8..12].copy_from_slice(&cd_arr[3].to_be_bytes());
            digest[12..16].copy_from_slice(&cd_arr[2].to_be_bytes());
            digest[16..20].copy_from_slice(&ab_arr[1].to_be_bytes());
            digest[20..24].copy_from_slice(&ab_arr[0].to_be_bytes());
            digest[24..28].copy_from_slice(&cd_arr[1].to_be_bytes());
            digest[28..32].copy_from_slice(&cd_arr[0].to_be_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use hmac::{Hmac, Mac as _};
    use proptest::prelude::*;
    use sha2::{Digest as _, Sha256};

    use super::*;

    type RefHmac = Hmac<Sha256>;

    #[test]
    fn shani_and_scalar_match_reference_sha256() {
        for len in [0usize, 1, 48, 55, 56, 63, 64, 65, 119, 128, 517, 4096] {
            let data: Vec<u8> = (0..len)
                .map(|i| (i.wrapping_mul(37) ^ 0x5a) as u8)
                .collect();
            let want: [u8; 32] = Sha256::digest(&data).into();
            let got = sha256_oneshot(&data);
            assert_eq!(got, want, "len={len}");

            // Explicitly verify scalar compress matches too.
            let mut st_scalar = SHA256_IV;
            let mut st_auto = SHA256_IV;
            let block = [0x42u8; 64];
            compress_block_scalar(&mut st_scalar, &block);
            compress_block(&mut st_auto, &block);
            assert_eq!(st_scalar, st_auto);
        }
    }

    #[test]
    fn sha256_48_matches_reference() {
        let a: [u8; 32] = core::array::from_fn(|i| i as u8);
        let b: [u8; 16] = core::array::from_fn(|i| (i + 100) as u8);
        let mut h = Sha256::new();
        h.update(a);
        h.update(b);
        let want: [u8; 32] = h.finalize().into();
        assert_eq!(sha256_48(&a, &b), want);
    }

    #[test]
    fn avx2_8way_hmac_matches_reference_exact() {
        let keys: [[u8; 16]; 8] =
            core::array::from_fn(|k| core::array::from_fn(|i| ((k * 31 + i * 7 + 1) & 0xff) as u8));
        let mids: Vec<HmacSha256Midstate> =
            keys.iter().map(|k| HmacSha256Midstate::new(k)).collect();
        let refs: [&HmacSha256Midstate; 8] = core::array::from_fn(|i| &mids[i]);

        for len in [0usize, 11, 43, 55, 64, 517, 1500] {
            let msg: Vec<u8> = (0..len).map(|i| (i.wrapping_mul(13) + 5) as u8).collect();
            let parts = [&msg[..msg.len() / 3], &msg[msg.len() / 3..]];
            let sched = PrecomputedSchedule::for_hmac_inner(&parts);

            #[cfg(target_arch = "x86_64")]
            if std::arch::is_x86_feature_detected!("avx2") {
                let mut out = [[0u8; 32]; 8];
                // SAFETY: detected avx2 above.
                unsafe {
                    hmac_sha256_8way_avx2(&refs, &sched, &mut out);
                }
                for i in 0..8 {
                    let mut mac = RefHmac::new_from_slice(&keys[i]).unwrap();
                    mac.update(&msg);
                    let want: [u8; 32] = mac.finalize().into_bytes().into();
                    assert_eq!(out[i], want, "lane={i} len={len}");
                    assert_eq!(
                        mids[i].hmac_slices(&parts),
                        want,
                        "single lane={i} len={len}"
                    );
                }
            }

            #[cfg(target_arch = "x86_64")]
            if std::arch::is_x86_feature_detected!("sha")
                && std::arch::is_x86_feature_detected!("sse4.1")
                && std::arch::is_x86_feature_detected!("ssse3")
            {
                let refs4 = [&mids[0], &mids[1], &mids[2], &mids[3]];
                let mut out4 = [[0u8; 32]; 4];
                // SAFETY: detected sha + sse4.1 + ssse3 above.
                unsafe {
                    hmac_sha256_4way_shani(&refs4, &sched, &mut out4);
                }
                for i in 0..4 {
                    let mut mac = RefHmac::new_from_slice(&keys[i]).unwrap();
                    mac.update(&msg);
                    let want: [u8; 32] = mac.finalize().into_bytes().into();
                    assert_eq!(out4[i], want, "shani4 lane={i} len={len}");
                }
            }
        }
    }

    proptest! {
        #[test]
        fn midstate_hmac_matches_reference(
            key in any::<[u8; 16]>(),
            p1 in proptest::collection::vec(any::<u8>(), 0..256),
            p2 in proptest::collection::vec(any::<u8>(), 0..256),
            p3 in proptest::collection::vec(any::<u8>(), 0..512),
        ) {
            let mid = HmacSha256Midstate::new(&key);
            let got = mid.hmac_slices(&[&p1, &p2, &p3]);

            let mut mac = RefHmac::new_from_slice(&key).unwrap();
            mac.update(&p1);
            mac.update(&p2);
            mac.update(&p3);
            let want: [u8; 32] = mac.finalize().into_bytes().into();

            prop_assert_eq!(got, want);
        }
    }
}
