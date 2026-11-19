//! Hardware-accelerated enc-only AES-256-CTR and fused bidirectional double-CTR.
//!
//! # Architecture
//! - Enc-only round keys: `[[u8; 16]; 15]` (240 bytes — half of a full enc+dec
//!   AES-256 schedule since CTR mode only ever invokes AES encryption).
//! - Runtime CPU dispatch:
//!   - `x86_64` `vaes + avx2`: 8-block (128-byte) parallel CTR & fused double-CTR
//!   - `x86_64` `aes + ssse3 + sse2`: 4-block (64-byte) parallel CTR & fused double-CTR
//!   - `aarch64` `aes + neon`: 4-block (64-byte) parallel CTR
//!   - Portable fallback via `aes::Aes256Enc`
//! - [`FusedCtrPair`] combines `decrypt(in_stream)` + `encrypt(out_stream)` into
//!   a single memory read/write sweep: `buf[i] ^= ks_in[i] ^ ks_out[i]`.

#![allow(clippy::cast_ptr_alignment)]

use std::fmt;

use aes::Aes256Enc;
use aes::cipher::{BlockEncrypt as _, KeyInit as _};
use zeroize::Zeroize;

/// AES block size in bytes.
pub const AES_BLOCK_SIZE: usize = 16;

/// Number of 128-bit round keys for AES-256 (Nr + 1 = 14 + 1 = 15).
pub const AES256_ROUND_KEYS: usize = 15;

/// Runtime-selected AES-256 acceleration backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AesBackend {
    #[cfg(target_arch = "x86_64")]
    VaesAvx2,
    #[cfg(target_arch = "x86_64")]
    AesNi,
    #[cfg(target_arch = "aarch64")]
    ArmAes,
    Portable,
}

/// Detect the fastest AES-256 backend supported by the running CPU.
#[inline]
pub fn detect_aes_backend() -> AesBackend {
    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("vaes")
            && std::arch::is_x86_feature_detected!("avx2")
        {
            return AesBackend::VaesAvx2;
        }
        if std::arch::is_x86_feature_detected!("aes")
            && std::arch::is_x86_feature_detected!("ssse3")
            && std::arch::is_x86_feature_detected!("sse2")
        {
            return AesBackend::AesNi;
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        if std::arch::is_aarch64_feature_detected!("aes") {
            return AesBackend::ArmAes;
        }
    }
    AesBackend::Portable
}

/// Expanded AES-256 encryption-only round keys (240 bytes, 16-byte aligned).
#[repr(C, align(16))]
#[derive(Clone)]
pub struct Aes256EncKey {
    rk: [[u8; AES_BLOCK_SIZE]; AES256_ROUND_KEYS],
}

impl Drop for Aes256EncKey {
    fn drop(&mut self) {
        self.rk.zeroize();
    }
}

impl fmt::Debug for Aes256EncKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Aes256EncKey(<redacted>)")
    }
}

impl Aes256EncKey {
    /// Expand a 32-byte AES-256 key into 15 encryption-only round keys.
    #[inline]
    pub fn new(key: &[u8; 32]) -> Self {
        #[cfg(target_arch = "x86_64")]
        if std::arch::is_x86_feature_detected!("aes") && std::arch::is_x86_feature_detected!("sse2")
        {
            // SAFETY: CPU feature detection above confirmed `aes` + `sse2`.
            return unsafe { Self::expand_aesni(key) };
        }
        Self::expand_portable(key)
    }

    /// Encrypt a single 16-byte block in place.
    #[inline]
    pub fn encrypt_block(&self, block: &mut [u8; AES_BLOCK_SIZE]) {
        #[cfg(target_arch = "x86_64")]
        if std::arch::is_x86_feature_detected!("aes") && std::arch::is_x86_feature_detected!("sse2")
        {
            // SAFETY: CPU feature detection above confirmed `aes` + `sse2`.
            unsafe {
                self.encrypt_block_aesni(block);
            }
            return;
        }
        #[cfg(target_arch = "aarch64")]
        if std::arch::is_aarch64_feature_detected!("aes") {
            // SAFETY: CPU feature detection above confirmed ARMv8 `aes`.
            unsafe {
                self.encrypt_block_arm_aes(block);
            }
            return;
        }
        self.encrypt_block_portable(block);
    }

    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "aes")]
    unsafe fn encrypt_block_arm_aes(&self, block: &mut [u8; AES_BLOCK_SIZE]) {
        use std::arch::aarch64::{vaeseq_u8, vaesmcq_u8, veorq_u8, vld1q_u8, vst1q_u8};

        // SAFETY: `block` is 16 bytes; `self.rk` has 15 × 16-byte round keys.
        unsafe {
            let mut v = vld1q_u8(block.as_ptr());
            for rk in &self.rk[..13] {
                v = vaesmcq_u8(vaeseq_u8(v, vld1q_u8(rk.as_ptr())));
            }
            v = vaeseq_u8(v, vld1q_u8(self.rk[13].as_ptr()));
            v = veorq_u8(v, vld1q_u8(self.rk[14].as_ptr()));
            vst1q_u8(block.as_mut_ptr(), v);
        }
    }

    /// Portable FIPS-197 AES-256 key expansion.
    fn expand_portable(key: &[u8; 32]) -> Self {
        const SBOX: [u8; 256] = [
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7,
            0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf,
            0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5,
            0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
            0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e,
            0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
            0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef,
            0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff,
            0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d,
            0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
            0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
            0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5,
            0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e,
            0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
            0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55,
            0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
            0xb0, 0x54, 0xbb, 0x16,
        ];
        const RCON: [u8; 7] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40];

        let mut w = [[0u8; 4]; 60];
        for (i, chunk) in key.chunks_exact(4).enumerate() {
            w[i].copy_from_slice(chunk);
        }

        for i in 8..60 {
            let mut temp = w[i - 1];
            if i % 8 == 0 {
                temp = [
                    SBOX[usize::from(temp[1])] ^ RCON[i / 8 - 1],
                    SBOX[usize::from(temp[2])],
                    SBOX[usize::from(temp[3])],
                    SBOX[usize::from(temp[0])],
                ];
            } else if i % 8 == 4 {
                temp = [
                    SBOX[usize::from(temp[0])],
                    SBOX[usize::from(temp[1])],
                    SBOX[usize::from(temp[2])],
                    SBOX[usize::from(temp[3])],
                ];
            }
            for b in 0..4 {
                w[i][b] = w[i - 8][b] ^ temp[b];
            }
        }

        let mut rk = [[0u8; AES_BLOCK_SIZE]; AES256_ROUND_KEYS];
        for r in 0..AES256_ROUND_KEYS {
            for j in 0..4 {
                rk[r][j * 4..(j + 1) * 4].copy_from_slice(&w[r * 4 + j]);
            }
        }
        Self { rk }
    }

    fn encrypt_block_portable(&self, block: &mut [u8; AES_BLOCK_SIZE]) {
        // Reconstruct original 32-byte key from rk[0] || rk[1] (always exact).
        let mut raw_key = [0u8; 32];
        raw_key[..16].copy_from_slice(&self.rk[0]);
        raw_key[16..].copy_from_slice(&self.rk[1]);
        let cipher = Aes256Enc::new_from_slice(&raw_key).expect("32-byte key");
        raw_key.zeroize();
        let mut b = aes::Block::from(*block);
        cipher.encrypt_block(&mut b);
        block.copy_from_slice(&b);
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "aes,sse2")]
    unsafe fn expand_aesni(key: &[u8; 32]) -> Self {
        use std::arch::x86_64::{
            __m128i, _mm_aeskeygenassist_si128, _mm_loadu_si128, _mm_shuffle_epi32, _mm_slli_si128,
            _mm_storeu_si128, _mm_xor_si128,
        };

        #[target_feature(enable = "aes,sse2")]
        #[inline]
        unsafe fn assist_even(mut t1: __m128i, t2: __m128i) -> __m128i {
            let t2 = _mm_shuffle_epi32::<0xff>(t2);
            let mut tmp = _mm_slli_si128::<4>(t1);
            t1 = _mm_xor_si128(t1, tmp);
            tmp = _mm_slli_si128::<4>(tmp);
            t1 = _mm_xor_si128(t1, tmp);
            tmp = _mm_slli_si128::<4>(tmp);
            t1 = _mm_xor_si128(t1, tmp);
            _mm_xor_si128(t1, t2)
        }

        #[target_feature(enable = "aes,sse2")]
        #[inline]
        unsafe fn assist_odd(t1: __m128i, mut t3: __m128i) -> __m128i {
            let t4 = _mm_aeskeygenassist_si128::<0x00>(t1);
            let t2 = _mm_shuffle_epi32::<0xaa>(t4);
            let mut tmp = _mm_slli_si128::<4>(t3);
            t3 = _mm_xor_si128(t3, tmp);
            tmp = _mm_slli_si128::<4>(tmp);
            t3 = _mm_xor_si128(t3, tmp);
            tmp = _mm_slli_si128::<4>(tmp);
            t3 = _mm_xor_si128(t3, tmp);
            _mm_xor_si128(t3, t2)
        }

        let mut rk = [[0u8; AES_BLOCK_SIZE]; AES256_ROUND_KEYS];
        // SAFETY: `key` is 32 bytes; offsets 0 and 16 are valid 16-byte reads;
        // `rk[idx]` are 16-byte arrays; helpers require `aes,sse2` which is enabled.
        unsafe {
            let mut t1 = _mm_loadu_si128(key.as_ptr().cast::<__m128i>());
            let mut t3 = _mm_loadu_si128(key.as_ptr().add(16).cast::<__m128i>());

            macro_rules! store {
                ($idx:expr, $val:expr) => {
                    _mm_storeu_si128(rk[$idx].as_mut_ptr().cast::<__m128i>(), $val);
                };
            }

            store!(0, t1);
            store!(1, t3);

            t1 = assist_even(t1, _mm_aeskeygenassist_si128::<0x01>(t3));
            store!(2, t1);
            t3 = assist_odd(t1, t3);
            store!(3, t3);

            t1 = assist_even(t1, _mm_aeskeygenassist_si128::<0x02>(t3));
            store!(4, t1);
            t3 = assist_odd(t1, t3);
            store!(5, t3);

            t1 = assist_even(t1, _mm_aeskeygenassist_si128::<0x04>(t3));
            store!(6, t1);
            t3 = assist_odd(t1, t3);
            store!(7, t3);

            t1 = assist_even(t1, _mm_aeskeygenassist_si128::<0x08>(t3));
            store!(8, t1);
            t3 = assist_odd(t1, t3);
            store!(9, t3);

            t1 = assist_even(t1, _mm_aeskeygenassist_si128::<0x10>(t3));
            store!(10, t1);
            t3 = assist_odd(t1, t3);
            store!(11, t3);

            t1 = assist_even(t1, _mm_aeskeygenassist_si128::<0x20>(t3));
            store!(12, t1);
            t3 = assist_odd(t1, t3);
            store!(13, t3);

            t1 = assist_even(t1, _mm_aeskeygenassist_si128::<0x40>(t3));
            store!(14, t1);
        }

        Self { rk }
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "aes,sse2")]
    unsafe fn encrypt_block_aesni(&self, block: &mut [u8; AES_BLOCK_SIZE]) {
        use std::arch::x86_64::{
            __m128i, _mm_aesenc_si128, _mm_aesenclast_si128, _mm_load_si128, _mm_loadu_si128,
            _mm_storeu_si128, _mm_xor_si128,
        };

        // SAFETY: `self.rk` is 16-byte aligned and has 15 blocks; `block` is 16 bytes.
        unsafe {
            let rk_ptr = self.rk.as_ptr().cast::<__m128i>();
            let mut s = _mm_xor_si128(
                _mm_loadu_si128(block.as_ptr().cast::<__m128i>()),
                _mm_load_si128(rk_ptr),
            );
            for r in 1..14 {
                s = _mm_aesenc_si128(s, _mm_load_si128(rk_ptr.add(r)));
            }
            s = _mm_aesenclast_si128(s, _mm_load_si128(rk_ptr.add(14)));
            _mm_storeu_si128(block.as_mut_ptr().cast::<__m128i>(), s);
        }
    }
}

/// Add `delta` to a big-endian 128-bit counter block (wrapping modulo `2^128`),
/// matching Go's `crypto/cipher.NewCTR`.
#[inline]
pub fn incr_be128(ctr: &mut [u8; AES_BLOCK_SIZE], delta: u64) {
    let hi = u64::from_be_bytes([
        ctr[0], ctr[1], ctr[2], ctr[3], ctr[4], ctr[5], ctr[6], ctr[7],
    ]);
    let lo = u64::from_be_bytes([
        ctr[8], ctr[9], ctr[10], ctr[11], ctr[12], ctr[13], ctr[14], ctr[15],
    ]);
    let (new_lo, carry) = lo.overflowing_add(delta);
    let new_hi = hi.wrapping_add(u64::from(carry));
    ctr[..8].copy_from_slice(&new_hi.to_be_bytes());
    ctr[8..].copy_from_slice(&new_lo.to_be_bytes());
}

/// Big-endian 128-bit AES-256-CTR stream cipher (~288 bytes).
#[repr(C, align(16))]
#[derive(Clone)]
pub struct Aes256Ctr {
    key: Aes256EncKey,
    ctr: [u8; AES_BLOCK_SIZE],
    leftover: [u8; AES_BLOCK_SIZE],
    /// Number of valid unconsumed keystream bytes at the tail of `leftover`
    /// (`leftover[16 - rem .. 16]`).
    rem: u8,
}

impl Drop for Aes256Ctr {
    fn drop(&mut self) {
        self.ctr.zeroize();
        self.leftover.zeroize();
        self.rem = 0;
    }
}

impl fmt::Debug for Aes256Ctr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Aes256Ctr")
            .field("rem", &self.rem)
            .finish_non_exhaustive()
    }
}

impl Aes256Ctr {
    /// Construct a new AES-256-CTR stream from a raw 32-byte key and 16-byte IV.
    #[inline]
    pub fn new(key: &[u8; 32], iv: &[u8; AES_BLOCK_SIZE]) -> Self {
        Self::from_expanded(Aes256EncKey::new(key), *iv)
    }

    /// Construct from an already-expanded [`Aes256EncKey`] and starting counter block.
    #[inline]
    pub const fn from_expanded(key: Aes256EncKey, iv: [u8; AES_BLOCK_SIZE]) -> Self {
        Self {
            key,
            ctr: iv,
            leftover: [0u8; AES_BLOCK_SIZE],
            rem: 0,
        }
    }

    /// XOR `data` in place with the AES-256-CTR keystream.
    #[inline]
    pub fn apply_keystream(&mut self, mut data: &mut [u8]) {
        if data.is_empty() {
            return;
        }

        // 1. Drain any buffered tail keystream from a previous unaligned call.
        if self.rem > 0 {
            let rem = usize::from(self.rem);
            let start = AES_BLOCK_SIZE - rem;
            let take = rem.min(data.len());
            for (dst, &ks) in data[..take]
                .iter_mut()
                .zip(&self.leftover[start..start + take])
            {
                *dst ^= ks;
            }
            self.rem -= take as u8;
            data = &mut data[take..];
            if data.is_empty() {
                return;
            }
        }

        // 2. Process full 16-byte blocks via fastest available SIMD kernel.
        let full_bytes = data.len() & !15;
        if full_bytes > 0 {
            let (full, tail) = data.split_at_mut(full_bytes);
            self.xor_full_blocks(full);
            data = tail;
        }

        // 3. Generate one final block if trailing < 16 bytes remain.
        if !data.is_empty() {
            let n = data.len();
            let mut ks = self.ctr;
            incr_be128(&mut self.ctr, 1);
            self.key.encrypt_block(&mut ks);
            for (dst, &k) in data.iter_mut().zip(&ks[..n]) {
                *dst ^= k;
            }
            let leftover_len = AES_BLOCK_SIZE - n;
            self.leftover[n..].copy_from_slice(&ks[n..]);
            self.rem = leftover_len as u8;
        }
    }

    #[inline]
    fn xor_full_blocks(&mut self, buf: &mut [u8]) {
        #[cfg(target_arch = "x86_64")]
        {
            if buf.len() >= 128
                && std::arch::is_x86_feature_detected!("vaes")
                && std::arch::is_x86_feature_detected!("avx2")
            {
                // SAFETY: runtime feature detection verified `vaes` + `avx2`.
                unsafe {
                    self.xor_blocks_vaes(buf);
                }
                return;
            }
            if std::arch::is_x86_feature_detected!("aes")
                && std::arch::is_x86_feature_detected!("ssse3")
                && std::arch::is_x86_feature_detected!("sse2")
            {
                // SAFETY: runtime feature detection verified `aes` + `ssse3` + `sse2`.
                unsafe {
                    self.xor_blocks_aesni(buf);
                }
                return;
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            if std::arch::is_aarch64_feature_detected!("aes") {
                // SAFETY: runtime feature detection verified ARMv8 `aes`.
                unsafe {
                    self.xor_blocks_arm_aes(buf);
                }
                return;
            }
        }
        self.xor_blocks_portable(buf);
    }

    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "aes")]
    unsafe fn xor_blocks_arm_aes(&mut self, buf: &mut [u8]) {
        use std::arch::aarch64::{uint8x16_t, vaeseq_u8, vaesmcq_u8, veorq_u8, vld1q_u8, vst1q_u8};

        // SAFETY: `self.key.rk` holds 15 × 16B round keys.
        let rk: [uint8x16_t; AES256_ROUND_KEYS] = unsafe {
            let mut k = [vld1q_u8(self.key.rk[0].as_ptr()); AES256_ROUND_KEYS];
            for r in 1..AES256_ROUND_KEYS {
                k[r] = vld1q_u8(self.key.rk[r].as_ptr());
            }
            k
        };

        let mut offset = 0usize;
        while offset + 64 <= buf.len() {
            let mut ctrs = [[0u8; AES_BLOCK_SIZE]; 4];
            for slot in &mut ctrs {
                *slot = self.ctr;
                incr_be128(&mut self.ctr, 1);
            }
            // SAFETY: `ctrs` is 64B and `offset + 64 <= buf.len()`.
            unsafe {
                let mut b0 = vld1q_u8(ctrs[0].as_ptr());
                let mut b1 = vld1q_u8(ctrs[1].as_ptr());
                let mut b2 = vld1q_u8(ctrs[2].as_ptr());
                let mut b3 = vld1q_u8(ctrs[3].as_ptr());
                for &k in &rk[..13] {
                    b0 = vaesmcq_u8(vaeseq_u8(b0, k));
                    b1 = vaesmcq_u8(vaeseq_u8(b1, k));
                    b2 = vaesmcq_u8(vaeseq_u8(b2, k));
                    b3 = vaesmcq_u8(vaeseq_u8(b3, k));
                }
                b0 = veorq_u8(vaeseq_u8(b0, rk[13]), rk[14]);
                b1 = veorq_u8(vaeseq_u8(b1, rk[13]), rk[14]);
                b2 = veorq_u8(vaeseq_u8(b2, rk[13]), rk[14]);
                b3 = veorq_u8(vaeseq_u8(b3, rk[13]), rk[14]);

                let p = buf.as_mut_ptr().add(offset);
                vst1q_u8(p, veorq_u8(vld1q_u8(p), b0));
                vst1q_u8(p.add(16), veorq_u8(vld1q_u8(p.add(16)), b1));
                vst1q_u8(p.add(32), veorq_u8(vld1q_u8(p.add(32)), b2));
                vst1q_u8(p.add(48), veorq_u8(vld1q_u8(p.add(48)), b3));
            }
            offset += 64;
        }
        while offset + 16 <= buf.len() {
            let c = self.ctr;
            incr_be128(&mut self.ctr, 1);
            // SAFETY: `offset + 16 <= buf.len()`.
            unsafe {
                let mut b0 = vld1q_u8(c.as_ptr());
                for &k in &rk[..13] {
                    b0 = vaesmcq_u8(vaeseq_u8(b0, k));
                }
                b0 = veorq_u8(vaeseq_u8(b0, rk[13]), rk[14]);
                let p = buf.as_mut_ptr().add(offset);
                vst1q_u8(p, veorq_u8(vld1q_u8(p), b0));
            }
            offset += 16;
        }
    }

    fn xor_blocks_portable(&mut self, buf: &mut [u8]) {
        let mut raw_key = [0u8; 32];
        raw_key[..16].copy_from_slice(&self.key.rk[0]);
        raw_key[16..].copy_from_slice(&self.key.rk[1]);
        let cipher = Aes256Enc::new_from_slice(&raw_key).expect("32-byte key");
        raw_key.zeroize();

        for chunk in buf.chunks_exact_mut(AES_BLOCK_SIZE) {
            let mut b = aes::Block::from(self.ctr);
            incr_be128(&mut self.ctr, 1);
            cipher.encrypt_block(&mut b);
            for (d, k) in chunk.iter_mut().zip(b.iter()) {
                *d ^= *k;
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "aes,ssse3,sse2")]
    unsafe fn xor_blocks_aesni(&mut self, buf: &mut [u8]) {
        use std::arch::x86_64::{
            __m128i, _mm_aesenc_si128, _mm_aesenclast_si128, _mm_load_si128, _mm_loadu_si128,
            _mm_storeu_si128, _mm_xor_si128,
        };

        // SAFETY: `self.key.rk` is 16-byte aligned with 15 round keys.
        let rk = unsafe {
            let p = self.key.rk.as_ptr().cast::<__m128i>();
            [
                _mm_load_si128(p),
                _mm_load_si128(p.add(1)),
                _mm_load_si128(p.add(2)),
                _mm_load_si128(p.add(3)),
                _mm_load_si128(p.add(4)),
                _mm_load_si128(p.add(5)),
                _mm_load_si128(p.add(6)),
                _mm_load_si128(p.add(7)),
                _mm_load_si128(p.add(8)),
                _mm_load_si128(p.add(9)),
                _mm_load_si128(p.add(10)),
                _mm_load_si128(p.add(11)),
                _mm_load_si128(p.add(12)),
                _mm_load_si128(p.add(13)),
                _mm_load_si128(p.add(14)),
            ]
        };

        let mut offset = 0usize;
        while offset + 64 <= buf.len() {
            let c0 = self.ctr;
            let mut c1 = c0;
            incr_be128(&mut c1, 1);
            let mut c2 = c0;
            incr_be128(&mut c2, 2);
            let mut c3 = c0;
            incr_be128(&mut c3, 3);
            incr_be128(&mut self.ctr, 4);

            // SAFETY: c0..c3 are 16-byte arrays, offset+64 <= buf.len().
            unsafe {
                let mut b0 = _mm_xor_si128(_mm_loadu_si128(c0.as_ptr().cast()), rk[0]);
                let mut b1 = _mm_xor_si128(_mm_loadu_si128(c1.as_ptr().cast()), rk[0]);
                let mut b2 = _mm_xor_si128(_mm_loadu_si128(c2.as_ptr().cast()), rk[0]);
                let mut b3 = _mm_xor_si128(_mm_loadu_si128(c3.as_ptr().cast()), rk[0]);

                for &k in &rk[1..14] {
                    b0 = _mm_aesenc_si128(b0, k);
                    b1 = _mm_aesenc_si128(b1, k);
                    b2 = _mm_aesenc_si128(b2, k);
                    b3 = _mm_aesenc_si128(b3, k);
                }

                b0 = _mm_aesenclast_si128(b0, rk[14]);
                b1 = _mm_aesenclast_si128(b1, rk[14]);
                b2 = _mm_aesenclast_si128(b2, rk[14]);
                b3 = _mm_aesenclast_si128(b3, rk[14]);

                let p = buf.as_mut_ptr().add(offset);
                let d0 = _mm_loadu_si128(p.cast());
                let d1 = _mm_loadu_si128(p.add(16).cast());
                let d2 = _mm_loadu_si128(p.add(32).cast());
                let d3 = _mm_loadu_si128(p.add(48).cast());

                _mm_storeu_si128(p.cast(), _mm_xor_si128(d0, b0));
                _mm_storeu_si128(p.add(16).cast(), _mm_xor_si128(d1, b1));
                _mm_storeu_si128(p.add(32).cast(), _mm_xor_si128(d2, b2));
                _mm_storeu_si128(p.add(48).cast(), _mm_xor_si128(d3, b3));
            }
            offset += 64;
        }

        while offset + 16 <= buf.len() {
            let c0 = self.ctr;
            incr_be128(&mut self.ctr, 1);
            // SAFETY: c0 is 16 bytes, offset+16 <= buf.len().
            unsafe {
                let mut b0 = _mm_xor_si128(_mm_loadu_si128(c0.as_ptr().cast()), rk[0]);
                for &k in &rk[1..14] {
                    b0 = _mm_aesenc_si128(b0, k);
                }
                b0 = _mm_aesenclast_si128(b0, rk[14]);
                let p = buf.as_mut_ptr().add(offset);
                let d0 = _mm_loadu_si128(p.cast());
                _mm_storeu_si128(p.cast(), _mm_xor_si128(d0, b0));
            }
            offset += 16;
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "vaes,avx2")]
    unsafe fn xor_blocks_vaes(&mut self, buf: &mut [u8]) {
        use std::arch::x86_64::{
            __m128i, __m256i, _mm_load_si128, _mm256_aesenc_epi128, _mm256_aesenclast_epi128,
            _mm256_broadcastsi128_si256, _mm256_loadu_si256, _mm256_storeu_si256, _mm256_xor_si256,
        };

        // SAFETY: `self.key.rk` is 16-byte aligned with 15 round keys.
        let rk = unsafe {
            let p = self.key.rk.as_ptr().cast::<__m128i>();
            let mut out = [_mm256_broadcastsi128_si256(_mm_load_si128(p)); AES256_ROUND_KEYS];
            for (r, slot) in out.iter_mut().enumerate().skip(1) {
                *slot = _mm256_broadcastsi128_si256(_mm_load_si128(p.add(r)));
            }
            out
        };

        let mut offset = 0usize;
        let mut ctrs = [[0u8; AES_BLOCK_SIZE]; 8];
        while offset + 128 <= buf.len() {
            fill_8_counters(&mut self.ctr, &mut ctrs);

            // SAFETY: `ctrs` is 128 contiguous bytes and `offset + 128 <= buf.len()`.
            unsafe {
                let cp = ctrs.as_ptr().cast::<__m256i>();
                let mut b0 = _mm256_xor_si256(_mm256_loadu_si256(cp), rk[0]);
                let mut b1 = _mm256_xor_si256(_mm256_loadu_si256(cp.add(1)), rk[0]);
                let mut b2 = _mm256_xor_si256(_mm256_loadu_si256(cp.add(2)), rk[0]);
                let mut b3 = _mm256_xor_si256(_mm256_loadu_si256(cp.add(3)), rk[0]);

                for &k in &rk[1..14] {
                    b0 = _mm256_aesenc_epi128(b0, k);
                    b1 = _mm256_aesenc_epi128(b1, k);
                    b2 = _mm256_aesenc_epi128(b2, k);
                    b3 = _mm256_aesenc_epi128(b3, k);
                }

                b0 = _mm256_aesenclast_epi128(b0, rk[14]);
                b1 = _mm256_aesenclast_epi128(b1, rk[14]);
                b2 = _mm256_aesenclast_epi128(b2, rk[14]);
                b3 = _mm256_aesenclast_epi128(b3, rk[14]);

                let dp = buf.as_mut_ptr().add(offset).cast::<__m256i>();
                let d0 = _mm256_loadu_si256(dp);
                let d1 = _mm256_loadu_si256(dp.add(1));
                let d2 = _mm256_loadu_si256(dp.add(2));
                let d3 = _mm256_loadu_si256(dp.add(3));

                _mm256_storeu_si256(dp, _mm256_xor_si256(d0, b0));
                _mm256_storeu_si256(dp.add(1), _mm256_xor_si256(d1, b1));
                _mm256_storeu_si256(dp.add(2), _mm256_xor_si256(d2, b2));
                _mm256_storeu_si256(dp.add(3), _mm256_xor_si256(d3, b3));
            }
            offset += 128;
        }

        if offset < buf.len() {
            // SAFETY: vaes+avx2 implies aes+ssse3+sse2 on x86_64.
            unsafe {
                self.xor_blocks_aesni(&mut buf[offset..]);
            }
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn fill_8_counters(ctr: &mut [u8; AES_BLOCK_SIZE], out: &mut [[u8; AES_BLOCK_SIZE]; 8]) {
    let hi = u64::from_be_bytes([
        ctr[0], ctr[1], ctr[2], ctr[3], ctr[4], ctr[5], ctr[6], ctr[7],
    ]);
    let lo = u64::from_be_bytes([
        ctr[8], ctr[9], ctr[10], ctr[11], ctr[12], ctr[13], ctr[14], ctr[15],
    ]);
    if lo <= u64::MAX - 8 {
        let hi_b = hi.to_be_bytes();
        for (i, slot) in out.iter_mut().enumerate() {
            slot[..8].copy_from_slice(&hi_b);
            slot[8..].copy_from_slice(&lo.wrapping_add(i as u64).to_be_bytes());
        }
        ctr[8..].copy_from_slice(&(lo + 8).to_be_bytes());
    } else {
        for slot in out.iter_mut() {
            *slot = *ctr;
            incr_be128(ctr, 1);
        }
    }
}

/// Fused bidirectional AES-256-CTR pair for one relay direction
/// (`decrypt(ingress) ^ encrypt(egress)` in a single memory sweep).
#[repr(C, align(16))]
#[derive(Clone, Debug)]
pub struct FusedCtrPair {
    pub in_ctr: Aes256Ctr,
    pub out_ctr: Aes256Ctr,
}

impl FusedCtrPair {
    #[inline]
    pub const fn new(in_ctr: Aes256Ctr, out_ctr: Aes256Ctr) -> Self {
        Self { in_ctr, out_ctr }
    }

    /// Apply both CTR keystreams (`in_ctr ^ out_ctr`) to `buf` in a single pass.
    ///
    /// Mathematically identical to `in_ctr.apply_keystream(buf); out_ctr.apply_keystream(buf);`
    /// for all chunk sizes and alignments, while cutting memory traffic in half
    /// on aligned bulk relay chunks.
    #[inline]
    pub fn apply_fused_in_place(&mut self, mut buf: &mut [u8]) {
        if buf.is_empty() {
            return;
        }

        // Fast aligned fused path when both streams sit cleanly on a 16-byte
        // block boundary (the 99.9%+ steady-state bulk relay case).
        if self.in_ctr.rem == 0 && self.out_ctr.rem == 0 && buf.len() >= 64 {
            let full_bytes = buf.len() & !15;
            let (full, tail) = buf.split_at_mut(full_bytes);
            self.xor_fused_full_blocks(full);
            buf = tail;
            if buf.is_empty() {
                return;
            }
        } else if self.in_ctr.rem == self.out_ctr.rem && self.in_ctr.rem > 0 {
            // Both streams have identical leftover count -> drain together in 1 pass,
            // then hit the fast fused path for the rest of `buf`!
            let rem = usize::from(self.in_ctr.rem);
            let start = AES_BLOCK_SIZE - rem;
            let take = rem.min(buf.len());
            for i in 0..take {
                buf[i] ^= self.in_ctr.leftover[start + i] ^ self.out_ctr.leftover[start + i];
            }
            self.in_ctr.rem -= take as u8;
            self.out_ctr.rem -= take as u8;
            buf = &mut buf[take..];
            if buf.is_empty() {
                return;
            }
            if self.in_ctr.rem == 0 && buf.len() >= 64 {
                let full_bytes = buf.len() & !15;
                let (full, tail) = buf.split_at_mut(full_bytes);
                self.xor_fused_full_blocks(full);
                buf = tail;
                if buf.is_empty() {
                    return;
                }
            }
        }

        // Remainder (<64B) or desynchronized sub-block offset fallback.
        self.in_ctr.apply_keystream(buf);
        self.out_ctr.apply_keystream(buf);
    }

    #[inline]
    fn xor_fused_full_blocks(&mut self, buf: &mut [u8]) {
        #[cfg(target_arch = "x86_64")]
        {
            if buf.len() >= 128
                && std::arch::is_x86_feature_detected!("vaes")
                && std::arch::is_x86_feature_detected!("avx2")
            {
                // SAFETY: runtime feature detection verified `vaes` + `avx2`.
                unsafe {
                    self.xor_fused_vaes(buf);
                }
                return;
            }
            if std::arch::is_x86_feature_detected!("aes")
                && std::arch::is_x86_feature_detected!("ssse3")
                && std::arch::is_x86_feature_detected!("sse2")
            {
                // SAFETY: runtime feature detection verified `aes` + `ssse3` + `sse2`.
                unsafe {
                    self.xor_fused_aesni(buf);
                }
                return;
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            if std::arch::is_aarch64_feature_detected!("aes") {
                // SAFETY: runtime feature detection verified ARMv8 `aes`.
                unsafe {
                    self.xor_fused_arm_aes(buf);
                }
                return;
            }
        }
        self.in_ctr.xor_blocks_portable(buf);
        self.out_ctr.xor_blocks_portable(buf);
    }

    /// ARMv8 Cryptography Extensions (`aarch64` `aes`) 4-block parallel fused double-CTR!
    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "aes")]
    unsafe fn xor_fused_arm_aes(&mut self, buf: &mut [u8]) {
        use std::arch::aarch64::{uint8x16_t, vaeseq_u8, vaesmcq_u8, veorq_u8, vld1q_u8, vst1q_u8};

        // SAFETY: `self.in_ctr.key.rk` & `self.out_ctr.key.rk` each hold 15 × 16B round keys.
        let (rk_in, rk_out): (
            [uint8x16_t; AES256_ROUND_KEYS],
            [uint8x16_t; AES256_ROUND_KEYS],
        ) = unsafe {
            let mut ki = [vld1q_u8(self.in_ctr.key.rk[0].as_ptr()); AES256_ROUND_KEYS];
            let mut ko = [vld1q_u8(self.out_ctr.key.rk[0].as_ptr()); AES256_ROUND_KEYS];
            for r in 1..AES256_ROUND_KEYS {
                ki[r] = vld1q_u8(self.in_ctr.key.rk[r].as_ptr());
                ko[r] = vld1q_u8(self.out_ctr.key.rk[r].as_ptr());
            }
            (ki, ko)
        };

        let mut offset = 0usize;
        while offset + 64 <= buf.len() {
            let mut ai = [[0u8; AES_BLOCK_SIZE]; 4];
            let mut bi = [[0u8; AES_BLOCK_SIZE]; 4];
            for i in 0..4 {
                ai[i] = self.in_ctr.ctr;
                incr_be128(&mut self.in_ctr.ctr, 1);
                bi[i] = self.out_ctr.ctr;
                incr_be128(&mut self.out_ctr.ctr, 1);
            }

            // SAFETY: `ai`/`bi` are 64 bytes; `offset + 64 <= buf.len()`.
            unsafe {
                let mut a0 = vld1q_u8(ai[0].as_ptr());
                let mut a1 = vld1q_u8(ai[1].as_ptr());
                let mut a2 = vld1q_u8(ai[2].as_ptr());
                let mut a3 = vld1q_u8(ai[3].as_ptr());

                let mut b0 = vld1q_u8(bi[0].as_ptr());
                let mut b1 = vld1q_u8(bi[1].as_ptr());
                let mut b2 = vld1q_u8(bi[2].as_ptr());
                let mut b3 = vld1q_u8(bi[3].as_ptr());

                for r in 0..13 {
                    let ki = rk_in[r];
                    let ko = rk_out[r];
                    a0 = vaesmcq_u8(vaeseq_u8(a0, ki));
                    b0 = vaesmcq_u8(vaeseq_u8(b0, ko));
                    a1 = vaesmcq_u8(vaeseq_u8(a1, ki));
                    b1 = vaesmcq_u8(vaeseq_u8(b1, ko));
                    a2 = vaesmcq_u8(vaeseq_u8(a2, ki));
                    b2 = vaesmcq_u8(vaeseq_u8(b2, ko));
                    a3 = vaesmcq_u8(vaeseq_u8(a3, ki));
                    b3 = vaesmcq_u8(vaeseq_u8(b3, ko));
                }

                a0 = veorq_u8(vaeseq_u8(a0, rk_in[13]), rk_in[14]);
                b0 = veorq_u8(vaeseq_u8(b0, rk_out[13]), rk_out[14]);
                a1 = veorq_u8(vaeseq_u8(a1, rk_in[13]), rk_in[14]);
                b1 = veorq_u8(vaeseq_u8(b1, rk_out[13]), rk_out[14]);
                a2 = veorq_u8(vaeseq_u8(a2, rk_in[13]), rk_in[14]);
                b2 = veorq_u8(vaeseq_u8(b2, rk_out[13]), rk_out[14]);
                a3 = veorq_u8(vaeseq_u8(a3, rk_in[13]), rk_in[14]);
                b3 = veorq_u8(vaeseq_u8(b3, rk_out[13]), rk_out[14]);

                let p = buf.as_mut_ptr().add(offset);
                vst1q_u8(p, veorq_u8(vld1q_u8(p), veorq_u8(a0, b0)));
                vst1q_u8(p.add(16), veorq_u8(vld1q_u8(p.add(16)), veorq_u8(a1, b1)));
                vst1q_u8(p.add(32), veorq_u8(vld1q_u8(p.add(32)), veorq_u8(a2, b2)));
                vst1q_u8(p.add(48), veorq_u8(vld1q_u8(p.add(48)), veorq_u8(a3, b3)));
            }
            offset += 64;
        }

        while offset + 16 <= buf.len() {
            let ci = self.in_ctr.ctr;
            let co = self.out_ctr.ctr;
            incr_be128(&mut self.in_ctr.ctr, 1);
            incr_be128(&mut self.out_ctr.ctr, 1);
            // SAFETY: `offset + 16 <= buf.len()`.
            unsafe {
                let mut a0 = vld1q_u8(ci.as_ptr());
                let mut b0 = vld1q_u8(co.as_ptr());
                for r in 0..13 {
                    a0 = vaesmcq_u8(vaeseq_u8(a0, rk_in[r]));
                    b0 = vaesmcq_u8(vaeseq_u8(b0, rk_out[r]));
                }
                a0 = veorq_u8(vaeseq_u8(a0, rk_in[13]), rk_in[14]);
                b0 = veorq_u8(vaeseq_u8(b0, rk_out[13]), rk_out[14]);
                let p = buf.as_mut_ptr().add(offset);
                vst1q_u8(p, veorq_u8(vld1q_u8(p), veorq_u8(a0, b0)));
            }
            offset += 16;
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "vaes,avx2")]
    unsafe fn xor_fused_vaes(&mut self, buf: &mut [u8]) {
        use std::arch::x86_64::{
            __m128i, __m256i, _mm_load_si128, _mm256_aesenc_epi128, _mm256_aesenclast_epi128,
            _mm256_broadcastsi128_si256, _mm256_loadu_si256, _mm256_storeu_si256, _mm256_xor_si256,
        };

        // SAFETY: `rk` arrays are 16-byte aligned with 15 round keys each.
        let (rk_in, rk_out) = unsafe {
            let pi = self.in_ctr.key.rk.as_ptr().cast::<__m128i>();
            let po = self.out_ctr.key.rk.as_ptr().cast::<__m128i>();
            let mut ki = [_mm256_broadcastsi128_si256(_mm_load_si128(pi)); AES256_ROUND_KEYS];
            let mut ko = [_mm256_broadcastsi128_si256(_mm_load_si128(po)); AES256_ROUND_KEYS];
            for r in 1..AES256_ROUND_KEYS {
                ki[r] = _mm256_broadcastsi128_si256(_mm_load_si128(pi.add(r)));
                ko[r] = _mm256_broadcastsi128_si256(_mm_load_si128(po.add(r)));
            }
            (ki, ko)
        };

        let mut offset = 0usize;
        let mut c_in = [[0u8; AES_BLOCK_SIZE]; 8];
        let mut c_out = [[0u8; AES_BLOCK_SIZE]; 8];

        while offset + 128 <= buf.len() {
            fill_8_counters(&mut self.in_ctr.ctr, &mut c_in);
            fill_8_counters(&mut self.out_ctr.ctr, &mut c_out);

            // SAFETY: `c_in` & `c_out` are 128 bytes each; `offset + 128 <= buf.len()`.
            unsafe {
                let ci = c_in.as_ptr().cast::<__m256i>();
                let co = c_out.as_ptr().cast::<__m256i>();

                let mut a0 = _mm256_xor_si256(_mm256_loadu_si256(ci), rk_in[0]);
                let mut a1 = _mm256_xor_si256(_mm256_loadu_si256(ci.add(1)), rk_in[0]);
                let mut a2 = _mm256_xor_si256(_mm256_loadu_si256(ci.add(2)), rk_in[0]);
                let mut a3 = _mm256_xor_si256(_mm256_loadu_si256(ci.add(3)), rk_in[0]);

                let mut b0 = _mm256_xor_si256(_mm256_loadu_si256(co), rk_out[0]);
                let mut b1 = _mm256_xor_si256(_mm256_loadu_si256(co.add(1)), rk_out[0]);
                let mut b2 = _mm256_xor_si256(_mm256_loadu_si256(co.add(2)), rk_out[0]);
                let mut b3 = _mm256_xor_si256(_mm256_loadu_si256(co.add(3)), rk_out[0]);

                for r in 1..14 {
                    let ki = rk_in[r];
                    let ko = rk_out[r];
                    a0 = _mm256_aesenc_epi128(a0, ki);
                    b0 = _mm256_aesenc_epi128(b0, ko);
                    a1 = _mm256_aesenc_epi128(a1, ki);
                    b1 = _mm256_aesenc_epi128(b1, ko);
                    a2 = _mm256_aesenc_epi128(a2, ki);
                    b2 = _mm256_aesenc_epi128(b2, ko);
                    a3 = _mm256_aesenc_epi128(a3, ki);
                    b3 = _mm256_aesenc_epi128(b3, ko);
                }

                let ki14 = rk_in[14];
                let ko14 = rk_out[14];
                a0 = _mm256_aesenclast_epi128(a0, ki14);
                b0 = _mm256_aesenclast_epi128(b0, ko14);
                a1 = _mm256_aesenclast_epi128(a1, ki14);
                b1 = _mm256_aesenclast_epi128(b1, ko14);
                a2 = _mm256_aesenclast_epi128(a2, ki14);
                b2 = _mm256_aesenclast_epi128(b2, ko14);
                a3 = _mm256_aesenclast_epi128(a3, ki14);
                b3 = _mm256_aesenclast_epi128(b3, ko14);

                let dp = buf.as_mut_ptr().add(offset).cast::<__m256i>();
                let k0 = _mm256_xor_si256(a0, b0);
                let k1 = _mm256_xor_si256(a1, b1);
                let k2 = _mm256_xor_si256(a2, b2);
                let k3 = _mm256_xor_si256(a3, b3);

                _mm256_storeu_si256(dp, _mm256_xor_si256(_mm256_loadu_si256(dp), k0));
                _mm256_storeu_si256(
                    dp.add(1),
                    _mm256_xor_si256(_mm256_loadu_si256(dp.add(1)), k1),
                );
                _mm256_storeu_si256(
                    dp.add(2),
                    _mm256_xor_si256(_mm256_loadu_si256(dp.add(2)), k2),
                );
                _mm256_storeu_si256(
                    dp.add(3),
                    _mm256_xor_si256(_mm256_loadu_si256(dp.add(3)), k3),
                );
            }
            offset += 128;
        }

        if offset < buf.len() {
            // SAFETY: vaes+avx2 implies aes+ssse3+sse2.
            unsafe {
                self.xor_fused_aesni(&mut buf[offset..]);
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "aes,ssse3,sse2")]
    unsafe fn xor_fused_aesni(&mut self, buf: &mut [u8]) {
        use std::arch::x86_64::{
            __m128i, _mm_aesenc_si128, _mm_aesenclast_si128, _mm_load_si128, _mm_loadu_si128,
            _mm_storeu_si128, _mm_xor_si128,
        };

        // SAFETY: `rk` arrays are 16-byte aligned with 15 round keys.
        let (rk_in, rk_out) = unsafe {
            let pi = self.in_ctr.key.rk.as_ptr().cast::<__m128i>();
            let po = self.out_ctr.key.rk.as_ptr().cast::<__m128i>();
            let mut ki = [_mm_load_si128(pi); AES256_ROUND_KEYS];
            let mut ko = [_mm_load_si128(po); AES256_ROUND_KEYS];
            for r in 1..AES256_ROUND_KEYS {
                ki[r] = _mm_load_si128(pi.add(r));
                ko[r] = _mm_load_si128(po.add(r));
            }
            (ki, ko)
        };

        let mut offset = 0usize;
        while offset + 64 <= buf.len() {
            let mut ai = [[0u8; AES_BLOCK_SIZE]; 4];
            let mut bi = [[0u8; AES_BLOCK_SIZE]; 4];
            for i in 0..4 {
                ai[i] = self.in_ctr.ctr;
                incr_be128(&mut self.in_ctr.ctr, 1);
                bi[i] = self.out_ctr.ctr;
                incr_be128(&mut self.out_ctr.ctr, 1);
            }

            // SAFETY: `ai` & `bi` are 64 bytes each; `offset + 64 <= buf.len()`.
            unsafe {
                let mut a0 = _mm_xor_si128(_mm_loadu_si128(ai[0].as_ptr().cast()), rk_in[0]);
                let mut a1 = _mm_xor_si128(_mm_loadu_si128(ai[1].as_ptr().cast()), rk_in[0]);
                let mut a2 = _mm_xor_si128(_mm_loadu_si128(ai[2].as_ptr().cast()), rk_in[0]);
                let mut a3 = _mm_xor_si128(_mm_loadu_si128(ai[3].as_ptr().cast()), rk_in[0]);

                let mut b0 = _mm_xor_si128(_mm_loadu_si128(bi[0].as_ptr().cast()), rk_out[0]);
                let mut b1 = _mm_xor_si128(_mm_loadu_si128(bi[1].as_ptr().cast()), rk_out[0]);
                let mut b2 = _mm_xor_si128(_mm_loadu_si128(bi[2].as_ptr().cast()), rk_out[0]);
                let mut b3 = _mm_xor_si128(_mm_loadu_si128(bi[3].as_ptr().cast()), rk_out[0]);

                for r in 1..14 {
                    let ki = rk_in[r];
                    let ko = rk_out[r];
                    a0 = _mm_aesenc_si128(a0, ki);
                    b0 = _mm_aesenc_si128(b0, ko);
                    a1 = _mm_aesenc_si128(a1, ki);
                    b1 = _mm_aesenc_si128(b1, ko);
                    a2 = _mm_aesenc_si128(a2, ki);
                    b2 = _mm_aesenc_si128(b2, ko);
                    a3 = _mm_aesenc_si128(a3, ki);
                    b3 = _mm_aesenc_si128(b3, ko);
                }

                a0 = _mm_aesenclast_si128(a0, rk_in[14]);
                b0 = _mm_aesenclast_si128(b0, rk_out[14]);
                a1 = _mm_aesenclast_si128(a1, rk_in[14]);
                b1 = _mm_aesenclast_si128(b1, rk_out[14]);
                a2 = _mm_aesenclast_si128(a2, rk_in[14]);
                b2 = _mm_aesenclast_si128(b2, rk_out[14]);
                a3 = _mm_aesenclast_si128(a3, rk_in[14]);
                b3 = _mm_aesenclast_si128(b3, rk_out[14]);

                let p = buf.as_mut_ptr().add(offset);
                let k0 = _mm_xor_si128(a0, b0);
                let k1 = _mm_xor_si128(a1, b1);
                let k2 = _mm_xor_si128(a2, b2);
                let k3 = _mm_xor_si128(a3, b3);

                _mm_storeu_si128(p.cast(), _mm_xor_si128(_mm_loadu_si128(p.cast()), k0));
                _mm_storeu_si128(
                    p.add(16).cast(),
                    _mm_xor_si128(_mm_loadu_si128(p.add(16).cast()), k1),
                );
                _mm_storeu_si128(
                    p.add(32).cast(),
                    _mm_xor_si128(_mm_loadu_si128(p.add(32).cast()), k2),
                );
                _mm_storeu_si128(
                    p.add(48).cast(),
                    _mm_xor_si128(_mm_loadu_si128(p.add(48).cast()), k3),
                );
            }
            offset += 64;
        }

        while offset + 16 <= buf.len() {
            let ci = self.in_ctr.ctr;
            let co = self.out_ctr.ctr;
            incr_be128(&mut self.in_ctr.ctr, 1);
            incr_be128(&mut self.out_ctr.ctr, 1);

            // SAFETY: `ci` & `co` are 16 bytes; `offset + 16 <= buf.len()`.
            unsafe {
                let mut a0 = _mm_xor_si128(_mm_loadu_si128(ci.as_ptr().cast()), rk_in[0]);
                let mut b0 = _mm_xor_si128(_mm_loadu_si128(co.as_ptr().cast()), rk_out[0]);
                for r in 1..14 {
                    a0 = _mm_aesenc_si128(a0, rk_in[r]);
                    b0 = _mm_aesenc_si128(b0, rk_out[r]);
                }
                a0 = _mm_aesenclast_si128(a0, rk_in[14]);
                b0 = _mm_aesenclast_si128(b0, rk_out[14]);
                let p = buf.as_mut_ptr().add(offset);
                let k0 = _mm_xor_si128(a0, b0);
                _mm_storeu_si128(p.cast(), _mm_xor_si128(_mm_loadu_si128(p.cast()), k0));
            }
            offset += 16;
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn reference_ctr(key: &[u8; 32], iv: &[u8; 16], data: &mut [u8]) {
        let cipher = Aes256Enc::new_from_slice(key).unwrap();
        let mut ctr = *iv;
        for chunk in data.chunks_mut(16) {
            let mut block = aes::Block::from(ctr);
            incr_be128(&mut ctr, 1);
            cipher.encrypt_block(&mut block);
            for (d, k) in chunk.iter_mut().zip(block.iter()) {
                *d ^= *k;
            }
        }
    }

    #[test]
    fn key_expansion_matches_portable_and_reference() {
        let key: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(17).wrapping_add(3));
        let hw = Aes256EncKey::new(&key);
        let sw = Aes256EncKey::expand_portable(&key);
        assert_eq!(hw.rk, sw.rk);

        let mut b_hw = [0x5au8; 16];
        let mut b_sw = b_hw;
        hw.encrypt_block(&mut b_hw);
        sw.encrypt_block_portable(&mut b_sw);
        assert_eq!(b_hw, b_sw);
    }

    #[test]
    fn counter_wraparound_matches_big_endian_128() {
        let key = [0x42u8; 32];
        // IV right at 64-bit low carry boundary!
        let iv = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfd,
        ];
        let mut got = vec![0xa5u8; 1024];
        let mut want = got.clone();
        Aes256Ctr::new(&key, &iv).apply_keystream(&mut got);
        reference_ctr(&key, &iv, &mut want);
        assert_eq!(got, want);
    }

    proptest! {
        #[test]
        fn single_and_fused_ctr_match_reference_across_arbitrary_splits(
            k1 in any::<[u8; 32]>(),
            iv1 in any::<[u8; 16]>(),
            k2 in any::<[u8; 32]>(),
            iv2 in any::<[u8; 16]>(),
            payload in proptest::collection::vec(any::<u8>(), 0..2048),
            splits in proptest::collection::vec(1usize..170, 1..20),
        ) {
            // Single stream test with arbitrary chunking.
            let mut ref_single = payload.clone();
            reference_ctr(&k1, &iv1, &mut ref_single);

            let mut got_single = payload.clone();
            let mut c1 = Aes256Ctr::new(&k1, &iv1);
            let mut pos = 0;
            let mut s_idx = 0;
            while pos < got_single.len() {
                let step = splits[s_idx % splits.len()].min(got_single.len() - pos);
                c1.apply_keystream(&mut got_single[pos..pos + step]);
                pos += step;
                s_idx += 1;
            }
            prop_assert_eq!(&got_single, &ref_single);

            // Fused double-CTR test with arbitrary chunking.
            let mut ref_fused = ref_single;
            reference_ctr(&k2, &iv2, &mut ref_fused);

            let mut got_fused = payload;
            let mut pair = FusedCtrPair::new(
                Aes256Ctr::new(&k1, &iv1),
                Aes256Ctr::new(&k2, &iv2),
            );
            let mut pos = 0;
            let mut s_idx = 0;
            while pos < got_fused.len() {
                let step = splits[s_idx % splits.len()].min(got_fused.len() - pos);
                pair.apply_fused_in_place(&mut got_fused[pos..pos + step]);
                pos += step;
                s_idx += 1;
            }
            prop_assert_eq!(got_fused, ref_fused);
        }
    }
}
