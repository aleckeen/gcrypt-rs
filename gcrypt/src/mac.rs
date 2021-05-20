use std::ffi::CStr;
use std::ptr;

use gpgrt::Error;

use crate::Result;

#[repr(u32)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum Algorithm
{
  /// This is keyed-hash message authentication code (HMAC) message authentication algorithm based
  /// on the SHA-256 hash algorithm.
  HmacSha256 = gcrypt_sys::GCRY_MAC_HMAC_SHA256,

  /// This is HMAC message authentication algorithm based on the SHA-224 hash algorithm.
  HmacSha224 = gcrypt_sys::GCRY_MAC_HMAC_SHA224,

  /// This is HMAC message authentication algorithm based on the SHA-512 hash algorithm.
  HmacSha512 = gcrypt_sys::GCRY_MAC_HMAC_SHA512,

  /// This is HMAC message authentication algorithm based on the SHA-384 hash algorithm.
  HmacSha384 = gcrypt_sys::GCRY_MAC_HMAC_SHA384,

  /// This is HMAC message authentication algorithm based on the SHA3-256 hash algorithm.
  HmacSha3_256 = gcrypt_sys::GCRY_MAC_HMAC_SHA3_256,

  /// This is HMAC message authentication algorithm based on the SHA3-224 hash algorithm.
  HmacSha3_224 = gcrypt_sys::GCRY_MAC_HMAC_SHA3_224,

  /// This is HMAC message authentication algorithm based on the SHA3-512 hash algorithm.
  HmacSha3_512 = gcrypt_sys::GCRY_MAC_HMAC_SHA3_512,

  /// This is HMAC message authentication algorithm based on the SHA3-384 hash algorithm.
  HmacSha3_384 = gcrypt_sys::GCRY_MAC_HMAC_SHA3_384,

  /// This is HMAC message authentication algorithm based on the SHA-512/224 hash algorithm.
  HmacSha512_224 = gcrypt_sys::GCRY_MAC_HMAC_SHA512_224,

  /// This is HMAC message authentication algorithm based on the SHA-512/256 hash algorithm.
  HmacSha512_256 = gcrypt_sys::GCRY_MAC_HMAC_SHA512_256,

  /// This is HMAC message authentication algorithm based on the SHA-1 hash algorithm.
  HmacSha1 = gcrypt_sys::GCRY_MAC_HMAC_SHA1,

  /// This is HMAC message authentication algorithm based on the MD5 hash algorithm.
  HmacMd5 = gcrypt_sys::GCRY_MAC_HMAC_MD5,

  /// This is HMAC message authentication algorithm based on the MD4 hash algorithm.
  HmacMd4 = gcrypt_sys::GCRY_MAC_HMAC_MD4,

  /// This is HMAC message authentication algorithm based on the RIPE-MD-160 hash algorithm.
  HmacRmd160 = gcrypt_sys::GCRY_MAC_HMAC_RMD160,

  /// This is HMAC message authentication algorithm based on the WHIRLPOOL hash algorithm.
  HmacWhirlpool = gcrypt_sys::GCRY_MAC_HMAC_WHIRLPOOL,

  /// This is HMAC message authentication algorithm based on the GOST R 34.11-94 hash algorithm.
  HmacGostr3411_94 = gcrypt_sys::GCRY_MAC_HMAC_GOSTR3411_94,

  /// This is HMAC message authentication algorithm based on the 256-bit hash algorithm described
  /// in GOST R 34.11-2012.
  HmacStribog256 = gcrypt_sys::GCRY_MAC_HMAC_STRIBOG256,

  /// This is HMAC message authentication algorithm based on the 512-bit hash algorithm described
  /// in GOST R 34.11-2012.
  HmacStribog512 = gcrypt_sys::GCRY_MAC_HMAC_STRIBOG512,

  /// This is HMAC message authentication algorithm based on the BLAKE2b-512 hash algorithm.
  HmacBlake2b512 = gcrypt_sys::GCRY_MAC_HMAC_BLAKE2B_512,

  /// This is HMAC message authentication algorithm based on the BLAKE2b-384 hash algorithm.
  HmacBlake2b384 = gcrypt_sys::GCRY_MAC_HMAC_BLAKE2B_384,

  /// This is HMAC message authentication algorithm based on the BLAKE2b-256 hash algorithm.
  HmacBlake2b256 = gcrypt_sys::GCRY_MAC_HMAC_BLAKE2B_256,

  /// This is HMAC message authentication algorithm based on the BLAKE2b-160 hash algorithm.
  HmacBlake2b160 = gcrypt_sys::GCRY_MAC_HMAC_BLAKE2B_160,

  /// This is HMAC message authentication algorithm based on the BLAKE2s-256 hash algorithm.
  HmacBlake2s256 = gcrypt_sys::GCRY_MAC_HMAC_BLAKE2S_256,

  /// This is HMAC message authentication algorithm based on the BLAKE2s-224 hash algorithm.
  HmacBlake2s224 = gcrypt_sys::GCRY_MAC_HMAC_BLAKE2S_224,

  /// This is HMAC message authentication algorithm based on the BLAKE2s-160 hash algorithm.
  HmacBlake2s160 = gcrypt_sys::GCRY_MAC_HMAC_BLAKE2S_160,

  /// This is HMAC message authentication algorithm based on the BLAKE2s-128 hash algorithm.
  HmacBlake2s128 = gcrypt_sys::GCRY_MAC_HMAC_BLAKE2S_128,

  /// This is HMAC message authentication algorithm based on the SM3 hash algorithm.
  HmacSm3 = gcrypt_sys::GCRY_MAC_HMAC_SM3,

  /// This is CMAC (Cipher-based MAC) message authentication algorithm based on the AES block
  /// cipher algorithm.
  CmacAes = gcrypt_sys::GCRY_MAC_CMAC_AES,

  /// This is CMAC message authentication algorithm based on the three-key EDE Triple-DES block
  /// cipher algorithm.
  Cmac3Des = gcrypt_sys::GCRY_MAC_CMAC_3DES,

  /// This is CMAC message authentication algorithm based on the Camellia block cipher algorithm.
  CmacCamellia = gcrypt_sys::GCRY_MAC_CMAC_CAMELLIA,

  /// This is CMAC message authentication algorithm based on the CAST128-5 block cipher algorithm.
  CmacCast5 = gcrypt_sys::GCRY_MAC_CMAC_CAST5,

  /// This is CMAC message authentication algorithm based on the Blowfish block cipher algorithm.
  CmacBlowfish = gcrypt_sys::GCRY_MAC_CMAC_BLOWFISH,

  /// This is CMAC message authentication algorithm based on the Twofish block cipher algorithm.
  CmacTwofish = gcrypt_sys::GCRY_MAC_CMAC_TWOFISH,

  /// This is CMAC message authentication algorithm based on the Serpent block cipher algorithm.
  CmacSerpent = gcrypt_sys::GCRY_MAC_CMAC_SERPENT,

  /// This is CMAC message authentication algorithm based on the SEED block cipher algorithm.
  CmacSeed = gcrypt_sys::GCRY_MAC_CMAC_SEED,

  /// This is CMAC message authentication algorithm based on the Ron’s Cipher 2 block cipher
  /// algorithm.
  CmacRfc2268 = gcrypt_sys::GCRY_MAC_CMAC_RFC2268,

  /// This is CMAC message authentication algorithm based on the IDEA block cipher algorithm.
  CmacIdea = gcrypt_sys::GCRY_MAC_CMAC_IDEA,

  /// This is CMAC message authentication algorithm based on the GOST 28147-89 block cipher
  /// algorithm.
  CmacGost28147 = gcrypt_sys::GCRY_MAC_CMAC_GOST28147,

  /// This is CMAC message authentication algorithm based on the SM4 block cipher algorithm.
  CmacSm4 = gcrypt_sys::GCRY_MAC_CMAC_SM4,

  /// This is GMAC (GCM mode based MAC) message authentication algorithm based on the AES block
  /// cipher algorithm.
  GmacAes = gcrypt_sys::GCRY_MAC_GMAC_AES,

  /// This is GMAC message authentication algorithm based on the Camellia block cipher algorithm.
  GmacCamellia = gcrypt_sys::GCRY_MAC_GMAC_CAMELLIA,

  /// This is GMAC message authentication algorithm based on the Twofish block cipher algorithm.
  GmacTwofish = gcrypt_sys::GCRY_MAC_GMAC_TWOFISH,

  /// This is GMAC message authentication algorithm based on the Serpent block cipher algorithm.
  GmacSerpent = gcrypt_sys::GCRY_MAC_GMAC_SERPENT,

  /// This is GMAC message authentication algorithm based on the SEED block cipher algorithm.
  GmacSeed = gcrypt_sys::GCRY_MAC_GMAC_SEED,

  /// This is plain Poly1305 message authentication algorithm, used with one-time key.
  Poly1305 = gcrypt_sys::GCRY_MAC_POLY1305,

  /// This is Poly1305-AES message authentication algorithm, used with key and one-time nonce.
  Poly1305Aes = gcrypt_sys::GCRY_MAC_POLY1305_AES,

  /// This is Poly1305-Camellia message authentication algorithm, used with key and one-time nonce.
  Poly1305Camellia = gcrypt_sys::GCRY_MAC_POLY1305_CAMELLIA,

  /// This is Poly1305-Twofish message authentication algorithm, used with key and one-time nonce.
  Poly1305Twofish = gcrypt_sys::GCRY_MAC_POLY1305_TWOFISH,

  /// This is Poly1305-Serpent message authentication algorithm, used with key and one-time nonce.
  Poly1305Serpent = gcrypt_sys::GCRY_MAC_POLY1305_SERPENT,

  /// This is Poly1305-SEED message authentication algorithm, used with key and one-time nonce.
  Poly1305Seed = gcrypt_sys::GCRY_MAC_POLY1305_SEED,

  /// This is MAC construction defined in GOST 28147-89 (see RFC 5830 Section 8).
  Gost28147Imit = gcrypt_sys::GCRY_MAC_GOST28147_IMIT,
}

impl Algorithm
{
  pub const ALGORITHMS: &'static [Self] = &[
    Self::HmacSha256,
    Self::HmacSha224,
    Self::HmacSha512,
    Self::HmacSha384,
    Self::HmacSha3_256,
    Self::HmacSha3_224,
    Self::HmacSha3_512,
    Self::HmacSha3_384,
    Self::HmacSha512_224,
    Self::HmacSha512_256,
    Self::HmacSha1,
    Self::HmacMd5,
    Self::HmacMd4,
    Self::HmacRmd160,
    Self::HmacWhirlpool,
    Self::HmacGostr3411_94,
    Self::HmacStribog256,
    Self::HmacStribog512,
    Self::HmacBlake2b512,
    Self::HmacBlake2b384,
    Self::HmacBlake2b256,
    Self::HmacBlake2b160,
    Self::HmacBlake2s256,
    Self::HmacBlake2s224,
    Self::HmacBlake2s160,
    Self::HmacBlake2s128,
    Self::HmacSm3,
    Self::CmacAes,
    Self::Cmac3Des,
    Self::CmacCamellia,
    Self::CmacCast5,
    Self::CmacBlowfish,
    Self::CmacTwofish,
    Self::CmacSerpent,
    Self::CmacSeed,
    Self::CmacRfc2268,
    Self::CmacIdea,
    Self::CmacGost28147,
    Self::CmacSm4,
    Self::GmacAes,
    Self::GmacCamellia,
    Self::GmacTwofish,
    Self::GmacSerpent,
    Self::GmacSeed,
    Self::Poly1305,
    Self::Poly1305Aes,
    Self::Poly1305Camellia,
    Self::Poly1305Twofish,
    Self::Poly1305Serpent,
    Self::Poly1305Seed,
    Self::Gost28147Imit,
  ];

  #[inline]
  pub(crate) fn from_raw(raw: i32) -> Option<Algorithm>
  {
    match raw as u32 {
      | gcrypt_sys::GCRY_MAC_HMAC_SHA256 => Some(Self::HmacSha256),
      | gcrypt_sys::GCRY_MAC_HMAC_SHA224 => Some(Self::HmacSha224),
      | gcrypt_sys::GCRY_MAC_HMAC_SHA512 => Some(Self::HmacSha512),
      | gcrypt_sys::GCRY_MAC_HMAC_SHA384 => Some(Self::HmacSha384),
      | gcrypt_sys::GCRY_MAC_HMAC_SHA3_256 => Some(Self::HmacSha3_256),
      | gcrypt_sys::GCRY_MAC_HMAC_SHA3_224 => Some(Self::HmacSha3_224),
      | gcrypt_sys::GCRY_MAC_HMAC_SHA3_512 => Some(Self::HmacSha3_512),
      | gcrypt_sys::GCRY_MAC_HMAC_SHA3_384 => Some(Self::HmacSha3_384),
      | gcrypt_sys::GCRY_MAC_HMAC_SHA512_224 => Some(Self::HmacSha512_224),
      | gcrypt_sys::GCRY_MAC_HMAC_SHA512_256 => Some(Self::HmacSha512_256),
      | gcrypt_sys::GCRY_MAC_HMAC_SHA1 => Some(Self::HmacSha1),
      | gcrypt_sys::GCRY_MAC_HMAC_MD5 => Some(Self::HmacMd5),
      | gcrypt_sys::GCRY_MAC_HMAC_MD4 => Some(Self::HmacMd4),
      | gcrypt_sys::GCRY_MAC_HMAC_RMD160 => Some(Self::HmacRmd160),
      | gcrypt_sys::GCRY_MAC_HMAC_WHIRLPOOL => Some(Self::HmacWhirlpool),
      | gcrypt_sys::GCRY_MAC_HMAC_GOSTR3411_94 => Some(Self::HmacGostr3411_94),
      | gcrypt_sys::GCRY_MAC_HMAC_STRIBOG256 => Some(Self::HmacStribog256),
      | gcrypt_sys::GCRY_MAC_HMAC_STRIBOG512 => Some(Self::HmacStribog512),
      | gcrypt_sys::GCRY_MAC_HMAC_BLAKE2B_512 => Some(Self::HmacBlake2b512),
      | gcrypt_sys::GCRY_MAC_HMAC_BLAKE2B_384 => Some(Self::HmacBlake2b384),
      | gcrypt_sys::GCRY_MAC_HMAC_BLAKE2B_256 => Some(Self::HmacBlake2b256),
      | gcrypt_sys::GCRY_MAC_HMAC_BLAKE2B_160 => Some(Self::HmacBlake2b160),
      | gcrypt_sys::GCRY_MAC_HMAC_BLAKE2S_256 => Some(Self::HmacBlake2s256),
      | gcrypt_sys::GCRY_MAC_HMAC_BLAKE2S_224 => Some(Self::HmacBlake2s224),
      | gcrypt_sys::GCRY_MAC_HMAC_BLAKE2S_160 => Some(Self::HmacBlake2s160),
      | gcrypt_sys::GCRY_MAC_HMAC_BLAKE2S_128 => Some(Self::HmacBlake2s128),
      | gcrypt_sys::GCRY_MAC_HMAC_SM3 => Some(Self::HmacSm3),
      | gcrypt_sys::GCRY_MAC_CMAC_AES => Some(Self::CmacAes),
      | gcrypt_sys::GCRY_MAC_CMAC_3DES => Some(Self::Cmac3Des),
      | gcrypt_sys::GCRY_MAC_CMAC_CAMELLIA => Some(Self::CmacCamellia),
      | gcrypt_sys::GCRY_MAC_CMAC_CAST5 => Some(Self::CmacCast5),
      | gcrypt_sys::GCRY_MAC_CMAC_BLOWFISH => Some(Self::CmacBlowfish),
      | gcrypt_sys::GCRY_MAC_CMAC_TWOFISH => Some(Self::CmacTwofish),
      | gcrypt_sys::GCRY_MAC_CMAC_SERPENT => Some(Self::CmacSerpent),
      | gcrypt_sys::GCRY_MAC_CMAC_SEED => Some(Self::CmacSeed),
      | gcrypt_sys::GCRY_MAC_CMAC_RFC2268 => Some(Self::CmacRfc2268),
      | gcrypt_sys::GCRY_MAC_CMAC_IDEA => Some(Self::CmacIdea),
      | gcrypt_sys::GCRY_MAC_CMAC_GOST28147 => Some(Self::CmacGost28147),
      | gcrypt_sys::GCRY_MAC_CMAC_SM4 => Some(Self::CmacSm4),
      | gcrypt_sys::GCRY_MAC_GMAC_AES => Some(Self::GmacAes),
      | gcrypt_sys::GCRY_MAC_GMAC_CAMELLIA => Some(Self::GmacCamellia),
      | gcrypt_sys::GCRY_MAC_GMAC_TWOFISH => Some(Self::GmacTwofish),
      | gcrypt_sys::GCRY_MAC_GMAC_SERPENT => Some(Self::GmacSerpent),
      | gcrypt_sys::GCRY_MAC_GMAC_SEED => Some(Self::GmacSeed),
      | gcrypt_sys::GCRY_MAC_POLY1305 => Some(Self::Poly1305),
      | gcrypt_sys::GCRY_MAC_POLY1305_AES => Some(Self::Poly1305Aes),
      | gcrypt_sys::GCRY_MAC_POLY1305_CAMELLIA => Some(Self::Poly1305Camellia),
      | gcrypt_sys::GCRY_MAC_POLY1305_TWOFISH => Some(Self::Poly1305Twofish),
      | gcrypt_sys::GCRY_MAC_POLY1305_SERPENT => Some(Self::Poly1305Serpent),
      | gcrypt_sys::GCRY_MAC_POLY1305_SEED => Some(Self::Poly1305Seed),
      | gcrypt_sys::GCRY_MAC_GOST28147_IMIT => Some(Self::Gost28147Imit),
      | _ => None,
    }
  }

  #[inline]
  pub(crate) fn raw(&self) -> i32
  {
    *self as i32
  }

  #[inline]
  pub fn name(&self) -> &str
  {
    let ptr = unsafe { gcrypt_sys::gcry_mac_algo_name(*self as _) };
    unsafe { CStr::from_ptr(ptr) }.to_str().unwrap()
  }

  #[inline]
  pub fn mac_len(&self) -> usize
  {
    unsafe { gcrypt_sys::gcry_mac_get_algo_maclen(*self as _) as usize }
  }

  #[inline]
  pub fn key_len(&self) -> usize
  {
    unsafe { gcrypt_sys::gcry_mac_get_algo_keylen(*self as _) as usize }
  }
}

impl std::fmt::Debug for Algorithm
{
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result
  {
    f.debug_struct(&format!("{} ({})", self.name(), self.raw()))
      .field("mac_len", &self.mac_len())
      .field("key_len", &self.key_len())
      .finish()
  }
}

pub struct Flags(u32);

impl Flags
{
  pub const NONE: Self = Self(0);
  pub const SECURE: Self = Self(gcrypt_sys::GCRY_MAC_FLAG_SECURE);

  #[inline]
  pub(crate) fn raw(&self) -> u32
  {
    self.0
  }
}

impl Default for Flags
{
  #[inline]
  fn default() -> Self
  {
    Self::NONE
  }
}

impl std::ops::BitOr for Flags
{
  type Output = Self;

  #[inline]
  fn bitor(self, rhs: Self) -> Self::Output
  {
    Self(self.0 | rhs.0)
  }
}

pub struct Mac(gcrypt_sys::gcry_mac_hd_t);

impl Mac
{
  #[inline]
  pub fn new(algo: Algorithm, flags: Flags) -> Result<Self>
  {
    let mut inner = ptr::null_mut();
    let err = Error::from_raw(unsafe {
      gcrypt_sys::gcry_mac_open(&mut inner, algo.raw(), flags.raw(), ptr::null_mut())
    });
    if err.is_error() {
      Err(err)
    } else if inner.is_null() {
      panic!("unexpected: returned handle is null");
    } else {
      Ok(Self(inner))
    }
  }

  #[inline]
  pub fn set_key(&mut self, key: &[u8]) -> Result<()>
  {
    let err = Error::from_raw(unsafe {
      gcrypt_sys::gcry_mac_setkey(self.0, key.as_ptr().cast(), key.len())
    });
    if err.is_error() { Err(err) } else { Ok(()) }
  }

  #[inline]
  pub fn set_iv(&mut self, iv: &[u8]) -> Result<()>
  {
    let err =
      Error::from_raw(unsafe { gcrypt_sys::gcry_mac_setiv(self.0, iv.as_ptr().cast(), iv.len()) });
    if err.is_error() { Err(err) } else { Ok(()) }
  }

  #[inline]
  pub fn algorithm(&self) -> Algorithm
  {
    Algorithm::from_raw(unsafe { gcrypt_sys::gcry_mac_get_algo(self.0) }).unwrap()
  }

  #[inline]
  pub fn reset(self) -> Self
  {
    unsafe { gcrypt_sys::gcry_mac_ctl(self.0, gcrypt_sys::GCRYCTL_RESET as _, ptr::null_mut(), 0) };
    self
  }

  #[inline]
  pub fn update(&mut self, buf: &[u8])
  {
    unsafe { gcrypt_sys::gcry_mac_write(self.0, buf.as_ptr().cast(), buf.len()) };
  }

  #[inline]
  pub fn finish(&mut self) -> Result<Box<[u8]>>
  {
    let mut len = self.algorithm().mac_len();
    let mut buffer: Box<[u8]> = unsafe { Box::new_uninit_slice(len).assume_init() };
    let err = Error::from_raw(unsafe {
      gcrypt_sys::gcry_mac_read(self.0, buffer.as_mut_ptr().cast(), &mut len)
    });
    if err.is_error() { Err(err) } else { Ok(buffer) }
  }
}

impl Drop for Mac
{
  fn drop(&mut self)
  {
    unsafe { gcrypt_sys::gcry_mac_close(self.0) };
  }
}
