use std::ffi::CStr;
use std::ptr;

use gpgrt::Error;

use crate::Result;

#[derive(Copy, Clone, Eq, PartialEq, Hash)]
#[repr(u32)]
pub enum Algorithm
{
  /// This is the SHA-1 algorithm which yields a message digest of 20 bytes. Note that SHA-1 begins
  /// to show some weaknesses and it is suggested to fade out its use if strong cryptographic
  /// properties are required.
  Sha1 = gcrypt_sys::GCRY_MD_SHA1,

  /// This is the 160 bit version of the RIPE message digest (RIPE-MD-160). Like SHA-1 it also
  /// yields a digest of 20 bytes. This algorithm share a lot of design properties with SHA-1 and
  /// thus it is advisable not to use it for new protocols.
  Rmd160 = gcrypt_sys::GCRY_MD_RMD160,

  /// This is the well known MD5 algorithm, which yields a message digest of 16 bytes. Note that
  /// the MD5 algorithm has severe weaknesses, for example it is easy to compute two messages
  /// yielding the same hash (collision attack). The use of this algorithm is only justified for
  /// non-cryptographic application.
  Md5 = gcrypt_sys::GCRY_MD_MD5,

  /// This is the MD4 algorithm, which yields a message digest of 16 bytes. This algorithm has
  /// severe weaknesses and should not be used.
  Md4 = gcrypt_sys::GCRY_MD_MD4,

  // /// This is an reserved identifier for MD-2; there is no implementation yet. This algorithm
  // has /// severe weaknesses and should not be used.
  // Md2 = gcrypt_sys::GCRY_MD_MD2,
  /// This is the TIGER/192 algorithm which yields a message digest of 24 bytes. Actually this is a
  /// variant of TIGER with a different output print order as used by GnuPG up to version 1.3.2.
  Tiger = gcrypt_sys::GCRY_MD_TIGER,

  /// This is the TIGER variant as used by the NESSIE project. It uses the most commonly used
  /// output print order.
  Tiger1 = gcrypt_sys::GCRY_MD_TIGER1,

  /// This is another variant of TIGER with a different padding scheme.
  Tiger2 = gcrypt_sys::GCRY_MD_TIGER2,

  // /// This is an reserved value for the HAVAL algorithm with 5 passes and 160 bit. It yields a
  // /// message digest of 20 bytes. Note that there is no implementation yet available.
  // Haval = gcrypt_sys::GCRY_MD_HAVAL,
  /// This is the SHA-224 algorithm which yields a message digest of 28 bytes. See Change Notice 1
  /// for FIPS 180-2 for the specification.
  Sha224 = gcrypt_sys::GCRY_MD_SHA224,

  /// This is the SHA-256 algorithm which yields a message digest of 32 bytes. See FIPS 180-2 for
  /// the specification.
  Sha256 = gcrypt_sys::GCRY_MD_SHA256,

  /// This is the SHA-384 algorithm which yields a message digest of 48 bytes. See FIPS 180-2 for
  /// the specification.
  Sha384 = gcrypt_sys::GCRY_MD_SHA384,

  /// This is the SHA-512 algorithm which yields a message digest of 64 bytes. See FIPS 180-2 for
  /// the specification.
  Sha512 = gcrypt_sys::GCRY_MD_SHA512,

  /// This is the SHA-512/224 algorithm which yields a message digest of 28 bytes. See FIPS 180-4
  /// for the specification.
  Sha512_224 = gcrypt_sys::GCRY_MD_SHA512_224,

  /// This is the SHA-512/256 algorithm which yields a message digest of 32 bytes. See FIPS 180-4
  /// for the specification.
  Sha512_256 = gcrypt_sys::GCRY_MD_SHA512_256,

  /// This is the SHA3-224 algorithm which yields a message digest of 28 bytes. See FIPS 202 for
  /// the specification.
  Sha3_224 = gcrypt_sys::GCRY_MD_SHA3_224,

  /// This is the SHA3-256 algorithm which yields a message digest of 32 bytes. See FIPS 202 for
  /// the specification.
  Sha3_256 = gcrypt_sys::GCRY_MD_SHA3_256,

  /// This is the SHA3-384 algorithm which yields a message digest of 48 bytes. See FIPS 202 for
  /// the specification.
  Sha3_384 = gcrypt_sys::GCRY_MD_SHA3_384,

  /// This is the SHA3-512 algorithm which yields a message digest of 64 bytes. See FIPS 202 for
  /// the specification.
  Sha3_512 = gcrypt_sys::GCRY_MD_SHA3_512,

  /// This is the SHAKE128 extendable-output function (XOF) algorithm with 128 bit security
  /// strength. See FIPS 202 for the specification.
  Shake128 = gcrypt_sys::GCRY_MD_SHAKE128,

  /// This is the SHAKE256 extendable-output function (XOF) algorithm with 256 bit security
  /// strength. See FIPS 202 for the specification.
  Shake256 = gcrypt_sys::GCRY_MD_SHAKE256,

  /// This is the ISO 3309 and ITU-T V.42 cyclic redundancy check. It yields an output of 4 bytes.
  /// Note that this is not a hash algorithm in the cryptographic sense.
  Crc32 = gcrypt_sys::GCRY_MD_CRC32,

  /// This is the above cyclic redundancy check function, as modified by RFC 1510. It yields an
  /// output of 4 bytes. Note that this is not a hash algorithm in the cryptographic sense.
  Crc32Rfc1510 = gcrypt_sys::GCRY_MD_CRC32_RFC1510,

  /// This is the OpenPGP cyclic redundancy check function. It yields an output of 3 bytes. Note
  /// that this is not a hash algorithm in the cryptographic sense.
  Crc24Rfc2440 = gcrypt_sys::GCRY_MD_CRC24_RFC2440,

  /// This is the Whirlpool algorithm which yields a message digest of 64 bytes.
  Whirlpool = gcrypt_sys::GCRY_MD_WHIRLPOOL,

  /// This is the hash algorithm described in GOST R 34.11-94 which yields a message digest of 32
  /// bytes.
  Gostr3411_94 = gcrypt_sys::GCRY_MD_GOSTR3411_94,

  /// This is the 256-bit version of hash algorithm described in GOST R 34.11-2012 which yields a
  /// message digest of 32 bytes.
  Stribog256 = gcrypt_sys::GCRY_MD_STRIBOG256,

  /// This is the 512-bit version of hash algorithm described in GOST R 34.11-2012 which yields a
  /// message digest of 64 bytes.
  Stribog512 = gcrypt_sys::GCRY_MD_STRIBOG512,

  /// This is the BLAKE2b-512 algorithm which yields a message digest of 64 bytes. See RFC 7693 for
  /// the specification.
  Blake2b512 = gcrypt_sys::GCRY_MD_BLAKE2B_512,

  /// This is the BLAKE2b-384 algorithm which yields a message digest of 48 bytes. See RFC 7693 for
  /// the specification.
  Blake2b384 = gcrypt_sys::GCRY_MD_BLAKE2B_384,

  /// This is the BLAKE2b-256 algorithm which yields a message digest of 32 bytes. See RFC 7693 for
  /// the specification.
  Blake2b256 = gcrypt_sys::GCRY_MD_BLAKE2B_256,

  /// This is the BLAKE2b-160 algorithm which yields a message digest of 20 bytes. See RFC 7693 for
  /// the specification.
  Blake2b160 = gcrypt_sys::GCRY_MD_BLAKE2B_160,

  /// This is the BLAKE2s-256 algorithm which yields a message digest of 32 bytes. See RFC 7693 for
  /// the specification.
  Blake2s256 = gcrypt_sys::GCRY_MD_BLAKE2S_256,

  /// This is the BLAKE2s-224 algorithm which yields a message digest of 28 bytes. See RFC 7693 for
  /// the specification.
  Blake2s224 = gcrypt_sys::GCRY_MD_BLAKE2S_224,

  /// This is the BLAKE2s-160 algorithm which yields a message digest of 20 bytes. See RFC 7693 for
  /// the specification.
  Blake2s160 = gcrypt_sys::GCRY_MD_BLAKE2S_160,

  /// This is the BLAKE2s-128 algorithm which yields a message digest of 16 bytes. See RFC 7693 for
  /// the specification.
  Blake2s128 = gcrypt_sys::GCRY_MD_BLAKE2S_128,

  /// This is the SM3 algorithm which yields a message digest of 32 bytes.
  Sm3 = gcrypt_sys::GCRY_MD_SM3,
}

impl Algorithm
{
  pub const ALGORITHMS: &'static [Self] = &[
    Self::Sha1,
    Self::Rmd160,
    Self::Md5,
    Self::Md4,
    // Self::Md2,
    Self::Tiger,
    Self::Tiger1,
    Self::Tiger2,
    // Self::Haval,
    Self::Sha224,
    Self::Sha256,
    Self::Sha384,
    Self::Sha512,
    Self::Sha512_224,
    Self::Sha512_256,
    Self::Sha3_224,
    Self::Sha3_256,
    Self::Sha3_384,
    Self::Sha3_512,
    Self::Shake128,
    Self::Shake256,
    Self::Crc32,
    Self::Crc32Rfc1510,
    Self::Crc24Rfc2440,
    Self::Whirlpool,
    Self::Gostr3411_94,
    Self::Stribog256,
    Self::Stribog512,
    Self::Blake2b512,
    Self::Blake2b384,
    Self::Blake2b256,
    Self::Blake2b160,
    Self::Blake2s256,
    Self::Blake2s224,
    Self::Blake2s160,
    Self::Blake2s128,
    Self::Sm3,
  ];

  #[inline]
  pub(crate) fn from_raw(raw: i32) -> Option<Self>
  {
    match raw as u32 {
      | gcrypt_sys::GCRY_MD_SHA1 => Some(Self::Sha1),
      | gcrypt_sys::GCRY_MD_RMD160 => Some(Self::Rmd160),
      | gcrypt_sys::GCRY_MD_MD5 => Some(Self::Md5),
      | gcrypt_sys::GCRY_MD_MD4 => Some(Self::Md4),
      // | gcrypt_sys::GCRY_MD_MD2 => Some(Self::Md2),
      | gcrypt_sys::GCRY_MD_TIGER => Some(Self::Tiger),
      | gcrypt_sys::GCRY_MD_TIGER1 => Some(Self::Tiger1),
      | gcrypt_sys::GCRY_MD_TIGER2 => Some(Self::Tiger2),
      // | gcrypt_sys::GCRY_MD_HAVAL => Some(Self::Haval),
      | gcrypt_sys::GCRY_MD_SHA224 => Some(Self::Sha224),
      | gcrypt_sys::GCRY_MD_SHA256 => Some(Self::Sha256),
      | gcrypt_sys::GCRY_MD_SHA384 => Some(Self::Sha384),
      | gcrypt_sys::GCRY_MD_SHA512 => Some(Self::Sha512),
      | gcrypt_sys::GCRY_MD_SHA512_224 => Some(Self::Sha512_224),
      | gcrypt_sys::GCRY_MD_SHA512_256 => Some(Self::Sha512_256),
      | gcrypt_sys::GCRY_MD_SHA3_224 => Some(Self::Sha3_224),
      | gcrypt_sys::GCRY_MD_SHA3_256 => Some(Self::Sha3_256),
      | gcrypt_sys::GCRY_MD_SHA3_384 => Some(Self::Sha3_384),
      | gcrypt_sys::GCRY_MD_SHA3_512 => Some(Self::Sha3_512),
      | gcrypt_sys::GCRY_MD_SHAKE128 => Some(Self::Shake128),
      | gcrypt_sys::GCRY_MD_SHAKE256 => Some(Self::Shake256),
      | gcrypt_sys::GCRY_MD_CRC32 => Some(Self::Crc32),
      | gcrypt_sys::GCRY_MD_CRC32_RFC1510 => Some(Self::Crc32Rfc1510),
      | gcrypt_sys::GCRY_MD_CRC24_RFC2440 => Some(Self::Crc24Rfc2440),
      | gcrypt_sys::GCRY_MD_WHIRLPOOL => Some(Self::Whirlpool),
      | gcrypt_sys::GCRY_MD_GOSTR3411_94 => Some(Self::Gostr3411_94),
      | gcrypt_sys::GCRY_MD_STRIBOG256 => Some(Self::Stribog256),
      | gcrypt_sys::GCRY_MD_STRIBOG512 => Some(Self::Stribog512),
      | gcrypt_sys::GCRY_MD_BLAKE2B_512 => Some(Self::Blake2b512),
      | gcrypt_sys::GCRY_MD_BLAKE2B_384 => Some(Self::Blake2b384),
      | gcrypt_sys::GCRY_MD_BLAKE2B_256 => Some(Self::Blake2b256),
      | gcrypt_sys::GCRY_MD_BLAKE2B_160 => Some(Self::Blake2b160),
      | gcrypt_sys::GCRY_MD_BLAKE2S_256 => Some(Self::Blake2s256),
      | gcrypt_sys::GCRY_MD_BLAKE2S_224 => Some(Self::Blake2s224),
      | gcrypt_sys::GCRY_MD_BLAKE2S_160 => Some(Self::Blake2s160),
      | gcrypt_sys::GCRY_MD_BLAKE2S_128 => Some(Self::Blake2s128),
      | gcrypt_sys::GCRY_MD_SM3 => Some(Self::Sm3),
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
    let ptr = unsafe { gcrypt_sys::gcry_md_algo_name(*self as _) };
    unsafe { CStr::from_ptr(ptr) }.to_str().unwrap()
  }

  #[inline]
  pub fn digest_len(&self) -> usize
  {
    unsafe { gcrypt_sys::gcry_md_get_algo_dlen(*self as _) as usize }
  }
}

impl std::fmt::Debug for Algorithm
{
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result
  {
    f.debug_struct(&format!("{} ({})", self.name(), self.raw()))
      .field("digest_len", &self.digest_len())
      .finish()
  }
}

pub struct Flags(u32);

impl Flags
{
  pub const BUGEMU1: Self = Self(gcrypt_sys::GCRY_MD_FLAG_BUGEMU1);
  pub const HMAC: Self = Self(gcrypt_sys::GCRY_MD_FLAG_HMAC);
  pub const NONE: Self = Self(0);
  pub const SECURE: Self = Self(gcrypt_sys::GCRY_MD_FLAG_SECURE);

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

pub struct Md(gcrypt_sys::gcry_md_hd_t);

impl Md
{
  #[inline]
  pub fn new(algo: Algorithm, flags: Flags) -> Result<Self>
  {
    let mut inner = ptr::null_mut();
    let err =
      Error::from_raw(unsafe { gcrypt_sys::gcry_md_open(&mut inner, algo.raw(), flags.raw()) });
    if err.is_error() {
      Err(err)
    } else if inner.is_null() {
      // TODO: make sure the returned handle is always ensured to be valid.
      panic!("unexpected: returned handle is null");
    } else {
      Ok(Self(inner))
    }
  }

  #[inline]
  pub fn enable(&mut self, algo: Algorithm) -> Result<()>
  {
    let err = Error::from_raw(unsafe { gcrypt_sys::gcry_md_enable(self.0, algo.raw()) });
    if err.is_error() { Err(err) } else { Ok(()) }
  }

  #[inline]
  pub fn algorithm(&self) -> Option<Algorithm>
  {
    Algorithm::from_raw(unsafe { gcrypt_sys::gcry_md_get_algo(self.0) })
  }

  #[inline]
  pub fn is_enabled(&self, algo: Algorithm) -> bool
  {
    let res = unsafe { gcrypt_sys::gcry_md_is_enabled(self.0, algo.raw()) };
    res != 0
  }

  #[inline]
  pub fn is_secure(&self) -> bool
  {
    unsafe { gcrypt_sys::gcry_md_is_secure(self.0) != 0 }
  }

  #[inline]
  pub fn set_key(&mut self, key: &[u8]) -> Result<()>
  {
    let err = Error::from_raw(unsafe {
      gcrypt_sys::gcry_md_setkey(self.0, key.as_ptr().cast(), key.len())
    });
    if err.is_error() { Err(err) } else { Ok(()) }
  }

  #[inline]
  pub fn reset(self) -> Self
  {
    unsafe { gcrypt_sys::gcry_md_reset(self.0) };
    self
  }

  #[inline]
  pub fn update(&mut self, buf: &[u8])
  {
    unsafe { gcrypt_sys::gcry_md_write(self.0, buf.as_ptr().cast(), buf.len()) };
  }

  #[inline]
  pub fn finish(&mut self, algo: Algorithm) -> Option<&[u8]>
  {
    let ptr = unsafe { gcrypt_sys::gcry_md_read(self.0, algo.raw()) };
    if ptr.is_null() {
      None
    } else {
      Some(unsafe { std::slice::from_raw_parts(ptr, algo.digest_len()) })
    }
  }

  #[inline]
  pub fn try_clone(&self) -> Result<Self>
  {
    let mut inner = ptr::null_mut();
    let err = Error::from_raw(unsafe { gcrypt_sys::gcry_md_copy(&mut inner, self.0) });
    if err.is_error() {
      Err(err)
    } else {
      Ok(Self(inner))
    }
  }
}

impl Drop for Md
{
  #[inline]
  fn drop(&mut self)
  {
    unsafe { gcrypt_sys::gcry_md_close(self.0) };
  }
}
