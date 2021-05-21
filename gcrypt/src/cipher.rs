use std::ffi::CStr;
use std::ptr;

use gpgrt::Error;

use crate::Result;

#[derive(Copy, Clone, Eq, PartialEq, Hash)]
#[repr(u32)]
pub enum Algorithm
{
  /// This is the IDEA algorithm.
  Idea = gcrypt_sys::GCRY_CIPHER_IDEA,

  /// Triple-DES with 3 Keys as EDE. The key size of this algorithm is 168 bits but you have to
  /// pass 192 bits because the most significant bits of each byte are ignored.
  TripleDes = gcrypt_sys::GCRY_CIPHER_3DES,

  /// CAST128-5 block cipher algorithm. The key size is 128 bits.
  Cast5 = gcrypt_sys::GCRY_CIPHER_CAST5,

  /// The blowfish algorithm. The supported key sizes are 8 to 576 bits in 8 bit increments.
  Blowfish = gcrypt_sys::GCRY_CIPHER_BLOWFISH,

  // /// Reserved and not currently implemented.
  // SaferSk128 = gcrypt_sys::GCRY_CIPHER_SAFER_SK128,

  // /// Reserved and not currently implemented.
  // DesSk = gcrypt_sys::GCRY_CIPHER_DES_SK,
  /// AES (Rijndael) with a 128 bit key.
  Aes128 = gcrypt_sys::GCRY_CIPHER_AES,

  /// AES (Rijndael) with a 192 bit key.
  Aes192 = gcrypt_sys::GCRY_CIPHER_AES192,

  /// AES (Rijndael) with a 256 bit key.
  Aes256 = gcrypt_sys::GCRY_CIPHER_AES256,

  /// The Twofish algorithm with a 128 bit key.
  Twofish128 = gcrypt_sys::GCRY_CIPHER_TWOFISH128,

  /// The Twofish algorithm with a 256 bit key.
  Twofish256 = gcrypt_sys::GCRY_CIPHER_TWOFISH,

  /// An algorithm which is 100% compatible with RSA Inc.’s RC4 algorithm. Note that this is a
  /// stream cipher and must be used very carefully to avoid a couple of weaknesses.
  Arcfour = gcrypt_sys::GCRY_CIPHER_ARCFOUR,

  /// Standard DES with a 56 bit key. You need to pass 64 bit but the high bits of each byte are
  /// ignored. Note, that this is a weak algorithm which can be broken in reasonable time using a
  /// brute force approach.
  Des = gcrypt_sys::GCRY_CIPHER_DES,

  /// The 128 bit Serpent cipher from the AES contest.
  Serpent128 = gcrypt_sys::GCRY_CIPHER_SERPENT128,

  /// The 192 bit Serpent cipher from the AES contest.
  Serpent192 = gcrypt_sys::GCRY_CIPHER_SERPENT192,

  /// The 256 bit Serpent cipher from the AES contest.
  Serpent256 = gcrypt_sys::GCRY_CIPHER_SERPENT256,

  /// Ron’s Cipher 2 in the 40 bit variant.
  Rfc2268_40 = gcrypt_sys::GCRY_CIPHER_RFC2268_40,

  /// Ron’s Cipher 2 in the 128 bit variant.
  Rfc2268_128 = gcrypt_sys::GCRY_CIPHER_RFC2268_128,

  /// A 128 bit cipher as described by RFC4269.
  Seed = gcrypt_sys::GCRY_CIPHER_SEED,

  /// The Camellia cipher by NTT.
  /// [See](http://info.isl.ntt.co.jp/crypt/eng/camellia/specifications.html).
  Camellia128 = gcrypt_sys::GCRY_CIPHER_CAMELLIA128,
  Camellia192 = gcrypt_sys::GCRY_CIPHER_CAMELLIA192,
  Camellia256 = gcrypt_sys::GCRY_CIPHER_CAMELLIA256,

  /// This is the Salsa20 stream cipher.
  Salsa20 = gcrypt_sys::GCRY_CIPHER_SALSA20,

  /// This is the Salsa20/12 - reduced round version of Salsa20 stream cipher.
  Salsa20r12 = gcrypt_sys::GCRY_CIPHER_SALSA20R12,

  /// The GOST 28147-89 cipher, defined in the respective GOST standard. Translation of this GOST
  /// into English is provided in the RFC-5830.
  Gost28147 = gcrypt_sys::GCRY_CIPHER_GOST28147,

  /// The GOST 28147-89 cipher, defined in the respective GOST standard. Translation of this GOST
  /// into English is provided in the RFC-5830. This cipher will use CryptoPro keymeshing as
  /// defined in RFC 4357 if it has to be used for the selected parameter set.
  Gost28147Mesh = gcrypt_sys::GCRY_CIPHER_GOST28147_MESH,

  /// This is the ChaCha20 stream cipher.
  Chacha20 = gcrypt_sys::GCRY_CIPHER_CHACHA20,

  /// A 128 bit cipher by the State Cryptography Administration of China (SCA).
  /// [See](https://tools.ietf.org/html/draft-ribose-cfrg-sm4-10).
  Sm4 = gcrypt_sys::GCRY_CIPHER_SM4,
}

impl Algorithm
{
  pub const ALGORITHMS: &'static [Self] = &[
    Self::Idea,
    Self::TripleDes,
    Self::Cast5,
    Self::Blowfish,
    // Self::SaferSk128,
    // Self::DesSk,
    Self::Aes128,
    Self::Aes192,
    Self::Aes256,
    Self::Twofish128,
    Self::Twofish256,
    Self::Arcfour,
    Self::Des,
    Self::Serpent128,
    Self::Serpent192,
    Self::Serpent256,
    Self::Rfc2268_40,
    Self::Rfc2268_128,
    Self::Seed,
    Self::Camellia128,
    Self::Camellia192,
    Self::Camellia256,
    Self::Salsa20,
    Self::Salsa20r12,
    Self::Gost28147,
    Self::Gost28147Mesh,
    Self::Chacha20,
    Self::Sm4,
  ];

  // #[inline]
  // pub(crate) fn from_raw(raw: i32) -> Option<Self>
  // {
  //   match raw as u32 {
  //     | gcrypt_sys::GCRY_CIPHER_IDEA => Some(Self::Idea),
  //     | gcrypt_sys::GCRY_CIPHER_3DES => Some(Self::TripleDes),
  //     | gcrypt_sys::GCRY_CIPHER_CAST5 => Some(Self::Cast5),
  //     | gcrypt_sys::GCRY_CIPHER_BLOWFISH => Some(Self::Blowfish),
  //     // | gcrypt_sys::GCRY_CIPHER_SAFER_SK128 => Some(Self::SaferSk128),
  //     // | gcrypt_sys::GCRY_CIPHER_DES_SK => Some(Self::DesSk),
  //     | gcrypt_sys::GCRY_CIPHER_AES => Some(Self::Aes128),
  //     | gcrypt_sys::GCRY_CIPHER_AES192 => Some(Self::Aes192),
  //     | gcrypt_sys::GCRY_CIPHER_AES256 => Some(Self::Aes256),
  //     | gcrypt_sys::GCRY_CIPHER_TWOFISH128 => Some(Self::Twofish128),
  //     | gcrypt_sys::GCRY_CIPHER_TWOFISH => Some(Self::Twofish256),
  //     | gcrypt_sys::GCRY_CIPHER_ARCFOUR => Some(Self::Arcfour),
  //     | gcrypt_sys::GCRY_CIPHER_DES => Some(Self::Des),
  //     | gcrypt_sys::GCRY_CIPHER_SERPENT128 => Some(Self::Serpent128),
  //     | gcrypt_sys::GCRY_CIPHER_SERPENT192 => Some(Self::Serpent192),
  //     | gcrypt_sys::GCRY_CIPHER_SERPENT256 => Some(Self::Serpent256),
  //     | gcrypt_sys::GCRY_CIPHER_RFC2268_40 => Some(Self::Rfc2268_40),
  //     | gcrypt_sys::GCRY_CIPHER_RFC2268_128 => Some(Self::Rfc2268_128),
  //     | gcrypt_sys::GCRY_CIPHER_SEED => Some(Self::Seed),
  //     | gcrypt_sys::GCRY_CIPHER_CAMELLIA128 => Some(Self::Camellia128),
  //     | gcrypt_sys::GCRY_CIPHER_CAMELLIA192 => Some(Self::Camellia192),
  //     | gcrypt_sys::GCRY_CIPHER_CAMELLIA256 => Some(Self::Camellia256),
  //     | gcrypt_sys::GCRY_CIPHER_SALSA20 => Some(Self::Salsa20),
  //     | gcrypt_sys::GCRY_CIPHER_SALSA20R12 => Some(Self::Salsa20r12),
  //     | gcrypt_sys::GCRY_CIPHER_GOST28147 => Some(Self::Gost28147),
  //     | gcrypt_sys::GCRY_CIPHER_GOST28147_MESH => Some(Self::Gost28147Mesh),
  //     | gcrypt_sys::GCRY_CIPHER_CHACHA20 => Some(Self::Chacha20),
  //     | gcrypt_sys::GCRY_CIPHER_SM4 => Some(Self::Sm4),
  //     | _ => None,
  //   }
  // }

  #[inline]
  pub(crate) fn raw(&self) -> i32
  {
    *self as i32
  }

  #[inline]
  pub fn name(&self) -> &str
  {
    let ptr = unsafe { gcrypt_sys::gcry_cipher_algo_name(*self as _) };
    unsafe { CStr::from_ptr(ptr) }.to_str().unwrap()
  }

  #[inline]
  pub fn key_len(&self) -> usize
  {
    unsafe { gcrypt_sys::gcry_cipher_get_algo_keylen(*self as _) }
  }

  #[inline]
  pub fn block_len(&self) -> usize
  {
    unsafe { gcrypt_sys::gcry_cipher_get_algo_blklen(*self as _) }
  }
}

impl std::fmt::Debug for Algorithm
{
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result
  {
    f.debug_struct(&format!("{} ({})", self.name(), self.raw()))
      .field("key_len", &self.key_len())
      .field("block_len", &self.block_len())
      .finish()
  }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash)]
#[repr(u32)]
pub enum Mode
{
  /// Electronic Codebook mode.
  Ecb = gcrypt_sys::GCRY_CIPHER_MODE_ECB,

  /// Cipher Feedback mode. For GCRY_CIPHER_MODE_CFB the shift size equals the block size of the
  /// cipher (e.g. for AES it is CFB-128). For GCRY_CIPHER_MODE_CFB8 the shift size is 8 bit but
  /// that variant is not yet available.
  Cfb = gcrypt_sys::GCRY_CIPHER_MODE_CFB,

  Cfb8 = gcrypt_sys::GCRY_CIPHER_MODE_CFB8,

  /// Cipher Block Chaining mode.
  Cbc = gcrypt_sys::GCRY_CIPHER_MODE_CBC,

  /// Stream mode, only to be used with stream cipher algorithms.
  Stream = gcrypt_sys::GCRY_CIPHER_MODE_STREAM,

  /// Output Feedback mode.
  Ofb = gcrypt_sys::GCRY_CIPHER_MODE_OFB,

  /// Counter mode.
  Ctr = gcrypt_sys::GCRY_CIPHER_MODE_CTR,

  /// This mode is used to implement the AES-Wrap algorithm according to RFC-3394. It may be used
  /// with any 128 bit block length algorithm, however the specs require one of the 3 AES
  /// algorithms. These special conditions apply: If gcry_cipher_setiv has not been used the
  /// standard IV is used; if it has been used the lower 64 bit of the IV are used as the
  /// Alternative Initial Value. On encryption the provided output buffer must be 64 bit (8 byte)
  /// larger than the input buffer; in-place encryption is still allowed. On decryption the output
  /// buffer may be specified 64 bit (8 byte) shorter than then input buffer. As per specs the
  /// input length must be at least 128 bits and the length must be a multiple of 64 bits.
  AesWrap = gcrypt_sys::GCRY_CIPHER_MODE_AESWRAP,

  /// Counter with CBC-MAC mode is an Authenticated Encryption with Associated Data (AEAD) block
  /// cipher mode, which is specified in ’NIST Special Publication 800-38C’ and RFC 3610.
  CCM = gcrypt_sys::GCRY_CIPHER_MODE_CCM,

  /// Galois/Counter Mode (GCM) is an Authenticated Encryption with Associated Data (AEAD) block
  /// cipher mode, which is specified in ’NIST Special Publication 800-38D’.
  Gcm = gcrypt_sys::GCRY_CIPHER_MODE_GCM,

  /// This mode implements the Poly1305 Authenticated Encryption with Associated Data (AEAD) mode
  /// according to RFC-8439. This mode can be used with ChaCha20 stream cipher.
  Poly1305 = gcrypt_sys::GCRY_CIPHER_MODE_POLY1305,

  /// OCB is an Authenticated Encryption with Associated Data (AEAD) block cipher mode, which is
  /// specified in RFC-7253. Supported tag lengths are 128, 96, and 64 bit with the default being
  /// 128 bit. To switch to a different tag length gcry_cipher_ctl using the command
  /// GCRYCTL_SET_TAGLEN and the address of an int variable set to 12 (for 96 bit) or 8 (for 64
  /// bit) provided for the buffer argument and sizeof(int) for buflen.
  ///
  /// Note that the use of gcry_cipher_final is required.
  Ocb = gcrypt_sys::GCRY_CIPHER_MODE_OCB,

  /// XEX-based tweaked-codebook mode with ciphertext stealing (XTS) mode is used to implement the
  /// AES-XTS as specified in IEEE 1619 Standard Architecture for Encrypted Shared Storage Media
  /// and NIST SP800-38E.
  ///
  /// The XTS mode requires doubling key-length, for example, using 512-bit key with AES-256
  /// (GCRY_CIPHER_AES256). The 128-bit tweak value is feed to XTS mode as little-endian byte array
  /// using gcry_cipher_setiv function. When encrypting or decrypting, full-sized data unit buffers
  /// needs to be passed to gcry_cipher_encrypt or gcry_cipher_decrypt. The tweak value is
  /// automatically incremented after each call of gcry_cipher_encrypt and gcry_cipher_decrypt.
  /// Auto-increment allows avoiding need of setting IV between processing of sequential data
  /// units.
  Xts = gcrypt_sys::GCRY_CIPHER_MODE_XTS,

  /// EAX is an Authenticated Encryption with Associated Data (AEAD) block cipher mode by Bellare,
  /// Rogaway, and Wagner ([see](http://web.cs.ucdavis.edu/~rogaway/papers/eax.html)).
  Eax = gcrypt_sys::GCRY_CIPHER_MODE_EAX,
}

impl Mode
{
  // #[inline]
  // pub(crate) fn from_raw(raw: i32) -> Option<Self>
  // {
  //   match raw as u32 {
  //     | gcrypt_sys::GCRY_CIPHER_MODE_ECB => Some(Self::Ecb),
  //     | gcrypt_sys::GCRY_CIPHER_MODE_CFB => Some(Self::Cfb),
  //     | gcrypt_sys::GCRY_CIPHER_MODE_CFB8 => Some(Self::Cfb8),
  //     | gcrypt_sys::GCRY_CIPHER_MODE_CBC => Some(Self::Cbc),
  //     | gcrypt_sys::GCRY_CIPHER_MODE_STREAM => Some(Self::Stream),
  //     | gcrypt_sys::GCRY_CIPHER_MODE_OFB => Some(Self::Ofb),
  //     | gcrypt_sys::GCRY_CIPHER_MODE_CTR => Some(Self::Ctr),
  //     | gcrypt_sys::GCRY_CIPHER_MODE_AESWRAP => Some(Self::AesWrap),
  //     | gcrypt_sys::GCRY_CIPHER_MODE_CCM => Some(Self::CCM),
  //     | gcrypt_sys::GCRY_CIPHER_MODE_GCM => Some(Self::Gcm),
  //     | gcrypt_sys::GCRY_CIPHER_MODE_POLY1305 => Some(Self::Poly1305),
  //     | gcrypt_sys::GCRY_CIPHER_MODE_OCB => Some(Self::Ocb),
  //     | gcrypt_sys::GCRY_CIPHER_MODE_XTS => Some(Self::Xts),
  //     | gcrypt_sys::GCRY_CIPHER_MODE_EAX => Some(Self::Eax),
  //     | _ => None,
  //   }
  // }

  #[inline]
  pub(crate) fn raw(&self) -> i32
  {
    *self as i32
  }
}

pub struct Flags(u32);

impl Flags
{
  pub const CBC_CTS: Self = Self(gcrypt_sys::GCRY_CIPHER_CBC_CTS);
  pub const CBC_MAC: Self = Self(gcrypt_sys::GCRY_CIPHER_CBC_MAC);
  pub const ENABLE_SYNC: Self = Self(gcrypt_sys::GCRY_CIPHER_ENABLE_SYNC);
  pub const NONE: Self = Self(0);
  pub const SECURE: Self = Self(gcrypt_sys::GCRY_CIPHER_SECURE);

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

pub struct Cipher(gcrypt_sys::gcry_cipher_hd_t);

impl Cipher
{
  #[inline]
  pub fn new(algo: Algorithm, mode: Mode, flags: Flags) -> Result<Self>
  {
    let mut inner = ptr::null_mut();
    let err = Error::from_raw(unsafe {
      gcrypt_sys::gcry_cipher_open(&mut inner, algo.raw(), mode.raw(), flags.raw())
    });
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
  pub fn set_key(&mut self, key: &[u8]) -> Result<()>
  {
    let err = Error::from_raw(unsafe {
      gcrypt_sys::gcry_cipher_setkey(self.0, key.as_ptr().cast(), key.len())
    });
    if err.is_error() { Err(err) } else { Ok(()) }
  }

  #[inline]
  pub fn set_iv(&mut self, iv: &[u8]) -> Result<()>
  {
    let err = Error::from_raw(unsafe {
      gcrypt_sys::gcry_cipher_setiv(self.0, iv.as_ptr().cast(), iv.len())
    });
    if err.is_error() { Err(err) } else { Ok(()) }
  }

  #[inline]
  pub fn set_ctr(&mut self, ctr: &[u8]) -> Result<()>
  {
    let err = Error::from_raw(unsafe {
      gcrypt_sys::gcry_cipher_setctr(self.0, ctr.as_ptr().cast(), ctr.len())
    });
    if err.is_error() { Err(err) } else { Ok(()) }
  }

  #[inline]
  pub fn get_tag(&self, tag: &mut [u8]) -> Result<()>
  {
    let err = Error::from_raw(unsafe {
      gcrypt_sys::gcry_cipher_gettag(self.0, tag.as_mut_ptr().cast(), tag.len())
    });
    if err.is_error() { Err(err) } else { Ok(()) }
  }

  #[inline]
  pub fn check_tag(&self, tag: &[u8]) -> Result<()>
  {
    let err = Error::from_raw(unsafe {
      gcrypt_sys::gcry_cipher_checktag(self.0, tag.as_ptr().cast(), tag.len())
    });
    if err.is_error() { Err(err) } else { Ok(()) }
  }

  #[inline]
  pub fn authenticate(&mut self, abuf: &[u8]) -> Result<()>
  {
    let err = Error::from_raw(unsafe {
      gcrypt_sys::gcry_cipher_authenticate(self.0, abuf.as_ptr().cast(), abuf.len())
    });
    if err.is_error() { Err(err) } else { Ok(()) }
  }

  #[inline]
  pub fn reset(self) -> Self
  {
    unsafe {
      gcrypt_sys::gcry_cipher_ctl(self.0, gcrypt_sys::GCRYCTL_RESET as _, ptr::null_mut(), 0)
    };
    self
  }

  #[inline]
  pub fn encrypt(&self, buffer: &mut [u8], input: Option<&[u8]>) -> Result<()>
  {
    let (inbuf, inlen) = match input {
      | None => (ptr::null(), 0),
      | Some(i) => (i.as_ptr().cast(), i.len()),
    };
    let err = Error::from_raw(unsafe {
      gcrypt_sys::gcry_cipher_encrypt(
        self.0,
        buffer.as_mut_ptr().cast(),
        buffer.len(),
        inbuf,
        inlen,
      )
    });
    if err.is_error() { Err(err) } else { Ok(()) }
  }

  #[inline]
  pub fn decrypt(&self, buffer: &mut [u8], input: Option<&[u8]>) -> Result<()>
  {
    let (inbuf, inlen) = match input {
      | None => (ptr::null(), 0),
      | Some(i) => (i.as_ptr().cast(), i.len()),
    };
    let err = Error::from_raw(unsafe {
      gcrypt_sys::gcry_cipher_decrypt(
        self.0,
        buffer.as_mut_ptr().cast(),
        buffer.len(),
        inbuf,
        inlen,
      )
    });
    if err.is_error() { Err(err) } else { Ok(()) }
  }
}

impl Drop for Cipher
{
  #[inline]
  fn drop(&mut self)
  {
    unsafe { gcrypt_sys::gcry_cipher_close(self.0) };
  }
}
