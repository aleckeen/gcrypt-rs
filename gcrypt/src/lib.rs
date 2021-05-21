#![feature(new_uninit)]

use std::ffi::{CStr, CString};
use std::ptr;

use gpgrt::Error;

pub mod cipher;
pub mod mac;
pub mod md;

pub use mac::Mac;
pub use md::Md;

pub type Result<T> = std::result::Result<T, Error>;

pub fn check_version(req_version: Option<&str>) -> Option<&str>
{
  let ver = match req_version {
    | Some(req_version) => {
      let cstr = CString::new(req_version).unwrap();
      unsafe { gcrypt_sys::gcry_check_version(cstr.as_ptr()) }
    }
    | None => unsafe { gcrypt_sys::gcry_check_version(ptr::null()) },
  };

  if ver.is_null() {
    None
  } else {
    Some(unsafe { CStr::from_ptr(ver) }.to_str().unwrap())
  }
}

pub struct Control;

impl Control
{
  pub fn disable_secure_memory() -> Result<()>
  {
    let err =
      Error::from_raw(unsafe { gcrypt_sys::gcry_control(gcrypt_sys::GCRYCTL_DISABLE_SECMEM) });
    if err.is_error() { Err(err) } else { Ok(()) }
  }

  pub fn initialization_finished() -> Result<()>
  {
    let err = Error::from_raw(unsafe {
      gcrypt_sys::gcry_control(gcrypt_sys::GCRYCTL_INITIALIZATION_FINISHED)
    });
    if err.is_error() { Err(err) } else { Ok(()) }
  }
}
