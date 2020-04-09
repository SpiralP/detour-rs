use crate::error::{Error, Result};
use crate::{alloc, arch, util};
use detours_sys::*;
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, Ordering};
use std::{mem, os::raw::c_void};
use winapi::um::processthreadsapi::GetCurrentThread;

#[derive(Debug)]
pub struct Detour {
  enabled: AtomicBool,
  trampoline: Cell<*const ()>,
  target: *const (),
  detour: *const (),
}

fn try_error(result: LONG) -> Result<()> {
  if result == 0 {
    Ok(())
  } else {
    Err(Error::MicrosoftDetours(result))
  }
}

impl Detour {
  pub fn new(target: *const (), detour: *const ()) -> Result<Self> {
    if target == detour {
      return Err(Error::SameAddress);
    }

    if !util::is_executable_address(target)? || !util::is_executable_address(detour)? {
      return Err(Error::NotExecutable);
    }

    Ok(Self {
      enabled: AtomicBool::new(false),
      trampoline: Cell::new(std::ptr::null()),
      target,
      detour,
    })
  }

  pub fn is_enabled(&self) -> bool {
    self.enabled.load(Ordering::SeqCst)
  }

  pub unsafe fn enable(&self) -> Result<()> {
    if self.enabled.load(Ordering::SeqCst) {
      return Ok(());
    }

    let mut trampoline = self.target as *mut c_void;

    try_error(DetourTransactionBegin())?;
    try_error(DetourUpdateThread(GetCurrentThread()))?;
    try_error(DetourAttach(&mut trampoline, self.detour as *mut c_void))?;
    try_error(DetourTransactionCommit())?;

    self.trampoline.set(trampoline as *const ());

    self.enabled.store(true, Ordering::SeqCst);

    Ok(())
  }

  pub unsafe fn disable(&self) -> Result<()> {
    if !self.enabled.load(Ordering::SeqCst) {
      return Ok(());
    }

    let mut trampoline = self.trampoline() as *const _ as *mut c_void;

    try_error(DetourTransactionBegin())?;
    try_error(DetourUpdateThread(GetCurrentThread()))?;
    try_error(DetourDetach(&mut trampoline, self.detour as *mut c_void))?;
    try_error(DetourTransactionCommit())?;

    self.trampoline.set(std::ptr::null());

    self.enabled.store(false, Ordering::SeqCst);

    Ok(())
  }

  pub fn trampoline(&self) -> &() {
    unsafe {
      self
        .trampoline
        .get()
        .as_ref()
        .expect("trampoline should not be null")
    }
  }
}

impl Drop for Detour {
  /// Disables the detour, if enabled.
  fn drop(&mut self) {
    debug_assert!(unsafe { self.disable().is_ok() });
  }
}
