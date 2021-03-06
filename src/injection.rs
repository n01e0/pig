use bytes::Buf;
use nix::sys::ptrace;
use nix::unistd::Pid;
use procfs::process::{MemoryMap, Process};
use std::ffi::c_void;
use std::fmt;

pub use libc::user_regs_struct;
pub use nix::Error;
pub use procfs::ProcError;

#[derive(Debug)]
pub struct Injector {
    pid: Pid,
    proc: Process,
    code: Vec<u8>,
}

#[derive(Debug)]
pub enum InjectorError {
    CanNotCreate(ProcError),
    CanNotAttach(Error),
    CanNotCont(Error),
    CanNotGetRegister(Error),
    CanNotSetRegister(Error),
    CanNotGetMemoryMap(ProcError),
    CanNotInjectCode(Error),
}

impl fmt::Display for InjectorError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use InjectorError::*;
        match self {
            CanNotCreate(e) => write!(f, "Can't create Injector object (maybe invalid pid)\n{}", e),
            CanNotAttach(e) => write!(f, "Can't attach the process.\n{}", e),
            CanNotCont(e) => write!(f, "Can't continue the process.\n{}", e),
            CanNotGetRegister(e) => write!(f, "Can't get register from the process.\n{}", e),
            CanNotSetRegister(e) => write!(f, "Can't set register to the process.\n{}", e),
            CanNotGetMemoryMap(e) => write!(f, "Can't get the process memory mapping.\n{}", e),
            CanNotInjectCode(e) => write!(f, "Can't inject to the process.\n{}", e),
        }
    }
}

impl Injector {
    pub fn new(target_pid: i32, shellcode: Vec<u8>) -> Result<Self, InjectorError> {
        match Process::new(target_pid) {
            Ok(p) => Ok(Injector {
                pid: Pid::from_raw(target_pid),
                proc: p,
                code: shellcode,
            }),
            Err(e) => Err(InjectorError::CanNotCreate(e)),
        }
    }

    pub fn attach(&self) -> Result<(), InjectorError> {
        ptrace::attach(self.pid).map_err(|e| InjectorError::CanNotAttach(e))
    }

    fn cont(&self) -> Result<(), InjectorError> {
        ptrace::cont(self.pid, None).map_err(|e| InjectorError::CanNotCont(e))
    }

    fn get_regs(&self) -> Result<user_regs_struct, InjectorError> {
        ptrace::getregs(self.pid).map_err(|e| InjectorError::CanNotGetRegister(e))
    }

    fn set_regs(&self, regs: user_regs_struct) -> Result<(), InjectorError> {
        ptrace::setregs(self.pid, regs).map_err(|e| InjectorError::CanNotSetRegister(e))
    }

    fn set_rip(&self, rip: u64) -> Result<(), InjectorError> {
        let mut regs = self.get_regs()?;
        regs.rip = rip;
        self.set_regs(regs)
    }

    fn get_writable_map(&self) -> Result<Option<MemoryMap>, InjectorError> {
        let mut maps = self
            .proc
            .maps()
            .map_err(|e| InjectorError::CanNotGetMemoryMap(e))?
            .into_iter()
            .filter(|m| {
                m.perms == "r-xp" /*&& (m.address.1 - m.address.0) as usize >= self.code.len()*/
            })
            .collect::<Vec<MemoryMap>>();
        maps.reverse();
        Ok(maps.pop())
    }

    fn inject_code(&self, addr: u64) -> Result<(), InjectorError> {
        let mut addr = addr;
        let mut code = &self.aligned_code()[..];
        for _ in 0..(code.len() / 8) {
            let c = code.get_u64_le();
            let b = Box::new(c);
            let b = Box::into_raw(b) as *mut c_void;
            unsafe {
                ptrace::write(self.pid, addr as ptrace::AddressType, b)
                    .map_err(|e| InjectorError::CanNotInjectCode(e))?;
            }
            println!("[+] writing 0x{:x} to 0x{:x}", c, addr);
            addr += 8;
        }
        Ok(())
    }

    fn aligned_code(&self) -> Vec<u8> {
        let mut code = self.code.clone();
        if code.len() / 8 != 0 {
            for _ in 0..(code.len() % 8) + 1 {
                code.push(0x90);
            }
        }
        code
    }

    pub fn inject(&self, verbose: bool) -> Result<(), InjectorError> {
        self.attach()?;
        if verbose {
            println!("[+] attached to the process {}", self.pid.as_raw());
        }
        if let Some(map) = self.get_writable_map()? {
            let addr = map.address.0;
            if verbose {
                println!("[+] got writable memory map at 0x{:x}", addr);
            }
            self.inject_code(addr)?;
            if verbose {
                println!("[+] injected code");
            }
            self.set_rip(addr)?;
            if verbose {
                println!("[+] jump to the code");
            }
            self.cont()?;
        }
        Ok(())
    }
}
