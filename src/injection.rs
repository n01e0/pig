use nix::sys::ptrace;
use nix::sys::signal::Signal;
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
    CanNotDetach(Error),
    CanNotGetRegister(Error),
    CanNotSetRegister(Error),
    CanNotSetRIP(Error),
    CanNotGetMemoryMap(ProcError),
    CanNotInjectCode(Error),
}

impl fmt::Display for InjectorError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use InjectorError::*;
        match self {
            CanNotCreate(e) => write!(f, "Can't create Injector object (maybe invalid pid)\n{}", e),
            CanNotAttach(e) => write!(f, "Can't attach the process.\n{}", e),
            CanNotDetach(e) => write!(f, "Can't detach from process.\n{}", e),
            CanNotGetRegister(e) => write!(f, "Can't get register from the process.\n{}", e),
            CanNotSetRegister(e) => write!(f, "Can't set register to the process.\n{}", e),
            CanNotSetRIP(e) => write!(f, "Can't set rip to the process.\n{}", e),
            CanNotGetMemoryMap(e) => write!(f, "Can't get the process memory mapping.\n{}", e),
            CanNotInjectCode(e) => write!(f, "Can't inject to the process.\n{}", e),
        }
    }
}

impl Injector {
    pub fn new(target_pid: i32, shellcode: Vec<u8>) -> Result<Self, ProcError> {
        Ok(Injector {
            pid: Pid::from_raw(target_pid),
            proc: Process::new(target_pid)?,
            code: shellcode,
        })
    }

    pub fn attach(&self) -> Result<(), Error> {
        ptrace::attach(self.pid)
    }

    pub fn detach(&self) -> Result<(), Error> {
        ptrace::detach(self.pid, Signal::SIGCONT)
    }

    fn get_regs(&self) -> Result<user_regs_struct, Error> {
        ptrace::getregs(self.pid)
    }

    fn set_regs(&self, regs: user_regs_struct) -> Result<(), Error> {
        ptrace::setregs(self.pid, regs)
    }

    fn set_rip(&self, rip: u64) -> Result<(), Error> {
        let mut regs = self.get_regs()?;
        regs.rip = rip;
        self.set_regs(regs)
    }

    fn get_writable_map(&self) -> Result<Option<MemoryMap>, ProcError> {
        let mut maps = self
            .proc
            .maps()?
            .into_iter()
            .filter(|m| {
                m.perms == "r-xp" && (m.address.1 - m.address.0) as usize >= self.code.len()
            })
            .collect::<Vec<MemoryMap>>();
        maps.reverse();
        Ok(maps.pop())
    }

    fn inject_code(
        &self,
        addr: u64,
    ) -> Result<(), Error> {
        for (i, byte) in self.code.iter().enumerate() {
            unsafe {
                ptrace::write(self.pid, (addr + i as u64) as ptrace::AddressType, *byte as *mut c_void)?
            }
        }
        Ok(())
    }
}
