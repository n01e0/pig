use procfs::process::Process;
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::unistd::Pid;
use nix::Error;

pub use procfs::ProcError;
pub use libc::user_regs_struct;

#[derive(Debug)]
pub struct Injector {
    pid: Pid,
    proc: Process,
    code: Vec<u8>,
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
}
