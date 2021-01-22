use procfs::{process, ProcError};
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::unistd::Pid;
use nix::Error;

#[derive(Debug)]
pub struct Injector {
    pid: i32,
    proc: process::Process,
    code: Vec<u8>,
}

impl Injector {
    pub fn new(target_pid: i32, shellcode: Vec<u8>) -> Result<Self, ProcError> {
        Ok(Injector {
            pid: target_pid,
            proc: process::Process::new(target_pid)?,
            code: shellcode,
        })
    }

    pub fn attach(&self) -> Result<(), Error> {
        ptrace::attach(Pid::from_raw(self.pid))
    }

    pub fn detach(&self) -> Result<(), Error> {
        ptrace::detach(Pid::from_raw(self.pid), Signal::SIGCONT)
    }
}
