# PIG
Process Injection Gear.

## about
### at first
get target process's memory mapping from `proc/{{PID}}/maps`.

### next
attach the process by using `ptrace`.

### inject
write any code(for example, shellcode.) by `PTRACE_POKETEXT`.

### pwned!
use `PTRACE_CONT` to restart the process, and it's yours now!
