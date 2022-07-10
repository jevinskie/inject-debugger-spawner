# inject-debugger-spawner
A library to inject via LD_PRELOAD to spawn a new terminal with an attached debugger.

Useful to debug issues in processes that

1. Are deeply nested in a subprocess tree like when using build tools or,
the impetus for this project, using Questa's `vsim` simulator which
ultimately spawns a `vsimk` kernel that loads a buggy plugin.
2. Are not long-running so attaching manually via PID is impossible or a hassle.

## Requirements
```
apt install cmake g++ libboost-dev make
```

## Building
```
cmake -S . -B build
cmake --build build
```

## Examples / Testing
### Basic
Spawn a debugger immediately and pause near the beginning of the process.
```
LD_PRELOAD=build/lib/libinjdbgspawn.so DBG_IMM=1 DBG_BREAK=1 ./build/test/simple

hello from simple
```
Enter `continue` in GDB to continue execution.

### Subprocesses
Spawn a debugger once an executable matching the regex `s.mpl` is executed and pause near the beginning of the process.
```
LD_PRELOAD=build/lib/libinjdbgspawn.so DBG_PAT=s.mpl DBG_BREAK=1 ./build/test/subproc

hello from subproc parent
hello from simple
goodbyte from subproc parent - child exited
```
Enter `continue` in GDB to continue execution of the `simple` subprocess.

### Custom debugger
Spawn LLDB immediately and pause near the beginning of the process. `%PID` is substituted with process ID.
```
LD_PRELOAD=build/lib/libinjdbgspawn.so DBG_IMM=1 DBG_BREAK=1 \
DBG_SPAWN="gnome-terminal -- lldb -p %PID -o 'c'" ./build/test/simple

hello from simple
```
Enter `continue` in LLDB to continue execution.

## Environment Variables

### `DBG_BREAK`
Set to `1` if you want the injected library to issue a debug trap instruction, pausing the debugger near the beginning of the process.
If unset or `0`, the trap instruction is skipped and the debugger does not pause.

### `DBG_IMM`
Set to `1` if you want the debugger to launch immediately instead of matching a particular executable path.
If unset or `0`, `DBG_PAT` must be set.

### `DBG_PAT`
A regex that is checked against every process/subprocess to determine if the debugger should be spawned. Required if `DBG_IMM` is unset or `0`.


### `DBG_SPAWN`
The command to execute once the matching process is executed. `%PID` is is substituted with the target process ID.
Defaults to `gnome-terminal -- gdb -p %PID -ex "handle SIGINT nostop noprint pass" -ex "handle SIG41 nostop noprint pass" -ex "continue"`

## Notes
Works on Linux only right now but it could be ported to macOS without much effort and to Windows with some more effort.
