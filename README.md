kronos
Prerequisites
Install bpf-linker: cargo install bpf-linker
Build & Run
Use cargo build, cargo check, etc. as normal. Run your program with xtask run.

Cargo build scripts are used to automatically build the eBPF correctly and include it in the program. When not using xtask run, eBPF code generation is skipped for a faster developer experience; this compromise necessitates the use of xtask to actually build the eBPF.

Environment: 
- Kronos uses BPF-LSM for enforcing MAC at runtime so the kernel should have support for BPF as well as BPF-LSM. Kronos currently supports cgroupfs as cgroupdriver for kubernetes so set - 
- cgroupfs as cgroup driver in your cluster. Kronos deployment artifacts can be found in the config directory.

