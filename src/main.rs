// musl's allocator is slow under multithreaded load; the router client is
// exactly that workload (see docs/PERF-BUFFERS.md).
#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL_ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> std::process::ExitCode {
    svpn::main_entry()
}
