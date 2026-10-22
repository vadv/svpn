// musl's allocator is slow under multithreaded load; the router client is
// exactly that workload.
#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL_ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> std::process::ExitCode {
    svpn::main_entry()
}
