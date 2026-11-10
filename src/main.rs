// Match pg_doorman's jemalloc defaults on every Linux build; see .cargo/config.toml.
#[cfg(target_os = "linux")]
#[global_allocator]
static GLOBAL_ALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn main() -> std::process::ExitCode {
    svpn::main_entry()
}
