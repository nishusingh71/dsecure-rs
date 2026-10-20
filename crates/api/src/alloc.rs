//! Global allocator: jemalloc on Linux only (ARCHITECTURE.md §12.2; Windows dev builds use the
//! system allocator, PHASE0_PROGRESS item 5). Tuning comes from `_RJEM_MALLOC_CONF` in the container
//! env (read by jemalloc itself at init; setting it from Rust would need `unsafe`, which is forbidden).

#[cfg(target_os = "linux")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;
