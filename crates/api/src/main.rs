//! dsecure-api binary. All wiring is in `api::startup` (exit 78 on config errors).

mod alloc;

fn main() -> std::process::ExitCode {
    api::startup::main_entry()
}
