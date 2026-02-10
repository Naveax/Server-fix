pub mod codec;
pub mod config;
pub mod guard;

pub use config::{CriticalOverflowPolicy, FbsGuardConfig};
pub use guard::run_fbs_guard;
