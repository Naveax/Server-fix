use std::net::SocketAddr;

use anyhow::{bail, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CriticalOverflowPolicy {
    #[default]
    DropNewest,
    Block,
}

#[derive(Debug, Clone)]
pub struct FbsGuardConfig {
    pub listen_addr: SocketAddr,
    pub upstream_addr: SocketAddr,
    pub max_frame_bytes: usize,
    pub telemetry_queue_capacity: usize,
    pub critical_queue_capacity: usize,
    pub critical_overflow_policy: CriticalOverflowPolicy,
    pub writer_delay_millis: u64,
}

impl FbsGuardConfig {
    pub fn validate(&self) -> Result<()> {
        if self.max_frame_bytes == 0 {
            bail!("max_frame_bytes must be > 0");
        }
        if self.telemetry_queue_capacity == 0 {
            bail!("telemetry_queue_capacity must be > 0");
        }
        if self.critical_queue_capacity == 0 {
            bail!("critical_queue_capacity must be > 0");
        }
        Ok(())
    }
}
