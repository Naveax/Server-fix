#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficLane {
    Telemetry,
    Critical,
}

impl TrafficLane {
    pub fn as_label(self) -> &'static str {
        match self {
            Self::Telemetry => "telemetry",
            Self::Critical => "critical",
        }
    }
}

pub fn classify_lane(payload: &[u8], telemetry_prefixes: &[Vec<u8>]) -> TrafficLane {
    if telemetry_prefixes
        .iter()
        .any(|prefix| payload.starts_with(prefix))
    {
        TrafficLane::Telemetry
    } else {
        TrafficLane::Critical
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_telemetry_by_prefix() {
        let prefixes = vec![b"TEL:".to_vec()];
        assert_eq!(
            classify_lane(b"TEL:spam", &prefixes),
            TrafficLane::Telemetry
        );
        assert_eq!(
            classify_lane(b"CRIT:data", &prefixes),
            TrafficLane::Critical
        );
    }
}
