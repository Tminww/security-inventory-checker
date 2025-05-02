pub mod analyzers;
pub mod collector;
pub mod communication;
pub mod models;
// pub mod parsers;
// pub mod tracers;
// pub mod utils;

pub use models::{
    AgentData, ContainerConfig, FirewallRule, LogEntry, NetworkConnection, ProcessInfo,
    SystemMetrics, SystemdUnit,
};

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
