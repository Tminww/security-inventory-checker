use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct HostInfo {
    pub mac_address: String,
    pub ip_address: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ContainerInfo {
    pub id: String,
    pub name: String,
    pub image: String,
    pub ports: Vec<String>,
    pub status: String,
    pub orchestrator: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ServiceInfo {
    pub name: String,
    pub status: String,
    pub unit_file: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ConnectionInfo {
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub protocol: String,
    pub process_id: Option<u32>,
    pub container_id: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Report {
    pub host: HostInfo,
    pub timestamp: String,
    pub containers: Vec<ContainerInfo>,
    #[serde(default)]
    pub services: Vec<ServiceInfo>,
    #[serde(default)]
    pub connections: Vec<ConnectionInfo>,
}
