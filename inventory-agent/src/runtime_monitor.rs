use common::{ConnectionInfo, ServiceInfo};
use std::error::Error;
use std::process::Command;

pub fn scan_services() -> Result<Vec<ServiceInfo>, Box<dyn Error>> {
    let output = Command::new("systemctl")
        .args(&["list-units", "--type=service", "--all", "--no-pager"])
        .output()?;
    let services = String::from_utf8(output.stdout)?
        .lines()
        .filter(|line| line.contains(".service"))
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 4 {
                Some(ServiceInfo {
                    name: fields[0].to_string(),
                    status: fields[3].to_string(),
                    unit_file: fields[1].to_string(),
                })
            } else {
                None
            }
        })
        .collect();
    Ok(services)
}

pub fn scan_network_connections() -> Result<Vec<ConnectionInfo>, Box<dyn Error>> {
    let output = Command::new("ss").args(&["-tunap"]).output()?;
    let lines = String::from_utf8(output.stdout)?
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 7 {
                let process_info = fields.get(6).unwrap_or(&"");
                let pid = process_info
                    .split(',')
                    .find(|s| s.starts_with("pid="))
                    .and_then(|s| s.strip_prefix("pid=").and_then(|p| p.parse::<u32>().ok()));

                Some(ConnectionInfo {
                    src_ip: fields[4].split(':').next().unwrap_or("unknown").to_string(),
                    src_port: fields[4]
                        .split(':')
                        .last()
                        .unwrap_or("0")
                        .parse()
                        .unwrap_or(0),
                    dst_ip: fields[5].split(':').next().unwrap_or("unknown").to_string(),
                    dst_port: fields[5]
                        .split(':')
                        .last()
                        .unwrap_or("0")
                        .parse()
                        .unwrap_or(0),
                    protocol: fields[0].to_string(),
                    process_id: pid,
                    container_id: None, // Будет заполнено позже
                })
            } else {
                None
            }
        })
        .collect();
    Ok(lines)
}
