use common::HostInfo;
use std::error::Error;
use std::process::Command;

pub fn get_host_info() -> Result<HostInfo, Box<dyn Error>> {
    // Получение IP
    let ip_output = Command::new("ip")
        .args(&["-4", "addr", "show", "eth0"])
        .output()?;
    let ip_str = String::from_utf8(ip_output.stdout)?;
    let ip = ip_str
        .lines()
        .find(|line| line.contains("inet"))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|addr| addr.split('/').next())
        .unwrap_or("unknown")
        .to_string();

    // Получение MAC
    let mac_output = Command::new("cat")
        .arg("/sys/class/net/eth0/address")
        .output()?;
    let mac = String::from_utf8(mac_output.stdout)?.trim().to_string();

    Ok(HostInfo {
        mac_address: mac,
        ip_address: ip,
    })
}
