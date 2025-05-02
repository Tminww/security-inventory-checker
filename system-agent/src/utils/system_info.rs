// system-agent/src/utils/system_info.rs
use anyhow::{Context, Result};
use chrono::{DateTime, TimeZone, Utc};
use log::debug;
use std::fs;
use std::process::Command;

use crate::models::SystemInfo;

/// Получает информацию о системе
pub fn get_system_info() -> Result<SystemInfo> {
    debug!("Сбор информации о системе...");

    // Получаем имя хоста
    let hostname = fs::read_to_string("/etc/hostname")
        .context("Не удалось прочитать /etc/hostname")?
        .trim()
        .to_string();

    // Получаем информацию о версии ОС
    let os_release =
        fs::read_to_string("/etc/os-release").context("Не удалось прочитать /etc/os-release")?;

    let os_name =
        extract_os_release_value(&os_release, "NAME").unwrap_or_else(|| "Unknown".to_string());

    let os_version = extract_os_release_value(&os_release, "VERSION_ID")
        .unwrap_or_else(|| "Unknown".to_string());

    // Получаем информацию о ядре
    let kernel = Command::new("uname")
        .arg("-r")
        .output()
        .context("Не удалось выполнить команду uname")?;

    let kernel_version = String::from_utf8_lossy(&kernel.stdout).trim().to_string();

    // Получаем информацию об архитектуре
    let arch = Command::new("uname")
        .arg("-m")
        .output()
        .context("Не удалось выполнить команду uname для получения архитектуры")?;

    let architecture = String::from_utf8_lossy(&arch.stdout).trim().to_string();

    // Получаем информацию о CPU
    let cpu_info =
        fs::read_to_string("/proc/cpuinfo").context("Не удалось прочитать /proc/cpuinfo")?;

    let cpu_model = extract_cpu_model(&cpu_info).unwrap_or_else(|| "Unknown CPU".to_string());

    let cpu_cores = extract_cpu_cores(&cpu_info).unwrap_or(1);

    // Получаем информацию о памяти
    let mem_info =
        fs::read_to_string("/proc/meminfo").context("Не удалось прочитать /proc/meminfo")?;

    let total_memory = extract_memory_value(&mem_info, "MemTotal").unwrap_or(0);

    // Сборка финальной структуры
    Ok(SystemInfo {
        hostname,
        os_name,
        os_version,
        kernel_version,
        architecture,
        cpu_model,
        cpu_cores,
        boot_time: Utc.timestamp(get_boot_time()? as i64, 0),
        total_memory,
        cpu_count: cpu_cores, // Assuming cpu_cores represents the CPU count
    })
}

/// Извлекает значение из файла /etc/os-release
fn extract_os_release_value(content: &str, key: &str) -> Option<String> {
    for line in content.lines() {
        if line.starts_with(&format!("{}=", key)) {
            let value = line.splitn(2, '=').nth(1)?;
            // Удаляем кавычки, если они есть
            return Some(value.trim_matches('"').to_string());
        }
    }
    None
}

/// Извлекает модель CPU из файла /proc/cpuinfo
fn extract_cpu_model(content: &str) -> Option<String> {
    for line in content.lines() {
        if line.starts_with("model name") || line.starts_with("Model") {
            let value = line.splitn(2, ':').nth(1)?;
            return Some(value.trim().to_string());
        }
    }
    None
}

/// Извлекает количество ядер CPU из файла /proc/cpuinfo
fn extract_cpu_cores(content: &str) -> Option<u32> {
    let mut count = 0;
    for line in content.lines() {
        if line.starts_with("processor") {
            count += 1;
        }
    }
    if count > 0 {
        Some(count)
    } else {
        None
    }
}

/// Извлекает значение памяти из файла /proc/meminfo
fn extract_memory_value(content: &str, key: &str) -> Option<u64> {
    for line in content.lines() {
        if line.starts_with(key) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                return parts[1].parse::<u64>().ok();
            }
        }
    }
    None
}

/// Получает время загрузки системы
fn get_boot_time() -> Result<u64> {
    let uptime = fs::read_to_string("/proc/uptime").context("Не удалось прочитать /proc/uptime")?;

    let uptime_secs = uptime
        .split_whitespace()
        .next()
        .context("Некорректный формат /proc/uptime")?
        .parse::<f64>()
        .context("Не удалось преобразовать uptime в число")?;

    // Получаем текущее время в секундах с начала эпохи
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("Не удалось получить текущее время")?
        .as_secs();

    // Вычитаем uptime, чтобы получить время загрузки
    Ok(now - uptime_secs as u64)
}
