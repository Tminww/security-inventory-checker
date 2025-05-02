// system-agent/src/tracers/metrics.rs
use anyhow::{Context, Result};
use log::debug;
use std::fs;
use std::time::Instant;

use crate::models::{
    CpuMetrics, DiskMetrics, MemoryMetrics, NetworkMetrics, SystemMetrics,
};

/// Сборщик метрик системы
pub struct MetricsCollector {
    /// Момент времени последнего сбора метрик
    last_collection: Instant,
    /// Предыдущие значения счетчиков CPU
    prev_cpu: Option<(Vec<u64>, u64)>,
    /// Предыдущие значения счетчиков дисков
    prev_disk: Option<Vec<(String, u64, u64)>>,
    /// Предыдущие значения счетчиков сети
    prev_net: Option<Vec<(String, u64, u64)>>,
}

impl MetricsCollector {
    /// Создает новый экземпляр сборщика метрик
    pub fn new() -> Self {
        Self {
            last_collection: Instant::now(),
            prev_cpu: None,
            prev_disk: None,
            prev_net: None,
        }
    }

    /// Собирает метрики системы
    pub fn collect_metrics(&mut self) -> Result<SystemMetrics> {
        debug!("Сбор метрик системы...");

        // Получаем текущий момент времени
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_collection).as_secs_f64();
        self.last_collection = now;

        // Собираем метрики CPU
        let cpu_metrics = self.collect_cpu_metrics(elapsed)?;

        // Собираем метрики памяти
        let memory_metrics = self.collect_memory_metrics()?;

        // Собираем метрики диска
        let disk_metrics = self.collect_disk_metrics(elapsed)?;

        // Собираем метрики сети
        let network_metrics = self.collect_network_metrics(elapsed)?;

        // Возвращаем все метрики
        Ok(SystemMetrics {
            cpu: cpu_metrics,
            memory: memory_metrics,
            disk: disk_metrics,
            network: network_metrics,
            timestamp: chrono::Local::now().timestamp(),
        })
    }

    /// Собирает метрики CPU
    fn collect_cpu_metrics(&mut self, elapsed: f64) -> Result<CpuMetrics> {
        debug!("Сбор метрик CPU...");

        // Читаем данные из /proc/stat
        let stat = fs::read_to_string("/proc/stat").context("Не удалось прочитать /proc/stat")?;

        // Парсим данные CPU
        let mut cpu_times = Vec::new();
        let mut total_jiffies = 0;

        for line in stat.lines() {
            if line.starts_with("cpu ") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                // Пропускаем "cpu" и собираем все числа
                for part in parts.iter().skip(1) {
                    if let Ok(value) = part.parse::<u64>() {
                        cpu_times.push(value);
                        total_jiffies += value;
                    }
                }
                break;
            }
        }

        // Вычисляем загрузку CPU
        let mut usage = 0.0;
        let mut user = 0.0;
        let mut system = 0.0;
        let mut iowait = 0.0;
        let mut idle = 0.0;

        if let Some((prev_times, prev_total)) = &self.prev_cpu {
            if cpu_times.len() >= 4 && prev_times.len() >= 4 {
                let delta_total = total_jiffies - prev_total;
                if delta_total > 0 {
                    // user (индекс 0)
                    let delta_user = cpu_times[0] - prev_times[0];
                    user = delta_user as f64 / delta_total as f64 * 100.0;

                    // system (индекс 2)
                    let delta_system = cpu_times[2] - prev_times[2];
                    system = delta_system as f64 / delta_total as f64 * 100.0;

                    // idle (индекс 3)
                    let delta_idle = cpu_times[3] - prev_times[3];
                    idle = delta_idle as f64 / delta_total as f64 * 100.0;

                    // iowait (индекс 4, если доступен)
                    if cpu_times.len() > 4 && prev_times.len() > 4 {
                        let delta_iowait = cpu_times[4] - prev_times[4];
                        iowait = delta_iowait as f64 / delta_total as f64 * 100.0;
                    }

                    // Общая загрузка
                    usage = 100.0 - idle;
                }
            }
        }

        // Сохраняем текущие значения для следующего расчета
        self.prev_cpu = Some((cpu_times, total_jiffies));

        // Получаем информацию о нагрузке
        let loadavg = fs::read_to_string("/proc/loadavg")
            .context("Не удалось прочитать /proc/loadavg")?;
        let loadavg_parts: Vec<&str> = loadavg.split_whitespace().collect();
        
        let load1 = loadavg_parts
            .get(0)
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(0.0);
        
        let load5 = loadavg_parts
            .get(1)
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(0.0);
        
        let load15 = loadavg_parts
            .get(2)
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(0.0);

        Ok(CpuMetrics {
            usage,
            user,
            system,
            iowait,
            idle,
            load1,
            load5,
            load15,
        })
    }

    /// Собирает метрики памяти
    fn collect_memory_metrics(&self) -> Result<MemoryMetrics> {
        debug!("Сбор метрик памяти...");

        // Читаем данные из /proc/meminfo
        let meminfo = fs::read_to_string("/proc/meminfo")
            .context("Не удалось прочитать /proc/meminfo")?;

        // Извлекаем нужные значения
        let total = self.extract_memory_value(&meminfo, "MemTotal:");
        let free = self.extract_memory_value(&meminfo, "MemFree:");
        let available = self.extract_memory_value(&meminfo, "MemAvailable:");
        let buffers = self.extract_memory_value(&meminfo, "Buffers:");
        let cached = self.extract_memory_value(&meminfo, "Cached:");
        let swap_total = self.extract_memory_value(&meminfo, "SwapTotal:");
        let swap_free = self.extract_memory_value(&meminfo, "SwapFree:");

        // Вычисляем использованную память и своп
        let used = total.saturating_sub(free).saturating_sub(buffers).saturating_sub(cached);
        let swap_used = swap_total.saturating_sub(swap_free);

        // Вычисляем проценты использования
        let usage_percent = if total > 0 {
            (used as f64 / total as f64) * 100.0
        } else {
            0.0
        };

        let swap_percent = if swap_total > 0 {
            (swap_used as f64 / swap_total as f64) * 100.0
        } else {
            0.0
        };

        Ok(MemoryMetrics {
            total,
            used,
            free,
            available,
            buffers,
            cached,
            usage_percent,
            swap_total,
            swap_used,
            swap_free,
            swap_percent,
        })
    }

    /// Извлекает значение памяти из строки /proc/meminfo
    fn extract_memory_value(&self, meminfo: &str, key: &str) -> u64 {
        for line in meminfo.lines() {
            if line.starts_with(key) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(value) = parts[1].parse::<u64>() {
                        // Конвертируем KB в байты
                        return value * 1024;
                    }
                }
            }
        }
        0
    }

    /// Собирает метрики дисков
    fn collect_disk_metrics(&mut self, elapsed: f64) -> Result<Vec<DiskMetrics>> {
        debug!("Сбор метрик дисков...");

        // Читаем данные из /proc/diskstats
        let diskstats = fs::read_to_string("/proc/diskstats")
            .context("Не удалось прочитать /proc/diskstats")?;

        // Читаем информацию о точках монтирования
        let mounts = fs::read_to_string("/proc/mounts")
            .context("Не удалось прочитать /proc/mounts")?;

        let mut metrics = Vec::new();
        let mut current_stats = Vec::new();

        // Парсим данные дисковой статистики
        for line in diskstats.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 14 {
                continue;
            }

            // Интересуют только физические диски и разделы
            let device_name = parts[2];
            if !device_name.starts_with("sd") 
               && !device_name.starts_with("hd") 
               && !device_name.starts_with("vd") 
               && !device_name.starts_with("nvme") {
                continue;
            }

            // Извлекаем статистику
            let reads_completed = parts[3].parse::<u64>().unwrap_or(0);
            let sectors_read = parts[5].parse::<u64>().unwrap_or(0); // В секторах
            let writes_completed = parts[7].parse::<u64>().unwrap_or(0);
            let sectors_written = parts[9].parse::<u64>().unwrap_or(0); // В секторах

            // Сохраняем текущие значения
            current_stats.push((device_name.to_string(), sectors_read, sectors_written));

            // Вычисляем скорость чтения/записи (если есть предыдущие значения)
            let mut read_speed = 0.0;
            let mut write_speed = 0.0;

            if let Some(prev_stats) = &self.prev_disk {
                for (prev_name, prev_read, prev_write) in prev_stats {
                    if prev_name == device_name {
                        // Сектор = 512 байт
                        let delta_read_bytes = (sectors_read - prev_read) * 512;
                        let delta_write_bytes = (sectors_written - prev_write) * 512;

                        // Переводим в MБ/с
                        read_speed = delta_read_bytes as f64 / elapsed / 1024.0 / 1024.0;
                        write_speed = delta_write_bytes as f64 / elapsed / 1024.0 / 1024.0;
                        break;
                    }
                }
            }

            // Находим точку монтирования для этого устройства
            let mount_point = find_mount_point(&mounts, device_name);
            let usage = get_disk_usage(&mount_point);

            metrics.push(DiskMetrics {
                device: device_name.to_string(),
                mount_point,
                reads_completed,
                writes_completed,
                read_speed,
                write_speed,
                used_bytes: usage.0,
                total_bytes: usage.1,
                usage_percent: usage.2,
            });
        }

        // Сохраняем текущие значения для следующего расчета
        self.prev_disk = Some(current_stats);

        Ok(metrics)
    }

    /// Собирает метрики сети
    fn collect_network_metrics(&mut self, elapsed: f64) -> Result<Vec<NetworkMetrics>> {
        debug!("Сбор метрик сети...");

        // Читаем данные из /proc/net/dev
        let netdev = fs::read_to_string("/proc/net/dev")
            .context("Не удалось прочитать /proc/net/dev")?;

        let mut metrics = Vec::new();
        let mut current_stats = Vec::new();

        // Парсим данные сетевой статистики
        for line in netdev.lines().skip(2) { // Пропускаем заголовки
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() != 2 {
                continue;
            }

            let interface = parts[0].trim();
            // Пропускаем loopback и виртуальные интерфейсы
            if interface == "lo" || interface.contains("docker") || interface.contains("veth") {
                continue;
            }

            let stats: Vec<&str> = parts[1].split_whitespace().collect();
            if stats.len() < 16 {
                continue;
            }

            // Получаем статистику
            let bytes_recv = stats[0].parse::<u64>().unwrap_or(0);
            let packets_recv = stats[1].parse::<u64>().unwrap_or(0);
            let bytes_sent = stats[8].parse::<u64>().unwrap_or(0);
            let packets_sent = stats[9].parse::<u64>().unwrap_or(0);

            // Сохраняем текущие значения
            current_stats.push((interface.to_string(), bytes_recv, bytes_sent));

            // Вычисляем скорость приема/отправки
            let mut recv_speed = 0.0;
            let mut send_speed = 0.0;

            if let Some(prev_stats) = &self.prev_net {
                for (prev_iface, prev_recv, prev_sent) in prev_stats {
                    if prev_iface == interface {
                        let delta_recv = bytes_recv - prev_recv;
                        let delta_sent = bytes_sent - prev_sent;

                        // Переводим в MБ/с
                        recv_speed = delta_recv as f64 / elapsed / 1024.0 / 1024.0;
                        send_speed = delta_sent as f64 / elapsed / 1024.0 / 1024.0;
                        break;
                    }
                }
            }

            metrics.push(NetworkMetrics {
                interface: interface.to_string(),
                bytes_recv,
                bytes_sent,
                packets_recv,
                packets_sent,
                recv_speed,
                send_speed,
            });
        }

        // Сохраняем текущие значения для следующего расчета
        self.prev_net = Some(current_stats);

        Ok(metrics)
    }
}

/// Находит точку монтирования для устройства
fn find_mount_point(mounts: &str, device: &str) -> String {
    let device_path = format!("/dev/{}", device);
    
    for line in mounts.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 && parts[0] == device_path {
            return parts[1].to_string();
        }
    }
    
    String::from("")
}

/// Получает информацию об использовании диска
// fn get_disk_usage(mount_point: &str) -> (u64, u64, f64) {
//     if mount_point.is_empty() {
//         return (0, 0, 0.0);
//     }
    
//     // Используем statvfs для получения информации о файловой системе
//     match fs::metadata(mount_point) {
//         Ok(_) => {
//             // В реальном коде здесь следует использовать libc::statvfs
//             // Для простоты примера используем заглушку
//             let used_bytes = 0;