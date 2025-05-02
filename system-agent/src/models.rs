// system-agent/src/models.rs
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AgentData {
    /// Уникальный идентификатор отчета
    pub id: String,
    /// Время создания отчета
    pub timestamp: DateTime<Utc>,
    /// Имя хоста
    pub hostname: String,
    /// Информация о системе
    pub system_info: SystemInfo,
    /// Результаты статического анализа
    pub static_data: StaticAnalysisResult,
    /// Результаты динамического анализа
    pub dynamic_data: DynamicAnalysisResult,
}

impl Default for AgentData {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            hostname: hostname::get()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
            system_info: SystemInfo::default(),
            static_data: StaticAnalysisResult::default(),
            dynamic_data: DynamicAnalysisResult::default(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct SystemInfo {
    pub hostname: String,
    pub os_name: String,
    pub cpu_model: String,
    pub cpu_cores: u32,
    pub boot_time: DateTime<Utc>,
    /// Версия ОС
    pub os_version: String,
    /// Версия ядра
    pub kernel_version: String,
    /// Архитектура системы
    pub architecture: String,
    /// Общее количество RAM
    pub total_memory: u64,
    /// Количество CPU
    pub cpu_count: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct StaticAnalysisResult {
    /// Контейнеры (Docker/Podman)
    pub containers: Vec<ContainerConfig>,
    /// Systemd сервисы
    pub services: Vec<SystemdUnit>,
    // Правила файервола
    // pub firewall_rules: Vec<FirewallRule>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct DynamicAnalysisResult {
    /// Информация о процессах
    pub processes: Vec<ProcessInfo>,
    /// Сетевые соединения
    pub network_connections: Vec<NetworkConnection>,
    /// Записи логов
    pub logs: Vec<LogEntry>,
    /// Метрики системы
    pub metrics: SystemMetrics,
}

// --------- Модели для контейнеров ---------

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ContainerConfig {
    /// Идентификатор контейнера
    pub id: String,
    /// Имя контейнера
    pub name: String,
    /// Используемый образ
    pub image: String,
    /// Версия образа
    pub image_version: String,
    /// Открытые порты
    pub ports: Vec<PortMapping>,
    /// Тома
    pub volumes: Vec<VolumeMount>,
    /// Переменные окружения
    pub environment: HashMap<String, String>,
    /// Сетевые настройки
    pub network_mode: String,
    /// Ограничения ресурсов
    pub resource_limits: Option<ResourceLimits>,
    /// Путь к конфигурационному файлу
    pub config_path: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PortMapping {
    pub host_port: u16,
    pub container_port: u16,
    pub protocol: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VolumeMount {
    pub host_path: String,
    pub container_path: String,
    pub read_only: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ResourceLimits {
    pub cpu: Option<f64>,
    pub memory: Option<u64>,
}

// --------- Модели для Systemd юнитов ---------

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SystemdUnit {
    /// Имя юнита
    pub name: String,
    /// Описание
    pub description: String,
    /// Тип юнита (service, socket, etc.)
    pub unit_type: String,
    /// Путь до исполняемого файла (для сервисов)
    pub exec_path: Option<String>,
    /// Аргументы командной строки
    pub exec_args: Vec<String>,
    /// Пользователь, от имени которого запускается
    pub user: String,
    /// Группа
    pub group: String,
    /// Рабочая директория
    pub working_directory: Option<String>,
    /// Зависимости (After, Requires, Wants)
    pub dependencies: Vec<String>,
    /// Состояние (active, inactive, failed)
    pub state: String,
    /// Автозапуск (enabled, disabled, static)
    pub enabled: bool,
    /// Путь к unit-файлу
    pub unit_file_path: String,
}

// --------- Модели для файервола ---------

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FirewallRule {
    /// Тип файервола (iptables, nftables)
    pub firewall_type: String,
    /// Таблица (filter, nat, etc.)
    pub table: String,
    /// Цепочка (INPUT, OUTPUT, etc.)
    pub chain: String,
    /// Приоритет/позиция правила
    pub priority: i32,
    /// Тип действия (ACCEPT, DROP, etc.)
    pub action: String,
    /// Протокол (tcp, udp, all)
    pub protocol: Option<String>,
    /// Исходный адрес/подсеть
    pub source: Option<String>,
    /// Целевой адрес/подсеть
    pub destination: Option<String>,
    /// Исходный порт или диапазон
    pub source_port: Option<String>,
    /// Целевой порт или диапазон
    pub destination_port: Option<String>,
    /// Интерфейс
    pub interface: Option<String>,
    /// Строковое представление правила
    pub raw_rule: String,
}

// --------- Модели для процессов ---------

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProcessInfo {
    /// PID процесса
    pub pid: i32,
    /// Имя процесса
    pub name: String,
    /// Полный путь до исполняемого файла
    pub executable: String,
    /// Аргументы командной строки
    pub cmdline: Vec<String>,
    /// ID пользователя
    pub uid: u32,
    /// Имя пользователя
    pub username: String,
    /// Использование CPU (%)
    pub cpu_usage: f64,
    /// Использование памяти (КБ)
    pub memory_usage: u64,
    /// Состояние (R, S, D, Z, etc.)
    pub state: String,
    /// Время запуска
    pub start_time: DateTime<Utc>,
    /// Связан ли с контейнером
    pub container_id: Option<String>,
    /// Связан ли с systemd юнитом
    pub systemd_unit: Option<String>,
}

// --------- Модели для сетевых соединений ---------

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NetworkConnection {
    /// Протокол (TCP/UDP)
    pub protocol: String,
    /// Локальный адрес
    pub local_address: String,
    /// Локальный порт
    pub local_port: u16,
    /// Удаленный адрес
    pub remote_address: String,
    /// Удаленный порт
    pub remote_port: u16,
    /// Состояние (ESTABLISHED, LISTEN, etc.)
    pub state: String,
    /// PID связанного процесса
    pub pid: Option<i32>,
    /// Имя связанного процесса
    pub process_name: Option<String>,
    /// Связан ли с контейнером
    pub container_id: Option<String>,
    /// Интерфейс
    pub interface: Option<String>,
}

// --------- Модели для логов ---------

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LogEntry {
    /// Временная метка
    pub timestamp: DateTime<Utc>,
    /// Источник (syslog, journal, etc.)
    pub source: String,
    /// Уровень важности (INFO, WARN, ERROR, etc.)
    pub level: String,
    /// Сообщение
    pub message: String,
    /// Имя службы/приложения
    pub service: Option<String>,
    /// PID процесса
    pub pid: Option<i32>,
    /// Имя хоста
    pub hostname: String,
    /// Дополнительные поля
    pub metadata: HashMap<String, String>,
}

// --------- Модели для метрик ---------

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct SystemMetrics {
    /// Использование CPU (%)
    pub cpu_usage: f64,
    /// Использование CPU по ядрам (%)
    pub cpu_usage_per_core: Vec<f64>,
    /// Использование оперативной памяти (КБ)
    pub memory_used: u64,
    /// Свободная оперативная память (КБ)
    pub memory_free: u64,
    /// Использование дискового пространства (КБ)
    pub disk_usage: HashMap<String, DiskUsage>,
    /// Статистика сети (байт/с)
    pub network_stats: HashMap<String, NetworkStats>,
    /// Загрузка системы (1m, 5m, 15m)
    pub load_average: [f64; 3],
    /// Количество процессов
    pub process_count: u32,
    /// Количество открытых файловых дескрипторов
    pub open_files: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DiskUsage {
    pub total: u64,
    pub used: u64,
    pub free: u64,
    pub mount_point: String,
    pub fs_type: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NetworkStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
}
