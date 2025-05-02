// system-agent/src/collector.rs
use anyhow::{Context, Result};
use log::{debug, error, info, warn};
use std::path::PathBuf;
use std::time::SystemTime;
use tokio::time::{Duration, Instant};

use crate::analyzers::{
    docker::DockerAnalyzer, firewall::FirewallAnalyzer, systemd::SystemdAnalyzer,
};
use crate::models::{
    AgentData, ContainerConfig, DynamicAnalysisResult, FirewallRule, LogEntry, NetworkConnection,
    ProcessInfo, StaticAnalysisResult, SystemInfo, SystemMetrics, SystemdUnit,
};
use crate::tracers::{
    logs::LogTracer, metrics::MetricsCollector, network::NetworkTracer, process::ProcessTracer,
};
use crate::utils::system_info::get_system_info;

#[cfg(feature = "ebpf")]
use crate::tracers::ebpf::EbpfTracer;

/// Конфигурация коллектора данных
pub struct CollectorConfig {
    /// Корневая директория для сканирования
    pub root_path: PathBuf,
    /// Собирать данные о логах
    pub collect_logs: bool,
    /// Собирать метрики
    pub collect_metrics: bool,
    /// Собирать информацию о сети
    pub collect_network: bool,
    /// Собирать информацию о процессах
    pub collect_processes: bool,
    /// Подробный режим сканирования
    pub detailed_scan: bool,
}

/// Коллектор данных системы
pub struct Collector {
    config: CollectorConfig,
    docker_analyzer: DockerAnalyzer,
    systemd_analyzer: SystemdAnalyzer,
    firewall_analyzer: FirewallAnalyzer,
    process_tracer: ProcessTracer,
    network_tracer: NetworkTracer,
    log_tracer: LogTracer,
    metrics_collector: MetricsCollector,
    #[cfg(feature = "ebpf")]
    ebpf_tracer: Option<EbpfTracer>,
    last_static_scan: Instant,
    static_data: StaticAnalysisResult,
    system_info: SystemInfo,
}

impl Collector {
    pub fn new(config: CollectorConfig) -> Result<Self> {
        let docker_analyzer = DockerAnalyzer::new(&config.root_path);
        let systemd_analyzer = SystemdAnalyzer::new();
        let firewall_analyzer = FirewallAnalyzer::new();
        let process_tracer = ProcessTracer::new();
        let network_tracer = NetworkTracer::new();
        let log_tracer = LogTracer::new();
        let metrics_collector = MetricsCollector::new();

        #[cfg(feature = "ebpf")]
        let ebpf_tracer = if config.detailed_scan {
            match EbpfTracer::new() {
                Ok(tracer) => {
                    info!("eBPF трейсер успешно инициализирован");
                    Some(tracer)
                }
                Err(e) => {
                    warn!("Не удалось инициализировать eBPF трейсер: {}", e);
                    None
                }
            }
        } else {
            None
        };

        let system_info = get_system_info().context("Не удалось получить информацию о системе")?;

        Ok(Self {
            config,
            docker_analyzer,
            systemd_analyzer,
            firewall_analyzer,
            process_tracer,
            network_tracer,
            log_tracer,
            metrics_collector,
            #[cfg(feature = "ebpf")]
            ebpf_tracer,
            last_static_scan: Instant::now(),
            static_data: StaticAnalysisResult::default(),
            system_info,
        })
    }

    /// Собирает статические данные о системе
    pub fn collect_static_data(&mut self) -> Result<AgentData> {
        info!("Сбор статических данных системы...");

        // Сканирование Docker/Podman контейнеров
        debug!("Анализ Docker/Podman контейнеров...");
        let containers = self
            .docker_analyzer
            .scan_containers()
            .context("Ошибка при анализе контейнеров")?;

        // Сканирование Systemd юнитов
        debug!("Анализ Systemd юнитов...");
        let services = self
            .systemd_analyzer
            .scan_units()
            .context("Ошибка при анализе Systemd юнитов")?;

        // Сканирование правил файервола
        debug!("Анализ правил файервола...");
        let firewall_rules = self
            .firewall_analyzer
            .scan_rules()
            .context("Ошибка при анализе правил файервола")?;

        // Сохранение результатов статического анализа
        self.static_data = StaticAnalysisResult {
            containers,
            services,
            firewall_rules,
        };

        self.last_static_scan = Instant::now();

        // Создание отчета с данными
        let data = AgentData {
            static_data: self.static_data.clone(),
            system_info: self.system_info.clone(),
            ..AgentData::default()
        };

        info!("Статические данные собраны успешно");
        Ok(data)
    }

    /// Собирает динамические данные в реальном времени
    pub async fn collect_dynamic_data(&mut self) -> Result<DynamicAnalysisResult> {
        debug!("Сбор динамических данных системы...");

        // Сбор информации о процессах
        let processes = if self.config.collect_processes {
            debug!("Сбор информации о процессах...");
            self.process_tracer
                .collect_processes()
                .context("Ошибка при сборе информации о процессах")?
        } else {
            Vec::new()
        };

        // Сбор информации о сетевых соединениях
        let network_connections = if self.config.collect_network {
            debug!("Сбор информации о сетевых соединениях...");
            self.network_tracer
                .collect_connections()
                .context("Ошибка при сборе информации о сетевых соединениях")?
        } else {
            Vec::new()
        };

        // Сбор записей журнала
        let logs = if self.config.collect_logs {
            debug!("Сбор записей журнала...");
            self.log_tracer
                .collect_logs()
                .context("Ошибка при сборе записей журнала")?
        } else {
            Vec::new()
        };

        // Сбор метрик системы
        let metrics = if self.config.collect_metrics {
            debug!("Сбор метрик системы...");
            self.metrics_collector
                .collect_metrics()
                .context("Ошибка при сборе метрик системы")?
        } else {
            SystemMetrics::default()
        };

        // Сбор данных eBPF трейсера
        #[cfg(feature = "ebpf")]
        if let Some(tracer) = &mut self.ebpf_tracer {
            debug!("Сбор данных eBPF трейсера...");
            if let Err(e) = tracer.collect_events() {
                warn!("Ошибка при сборе данных eBPF трейсера: {}", e);
            }
        }

        // Обогащение данных (связывание процессов с контейнерами и т.д.)
        let processes = self.enrich_process_data(processes);
        let network_connections = self.enrich_network_data(network_connections);

        // Создание результата с динамическими данными
        let dynamic_data = DynamicAnalysisResult {
            processes,
            network_connections,
            logs,
            metrics,
        };

        debug!("Динамические данные собраны успешно");
        Ok(dynamic_data)
    }

    /// Собирает все данные (статические и динамические)
    pub async fn collect_all_data(&mut self) -> Result<AgentData> {
        // Проверяем, нужно ли обновить статические данные
        // (обновляем их каждые 15 минут)
        if self.last_static_scan.elapsed() > Duration::from_secs(15 * 60) {
            debug!("Обновление статических данных...");
            self.collect_static_data()?;
        }

        // Сбор динамических данных
        let dynamic_data = self.collect_dynamic_data().await?;

        // Создание полного отчета
        let data = AgentData {
            static_data: self.static_data.clone(),
            dynamic_data,
            system_info: self.system_info.clone(),
            ..AgentData::default()
        };

        Ok(data)
    }

    // ---- Вспомогательные методы ----

    /// Обогащает информацию о процессах данными о контейнерах и сервисах
    fn enrich_process_data(&self, processes: Vec<ProcessInfo>) -> Vec<ProcessInfo> {
        let mut enriched_processes = Vec::with_capacity(processes.len());

        for mut process in processes {
            // Связывание с контейнерами
            process.container_id = self.find_container_for_process(&process);

            // Связывание с systemd юнитами
            process.systemd_unit = self.find_unit_for_process(&process);

            enriched_processes.push(process);
        }

        enriched_processes
    }

    /// Обогащает информацию о сетевых соединениях данными о процессах и контейнерах
    fn enrich_network_data(&self, connections: Vec<NetworkConnection>) -> Vec<NetworkConnection> {
        let mut enriched_connections = Vec::with_capacity(connections.len());

        for mut connection in connections {
            // Если PID уже известен, находим информацию о процессе
            if let Some(pid) = connection.pid {
                // Находим имя процесса
                if connection.process_name.is_none() {
                    connection.process_name = self.find_process_name_by_pid(pid);
                }

                // Связываем с контейнером
                if connection.container_id.is_none() {
                    connection.container_id = self.find_container_by_pid(pid);
                }
            }

            enriched_connections.push(connection);
        }

        enriched_connections
    }

    /// Находит контейнер, которому принадлежит процесс
    fn find_container_for_process(&self, process: &ProcessInfo) -> Option<String> {
        // Простая эвристика: проверяем cgroups процесса на принадлежность к контейнеру
        // В реальной реализации нужно будет анализировать cgroups или namespaces

        // Заглушка для примера
        // В реальной реализации здесь должен быть код
        None
    }

    /// Находит systemd юнит, которому принадлежит процесс
    fn find_unit_for_process(&self, process: &ProcessInfo) -> Option<String> {
        // Ищем юнит по исполняемому файлу и PID
        for unit in &self.static_data.services {
            if let Some(exec_path) = &unit.exec_path {
                if exec_path == &process.executable {
                    return Some(unit.name.clone());
                }
            }
        }

        // Дополнительная проверка: проверяем, принадлежит ли процесс какому-либо юниту
        // через systemd API или через интерфейс файловой системы /proc
        None
    }

    /// Находит имя процесса по PID
    fn find_process_name_by_pid(&self, pid: i32) -> Option<String> {
        // Ищем процесс в кэше собранных процессов
        for process in &self.process_tracer.cached_processes {
            if process.pid == pid {
                return Some(process.name.clone());
            }
        }

        // Если не нашли в кэше, читаем из /proc/{pid}/comm
        std::fs::read_to_string(format!("/proc/{}/comm", pid))
            .map(|name| name.trim().to_string())
            .ok()
    }

    /// Находит контейнер по PID процесса
    fn find_container_by_pid(&self, pid: i32) -> Option<String> {
        // Ищем процесс в кэше собранных процессов
        for process in &self.process_tracer.cached_processes {
            if process.pid == pid {
                return process.container_id.clone();
            }
        }

        None
    }
}
