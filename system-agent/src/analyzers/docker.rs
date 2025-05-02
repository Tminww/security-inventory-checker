use anyhow::{Context, Result};
use log::{debug, warn};
use serde_yaml::Value;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::models::{ContainerConfig, PortMapping, ResourceLimits, VolumeMount};
use crate::parsers::docker::parse_dockerfile;

/// Анализатор Docker/Podman конфигураций
pub struct DockerAnalyzer {
    /// Корневая директория для сканирования
    root_path: PathBuf,
}

impl DockerAnalyzer {
    /// Создает новый анализатор Docker
    pub fn new(root_path: &Path) -> Self {
        Self {
            root_path: root_path.to_path_buf(),
        }
    }

    /// Сканирует конфигурации контейнеров
    pub fn scan_containers(&self) -> Result<Vec<ContainerConfig>> {
        debug!(
            "Начало сканирования контейнеров в директории: {}",
            self.root_path.display()
        );

        let mut configs = Vec::new();

        // Поиск и анализ docker-compose.yml файлов
        let compose_files = self.find_compose_files()?;
        for file_path in compose_files {
            debug!("Анализ docker-compose файла: {}", file_path.display());
            match self.parse_compose_file(&file_path) {
                Ok(mut container_configs) => {
                    debug!(
                        "Обнаружено {} контейнеров в файле {}",
                        container_configs.len(),
                        file_path.display()
                    );
                    configs.append(&mut container_configs);
                }
                Err(e) => {
                    warn!(
                        "Ошибка при анализе docker-compose файла {}: {}",
                        file_path.display(),
                        e
                    );
                }
            }
        }

        // Поиск и анализ Dockerfile файлов
        let dockerfiles = self.find_dockerfiles()?;
        for file_path in dockerfiles {
            debug!("Анализ Dockerfile: {}", file_path.display());
            match parse_dockerfile(&file_path) {
                Ok(container_config) => {
                    debug!(
                        "Обнаружена конфигурация контейнера в файле {}",
                        file_path.display()
                    );
                    configs.push(container_config);
                }
                Err(e) => {
                    warn!(
                        "Ошибка при анализе Dockerfile {}: {}",
                        file_path.display(),
                        e
                    );
                }
            }
        }

        // Удаление дубликатов и нормализация
        self.deduplicate_and_normalize(&mut configs);

        debug!(
            "Сканирование контейнеров завершено, найдено {} контейнеров",
            configs.len()
        );
        Ok(configs)
    }

    /// Ищет docker-compose.yml файлы
    fn find_compose_files(&self) -> Result<Vec<PathBuf>> {
        // В реальном приложении здесь должен быть рекурсивный поиск
        // или использование fd/find

        // Заглушка для примера
        let common_paths = vec![
            self.root_path.join("docker-compose.yml"),
            self.root_path.join("docker-compose.yaml"),
            self.root_path.join("compose.yml"),
            self.root_path.join("compose.yaml"),
        ];

        let mut found_files = Vec::new();
        for path in common_paths {
            if path.exists() && path.is_file() {
                found_files.push(path);
            }
        }

        Ok(found_files)
    }

    /// Ищет Dockerfile файлы
    fn find_dockerfiles(&self) -> Result<Vec<PathBuf>> {
        // В реальном приложении здесь должен быть рекурсивный поиск
        // или использование fd/find

        // Заглушка для примера
        let dockerfile_path = self.root_path.join("Dockerfile");
        let mut found_files = Vec::new();

        if dockerfile_path.exists() && dockerfile_path.is_file() {
            found_files.push(dockerfile_path);
        }

        Ok(found_files)
    }

    /// Парсит docker-compose файл
    fn parse_compose_file(&self, file_path: &Path) -> Result<Vec<ContainerConfig>> {
        let content = fs::read_to_string(file_path)
            .context(format!("Не удалось прочитать файл {}", file_path.display()))?;

        let yaml: Value = serde_yaml::from_str(&content).context(format!(
            "Ошибка парсинга YAML в файле {}",
            file_path.display()
        ))?;

        // Извлекаем сервисы из docker-compose
        let services = match yaml.get("services") {
            Some(services) => services,
            None => {
                warn!("В файле {} не найдена секция services", file_path.display());
                return Ok(Vec::new());
            }
        };

        let services_map = match services.as_mapping() {
            Some(map) => map,
            None => {
                warn!(
                    "Секция services в файле {} не является объектом",
                    file_path.display()
                );
                return Ok(Vec::new());
            }
        };

        let mut container_configs = Vec::new();

        // Обрабатываем каждый сервис
        for (service_name, service_config) in services_map {
            let service_name = match service_name.as_str() {
                Some(name) => name,
                None => continue,
            };

            let service_config = match service_config.as_mapping() {
                Some(config) => config,
                None => continue,
            };

            // Извлекаем образ
            let image = match service_config.get(&Value::String("image".to_string())) {
                Some(image) => match image.as_str() {
                    Some(image_str) => image_str,
                    None => continue,
                },
                None => continue,
            };

            // Парсим image и tag
            let (image_name, image_version) = parse_image_string(image);

            // Извлекаем порты
            let ports = extract_ports(service_config);

            // Извлекаем тома
            let volumes = extract_volumes(service_config);

            // Извлекаем переменные окружения
            let environment = extract_environment(service_config);

            // Извлекаем настройки сети
            let network_mode = extract_network_mode(service_config);

            // Извлекаем ограничения ресурсов
            let resource_limits = extract_resource_limits(service_config);

            // Создаем конфигурацию контейнера
            let container_config = ContainerConfig {
                id: format!("docker_{}", service_name),
                name: service_name.to_string(),
                image: image_name,
                image_version,
                ports,
                volumes,
                environment,
                network_mode,
                resource_limits,
                config_path: file_path.to_string_lossy().to_string(),
            };

            container_configs.push(container_config);
        }

        Ok(container_configs)
    }

    /// Удаляет дубликаты и нормализует данные
    fn deduplicate_and_normalize(&self, configs: &mut Vec<ContainerConfig>) {
        // Удаление дубликатов по id
        let mut seen_ids = std::collections::HashSet::new();
        configs.retain(|config| seen_ids.insert(config.id.clone()));
    }
}

/// Парсит строку с образом на имя и версию
fn parse_image_string(image: &str) -> (String, String) {
    let parts: Vec<&str> = image.split(':').collect();

    match parts.len() {
        1 => (image.to_string(), "latest".to_string()),
        _ => (parts[0].to_string(), parts[1..].join(":").to_string()),
    }
}

/// Извлекает настройки портов из конфигурации сервиса
fn extract_ports(service_config: &serde_yaml::Mapping) -> Vec<PortMapping> {
    let mut ports = Vec::new();

    // Извлекаем порты
    if let Some(ports_value) = service_config.get(&Value::String("ports".to_string())) {
        if let Some(ports_array) = ports_value.as_sequence() {
            for port_value in ports_array {
                // Парсим порт из строки вида "8080:80" или "8080:80/tcp"
                if let Some(port_str) = port_value.as_str() {
                    if let Some(port_mapping) = parse_port_mapping(port_str) {
                        ports.push(port_mapping);
                    }
                }
            }
        }
    }

    ports
}

/// Парсит строку с портом в структуру PortMapping
fn parse_port_mapping(port_str: &str) -> Option<PortMapping> {
    // Парсим протокол
    let (port_part, protocol) = if port_str.contains('/') {
        let parts: Vec<&str> = port_str.split('/').collect();
        (parts[0], parts[1].to_string())
    } else {
        (port_str, "tcp".to_string())
    };

    // Парсим порты
    let port_parts: Vec<&str> = port_part.split(':').collect();

    match port_parts.len() {
        1 => {
            // Только один порт - используется для хоста и контейнера
            port_parts[0].parse::<u16>().ok().map(|port| PortMapping {
                host_port: port,
                container_port: port,
                protocol,
            })
        }
        2 => {
            // Два порта - хост:контейнер
            let host_port = port_parts[0].parse::<u16>().ok()?;
            let container_port = port_parts[1].parse::<u16>().ok()?;

            Some(PortMapping {
                host_port,
                container_port,
                protocol,
            })
        }
        _ => None,
    }
}

/// Извлекает настройки томов из конфигурации сервиса
fn extract_volumes(service_config: &serde_yaml::Mapping) -> Vec<VolumeMount> {
    let mut volumes = Vec::new();

    // Извлекаем тома
    if let Some(volumes_value) = service_config.get(&Value::String("volumes".to_string())) {
        if let Some(volumes_array) = volumes_value.as_sequence() {
            for volume_value in volumes_array {
                // Парсим том из строки вида "/host/path:/container/path" или "/host/path:/container/path:ro"
                if let Some(volume_str) = volume_value.as_str() {
                    if let Some(volume_mount) = parse_volume_mount(volume_str) {
                        volumes.push(volume_mount);
                    }
                }
            }
        }
    }

    volumes
}

/// Парсит строку с томом в структуру VolumeMount
fn parse_volume_mount(volume_str: &str) -> Option<VolumeMount> {
    let parts: Vec<&str> = volume_str.split(':').collect();

    match parts.len() {
        2 => {
            // Только путь хоста и контейнера
            Some(VolumeMount {
                host_path: parts[0].to_string(),
                container_path: parts[1].to_string(),
                read_only: false,
            })
        }
        3 => {
            // Путь хоста, контейнера и флаг доступа
            let read_only = parts[2] == "ro";

            Some(VolumeMount {
                host_path: parts[0].to_string(),
                container_path: parts[1].to_string(),
                read_only,
            })
        }
        _ => None,
    }
}

/// Извлекает переменные окружения из конфигурации сервиса
fn extract_environment(service_config: &serde_yaml::Mapping) -> HashMap<String, String> {
    let mut environment = HashMap::new();

    // Извлекаем переменные окружения
    if let Some(env_value) = service_config.get(&Value::String("environment".to_string())) {
        // Переменные могут быть в виде массива или объекта
        if let Some(env_mapping) = env_value.as_mapping() {
            for (key, value) in env_mapping {
                if let (Some(key_str), Some(value_str)) = (key.as_str(), value.as_str()) {
                    environment.insert(key_str.to_string(), value_str.to_string());
                }
            }
        } else if let Some(env_array) = env_value.as_sequence() {
            for env_item in env_array {
                if let Some(env_str) = env_item.as_str() {
                    if let Some((key, value)) = env_str.split_once('=') {
                        environment.insert(key.to_string(), value.to_string());
                    }
                }
            }
        }
    }

    environment
}

/// Извлекает режим сети из конфигурации сервиса
fn extract_network_mode(service_config: &serde_yaml::Mapping) -> String {
    // Извлекаем режим сети
    if let Some(network_mode_value) = service_config.get(&Value::String("network_mode".to_string()))
    {
        if let Some(network_mode_str) = network_mode_value.as_str() {
            return network_mode_str.to_string();
        }
    }

    // Значение по умолчанию
    "bridge".to_string()
}

/// Извлекает ограничения ресурсов из конфигурации сервиса
fn extract_resource_limits(service_config: &serde_yaml::Mapping) -> Option<ResourceLimits> {
    let mut cpu = None;
    let mut memory = None;

    // Извлекаем лимит CPU
    if let Some(cpu_value) = service_config.get(&Value::String("cpu_limit".to_string())) {
        if let Some(cpu_str) = cpu_value.as_str() {
            cpu = cpu_str.parse::<f64>().ok();
        } else if let Some(cpu_num) = cpu_value.as_f64() {
            cpu = Some(cpu_num);
        }
    }

    // Извлекаем лимит памяти
    if let Some(memory_value) = service_config.get(&Value::String("mem_limit".to_string())) {
        if let Some(memory_str) = memory_value.as_str() {
            // Парсим строку вида "512m" или "1g"
            memory = parse_memory_string(memory_str);
        }
    }

    if cpu.is_some() || memory.is_some() {
        Some(ResourceLimits { cpu, memory })
    } else {
        None
    }
}

/// Парсит строку с размером памяти в байты
fn parse_memory_string(memory_str: &str) -> Option<u64> {
    let memory_str = memory_str.to_lowercase();

    // Извлекаем число и единицу измерения
    let mut num_part = String::new();
    let mut unit_part = String::new();

    for c in memory_str.chars() {
        if c.is_ascii_digit() || c == '.' {
            num_part.push(c);
        } else {
            unit_part.push(c);
        }
    }

    if num_part.is_empty() {
        return None;
    }

    let value = num_part.parse::<f64>().ok()?;

    // Конвертируем в байты
    match unit_part.as_str() {
        "b" => Some(value as u64),
        "k" | "kb" => Some((value * 1024.0) as u64),
        "m" | "mb" => Some((value * 1024.0 * 1024.0) as u64),
        "g" | "gb" => Some((value * 1024.0 * 1024.0 * 1024.0) as u64),
        _ => Some(value as u64), // По умолчанию считаем, что это байты
    }
}
