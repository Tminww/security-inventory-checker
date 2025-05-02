use anyhow::{Context, Result};
use log::{debug, warn};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::models::{ContainerConfig, PortMapping, ResourceLimits, VolumeMount};

/// Парсер Dockerfile
pub fn parse_dockerfile(file_path: &Path) -> Result<ContainerConfig> {
    debug!("Начало анализа Dockerfile: {}", file_path.display());

    // Чтение содержимого файла
    let content = fs::read_to_string(file_path)
        .context(format!("Не удалось прочитать файл {}", file_path.display()))?;

    // Получение базового имени файла для идентификации контейнера
    let container_name = file_path
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|name| name.to_str())
        .unwrap_or("unnamed")
        .to_string();

    // Инициализация структуры конфигурации контейнера
    let mut config = ContainerConfig {
        id: format!("dockerfile_{}", container_name),
        name: container_name,
        image: "".to_string(),
        image_version: "latest".to_string(),
        ports: Vec::new(),
        volumes: Vec::new(),
        environment: HashMap::new(),
        network_mode: "bridge".to_string(), // По умолчанию для Docker
        resource_limits: None,
        config_path: file_path.to_string_lossy().to_string(),
    };

    // Разбиваем файл на строки и анализируем каждую инструкцию
    let lines: Vec<&str> = content.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let mut line = lines[i].trim();

        // Пропускаем пустые строки и комментарии
        if line.is_empty() || line.starts_with('#') {
            i += 1;
            continue;
        }

        // Обработка многострочных инструкций (со символом \ в конце)
        let mut full_instruction = line.to_string();
        while line.ends_with('\\') && i + 1 < lines.len() {
            full_instruction.pop(); // Удаляем символ \
            i += 1;
            line = lines[i].trim();
            full_instruction.push_str(line);
        }

        // Анализ инструкции
        parse_instruction(&full_instruction, &mut config);

        i += 1;
    }

    debug!("Завершен анализ Dockerfile: {}", file_path.display());
    Ok(config)
}

/// Парсит отдельную инструкцию Dockerfile
fn parse_instruction(instruction: &str, config: &mut ContainerConfig) {
    let parts: Vec<&str> = instruction.splitn(2, ' ').collect();
    if parts.len() < 2 {
        return;
    }

    let cmd = parts[0].to_uppercase();
    let args = parts[1].trim();

    match cmd.as_str() {
        "FROM" => parse_from(args, config),
        "EXPOSE" => parse_expose(args, config),
        "ENV" => parse_env(args, config),
        "VOLUME" => parse_volume(args, config),
        "LABEL" => parse_label(args, config),
        "HEALTHCHECK" => parse_healthcheck(args, config),
        // Другие инструкции Dockerfile можно добавить по мере необходимости
        _ => {} // Игнорируем неизвестные инструкции
    }
}

/// Парсит инструкцию FROM
fn parse_from(args: &str, config: &mut ContainerConfig) {
    let image_parts: Vec<&str> = args.split(':').collect();

    if !image_parts.is_empty() {
        config.image = image_parts[0].to_string();

        if image_parts.len() > 1 {
            config.image_version = image_parts[1].to_string();
        } else {
            config.image_version = "latest".to_string();
        }
    }
}

/// Парсит инструкцию EXPOSE
fn parse_expose(args: &str, config: &mut ContainerConfig) {
    for port_spec in args.split_whitespace() {
        // Удаляем все нецифровые символы и пробуем разобрать порт
        let port_parts: Vec<&str> = port_spec.split('/').collect();

        let port_number = match port_parts[0].parse::<u16>() {
            Ok(port) => port,
            Err(_) => continue,
        };

        let protocol = if port_parts.len() > 1 {
            port_parts[1].to_lowercase()
        } else {
            "tcp".to_string()
        };

        // Добавляем порт в конфигурацию
        // Обратите внимание, что в Dockerfile мы знаем только контейнерные порты
        config.ports.push(PortMapping {
            host_port: port_number, // Предполагаем, что хост порт такой же (это будет корректироваться при запуске)
            container_port: port_number,
            protocol,
        });
    }
}

/// Парсит инструкцию ENV
fn parse_env(args: &str, config: &mut ContainerConfig) {
    // Обработка формата ENV KEY=VALUE
    if args.contains('=') {
        // Обработка одной переменной с значением, содержащим пробелы
        if let Some((key, value)) = args.split_once('=') {
            config
                .environment
                .insert(key.trim().to_string(), value.trim().to_string());
        }
    } else {
        // Обработка формата ENV KEY VALUE
        let parts: Vec<&str> = args.splitn(2, ' ').collect();
        if parts.len() == 2 {
            config
                .environment
                .insert(parts[0].to_string(), parts[1].to_string());
        }
    }
}

/// Парсит инструкцию VOLUME
fn parse_volume(args: &str, config: &mut ContainerConfig) {
    // VOLUME может быть в форматах:
    // VOLUME /path1 /path2
    // VOLUME ["/path1", "/path2"]

    let args = args.trim();
    let paths = if args.starts_with('[') && args.ends_with(']') {
        // Формат JSON массива
        let json_str = args.to_string();
        match serde_json::from_str::<Vec<String>>(&json_str) {
            Ok(paths) => paths,
            Err(_) => {
                // Если парсинг JSON не удался, попробуем разобрать вручную
                args[1..args.len() - 1]
                    .split(',')
                    .map(|s| s.trim().trim_matches('"').to_string())
                    .collect()
            }
        }
    } else {
        // Простой формат с пробелами
        args.split_whitespace().map(|s| s.to_string()).collect()
    };

    for path in paths {
        // В Dockerfile указываются только пути в контейнере
        config.volumes.push(VolumeMount {
            host_path: "".to_string(), // Будет определено при запуске
            container_path: path,
            read_only: false,
        });
    }
}

/// Парсит инструкцию LABEL (для потенциальной метаинформации)
fn parse_label(_args: &str, _config: &mut ContainerConfig) {
    // Метки обычно не влияют на конфигурацию контейнера
    // Но можно добавить специальные метки для ограничения ресурсов
    // Например: LABEL com.example.resource.cpu="0.5"

    // Это заглушка для будущего расширения
}

/// Парсит инструкцию HEALTHCHECK
fn parse_healthcheck(_args: &str, _config: &mut ContainerConfig) {
    // Проверки работоспособности не напрямую влияют на конфигурацию
    // Но могут быть полезны для мониторинга

    // Это заглушка для будущего расширения
}
