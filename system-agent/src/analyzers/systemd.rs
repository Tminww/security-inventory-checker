use anyhow::{Context, Result};
use log::{debug, warn};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::models::SystemdUnit;

/// Анализатор Systemd юнитов
pub struct SystemdAnalyzer {
    /// Кэшированные данные о юнитах
    cached_units: HashMap<String, SystemdUnit>,
}

impl SystemdAnalyzer {
    /// Создает новый анализатор Systemd
    pub fn new() -> Self {
        Self {
            cached_units: HashMap::new(),
        }
    }

    /// Сканирует Systemd юниты
    pub fn scan_units(&mut self) -> Result<Vec<SystemdUnit>> {
        debug!("Начало сканирования Systemd юнитов");

        // Получаем список всех активных юнитов
        let units = self.get_active_units()?;

        // Заполняем кэш
        self.cached_units.clear();
        for unit in &units {
            self.cached_units.insert(unit.name.clone(), unit.clone());
        }

        debug!(
            "Сканирование Systemd юнитов завершено, найдено {} юнитов",
            units.len()
        );
        Ok(units)
    }

    /// Получает список активных юнитов
    fn get_active_units(&self) -> Result<Vec<SystemdUnit>> {
        debug!("Получение списка активных юнитов");

        // Запускаем systemctl list-units
        let output = Command::new("systemctl")
            .args(["list-units", "--type=service", "--all", "--no-legend"])
            .output()
            .context("Не удалось выполнить команду systemctl list-units")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("Ошибка при выполнении systemctl list-units: {}", stderr);
            return Ok(Vec::new());
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        let mut units = Vec::new();

        // Обрабатываем каждую строку
        for line in output_str.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();

            if parts.len() >= 4 {
                let unit_name = parts[0].to_string();

                // Получаем информацию о юните
                if let Ok(unit_info) = self.get_unit_info(&unit_name) {
                    units.push(unit_info);
                }
            }
        }

        debug!("Найдено {} активных юнитов", units.len());
        Ok(units)
    }

    /// Получает информацию о конкретном юните
    fn get_unit_info(&self, unit_name: &str) -> Result<SystemdUnit> {
        debug!("Получение информации о юните: {}", unit_name);

        // Запускаем systemctl show
        let output = Command::new("systemctl")
            .args(["show", unit_name])
            .output()
            .context(format!(
                "Не удалось выполнить команду systemctl show {}",
                unit_name
            ))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!(
                "Ошибка при выполнении systemctl show {}: {}",
                unit_name, stderr
            );
            return Err(anyhow::anyhow!(
                "Ошибка при получении информации о юните {}",
                unit_name
            ));
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        let mut properties = HashMap::new();

        // Парсим вывод
        for line in output_str.lines() {
            if let Some((key, value)) = line.split_once('=') {
                properties.insert(key.to_string(), value.to_string());
            }
        }

        // Получаем значения свойств
        let description = properties
            .get("Description")
            .cloned()
            .unwrap_or_else(|| unit_name.to_string());

        let exec_path = properties.get("ExecStart").cloned().map(|s| {
            // Извлекаем путь из строки вида "{ path=...; argv[]={...}; }"
            if let Some(start) = s.find("path=") {
                if let Some(end) = s[start..].find(';') {
                    return s[start + 5..start + end].to_string();
                }
            }
            s
        });

        let exec_args = properties
            .get("ExecStart")
            .cloned()
            .map(|s| {
                // Извлекаем аргументы из строки вида "{ argv[]={...}; }"
                if let Some(start) = s.find("argv[]={") {
                    if let Some(end) = s[start..].find("};") {
                        let args_str = &s[start + 8..start + end];
                        return args_str
                            .split(',')
                            .map(|s| s.trim().trim_matches('"').to_string())
                            .collect();
                    }
                }
                Vec::new()
            })
            .unwrap_or_else(Vec::new);

        let user = properties
            .get("User")
            .cloned()
            .unwrap_or_else(|| "root".to_string());

        let group = properties
            .get("Group")
            .cloned()
            .unwrap_or_else(|| "root".to_string());

        let working_directory = properties
            .get("WorkingDirectory")
            .cloned()
            .filter(|s| s != "-");

        let dependencies: Vec<String> = properties
            .get("Requires")
            .into_iter()
            .flat_map(|s| s.split_whitespace().map(|s| s.to_string()))
            .collect();

        let state = properties
            .get("ActiveState")
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());

        let enabled = properties
            .get("UnitFileState")
            .map(|s| s == "enabled")
            .unwrap_or(false);

        let unit_file_path = properties
            .get("FragmentPath")
            .cloned()
            .unwrap_or_else(|| format!("/etc/systemd/system/{}", unit_name));

        let unit_type = if unit_name.ends_with(".service") {
            "service".to_string()
        } else if unit_name.ends_with(".socket") {
            "socket".to_string()
        } else if unit_name.ends_with(".timer") {
            "timer".to_string()
        } else if unit_name.ends_with(".target") {
            "target".to_string()
        } else if unit_name.ends_with(".path") {
            "path".to_string()
        } else if unit_name.ends_with(".device") {
            "device".to_string()
        } else if unit_name.ends_with(".mount") {
            "mount".to_string()
        } else if unit_name.ends_with(".automount") {
            "automount".to_string()
        } else if unit_name.ends_with(".swap") {
            "swap".to_string()
        } else if unit_name.ends_with(".scope") {
            "scope".to_string()
        } else if unit_name.ends_with(".slice") {
            "slice".to_string()
        } else {
            "unknown".to_string()
        };

        let unit = SystemdUnit {
            name: unit_name.to_string(),
            description,
            unit_type,
            exec_path,
            exec_args,
            user,
            group,
            working_directory,
            dependencies,
            state,
            enabled,
            unit_file_path,
        };

        debug!("Получена информация о юните: {}", unit_name);
        Ok(unit)
    }

    /// Получает конфигурацию юнита из файла
    fn parse_unit_file(&self, unit_name: &str, file_path: &Path) -> Result<SystemdUnit> {
        debug!("Парсинг файла юнита: {}", file_path.display());

        // Проверяем существование файла
        if !file_path.exists() {
            return Err(anyhow::anyhow!(
                "Файл юнита {} не существует",
                file_path.display()
            ));
        }

        // Читаем содержимое файла
        let content = fs::read_to_string(file_path)
            .context(format!("Не удалось прочитать файл {}", file_path.display()))?;

        let mut description = unit_name.to_string();
        let mut exec_path = None;
        let mut exec_args = Vec::new();
        let mut user = "root".to_string();
        let mut group = "root".to_string();
        let mut working_directory = None;
        let mut dependencies = Vec::new();

        // Парсим содержимое файла
        let mut current_section = "";

        for line in content.lines() {
            let line = line.trim();

            // Пропускаем пустые строки и комментарии
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Определяем секцию
            if line.starts_with('[') && line.ends_with(']') {
                current_section = line;
                continue;
            }

            // Обрабатываем директивы
            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim();
                let value = value.trim();

                match current_section {
                    "[Unit]" => {
                        if key == "Description" {
                            description = value.to_string();
                        } else if key == "Requires" || key == "Wants" || key == "After" {
                            dependencies.extend(value.split_whitespace().map(|s| s.to_string()));
                        }
                    }
                    "[Service]" => {
                        if key == "ExecStart" {
                            // Парсим команду запуска
                            if let Some((cmd, args)) = value.split_once(' ') {
                                exec_path = Some(cmd.to_string());
                                exec_args =
                                    args.split_whitespace().map(|s| s.to_string()).collect();
                            } else {
                                exec_path = Some(value.to_string());
                            }
                        } else if key == "User" {
                            user = value.to_string();
                        } else if key == "Group" {
                            group = value.to_string();
                        } else if key == "WorkingDirectory" {
                            working_directory = Some(value.to_string());
                        }
                    }
                    _ => {}
                }
            }
        }

        // Определяем тип юнита
        let unit_type = if unit_name.ends_with(".service") {
            "service".to_string()
        } else if unit_name.ends_with(".socket") {
            "socket".to_string()
        } else {
            // Аналогично как в методе get_unit_info()
            "unknown".to_string()
        };

        // Получаем состояние юнита
        let (state, enabled) = self.get_unit_state(unit_name)?;

        let unit = SystemdUnit {
            name: unit_name.to_string(),
            description,
            unit_type,
            exec_path,
            exec_args,
            user,
            group,
            working_directory,
            dependencies,
            state,
            enabled,
            unit_file_path: file_path.to_string_lossy().to_string(),
        };

        debug!("Успешно распарсен файл юнита: {}", file_path.display());
        Ok(unit)
    }

    /// Получает состояние юнита
    fn get_unit_state(&self, unit_name: &str) -> Result<(String, bool)> {
        // Проверяем активность юнита
        let output = Command::new("systemctl")
            .args(["is-active", unit_name, "--quiet"])
            .status()
            .context(format!(
                "Не удалось выполнить команду systemctl is-active {}",
                unit_name
            ))?;

        let state = if output.success() {
            "active".to_string()
        } else {
            // Если неактивен, проверяем, может быть в состоянии failed
            let failed_output = Command::new("systemctl")
                .args(["is-failed", unit_name, "--quiet"])
                .status()
                .context(format!(
                    "Не удалось выполнить команду systemctl is-failed {}",
                    unit_name
                ))?;

            if failed_output.success() {
                "failed".to_string()
            } else {
                "inactive".to_string()
            }
        };

        // Проверяем, включен ли автозапуск
        let enabled_output = Command::new("systemctl")
            .args(["is-enabled", unit_name, "--quiet"])
            .status()
            .context(format!(
                "Не удалось выполнить команду systemctl is-enabled {}",
                unit_name
            ))?;

        let enabled = enabled_output.success();

        Ok((state, enabled))
    }

    /// Находит все файлы юнитов в системе
    fn find_unit_files(&self) -> Result<Vec<PathBuf>> {
        debug!("Поиск файлов юнитов в системе");

        // Запускаем systemctl list-unit-files
        let output = Command::new("systemctl")
            .args(["list-unit-files", "--type=service", "--no-legend"])
            .output()
            .context("Не удалось выполнить команду systemctl list-unit-files")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!(
                "Ошибка при выполнении systemctl list-unit-files: {}",
                stderr
            );
            return Ok(Vec::new());
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        let mut files = Vec::new();

        // Стандартные пути для файлов юнитов
        let unit_paths = vec![
            PathBuf::from("/etc/systemd/system"),
            PathBuf::from("/usr/lib/systemd/system"),
        ];

        // Обрабатываем каждую строку
        for line in output_str.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();

            if parts.is_empty() {
                continue;
            }

            let unit_name = parts[0];

            // Ищем файл юнита в стандартных путях
            for path in &unit_paths {
                let file_path = path.join(unit_name);

                if file_path.exists() {
                    files.push(file_path);
                    break;
                }
            }
        }

        debug!("Найдено {} файлов юнитов", files.len());
        Ok(files)
    }

    /// Получает юнит по имени
    pub fn get_unit(&self, unit_name: &str) -> Option<&SystemdUnit> {
        self.cached_units.get(unit_name)
    }

    /// Проверяет, запущен ли юнит
    pub fn is_unit_active(&self, unit_name: &str) -> bool {
        if let Some(unit) = self.cached_units.get(unit_name) {
            unit.state == "active"
        } else {
            // Если юнит не в кэше, проверяем через systemctl
            Command::new("systemctl")
                .args(["is-active", unit_name, "--quiet"])
                .status()
                .map_or(false, |status| status.success())
        }
    }

    /// Возвращает зависимости юнита
    pub fn get_unit_dependencies(&self, unit_name: &str) -> Vec<String> {
        if let Some(unit) = self.cached_units.get(unit_name) {
            unit.dependencies.clone()
        } else {
            Vec::new()
        }
    }

    /// Находит юниты, связанные с указанным процессом
    pub fn find_units_for_process(&self, pid: i32) -> Vec<String> {
        let mut related_units = Vec::new();

        // Запрашиваем cgroup процесса
        let cgroup_path = format!("/proc/{}/cgroup", pid);

        if let Ok(content) = fs::read_to_string(cgroup_path) {
            for line in content.lines() {
                // Ищем строки, содержащие systemd
                if line.contains("systemd") {
                    // Извлекаем имя юнита из пути cgroup
                    let parts: Vec<&str> = line.split('/').collect();
                    for part in parts {
                        if part.ends_with(".service") || part.ends_with(".scope") {
                            related_units.push(part.to_string());
                        }
                    }
                }
            }
        }

        related_units
    }
}
