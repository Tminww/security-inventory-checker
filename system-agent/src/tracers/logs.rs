// system-agent/src/tracers/logs.rs
use anyhow::{Context, Result};
use chrono::{DateTime, Local, TimeZone};
use log::{debug, warn};
use regex::Regex;
use std::process::Command;
use std::str::FromStr;

use crate::models::LogEntry;

const MAX_LOG_ENTRIES: usize = 1000;

/// Трейсер для сбора журнальных записей
pub struct LogTracer {
    /// Время последнего сбора логов
    last_timestamp: i64,
    /// Шаблоны для фильтрации логов
    patterns: Vec<Regex>,
}

impl LogTracer {
    /// Создает новый экземпляр трейсера логов
    pub fn new() -> Self {
        let patterns = vec![
            // Примеры шаблонов для фильтрации интересных логов
            Regex::new(r"authentication failure").unwrap_or_default(),
            Regex::new(r"Failed password").unwrap_or_default(),
            Regex::new(r"segfault").unwrap_or_default(),
            Regex::new(r"Permission denied").unwrap_or_default(),
            Regex::new(r"ERROR").unwrap_or_default(),
            Regex::new(r"CRITICAL").unwrap_or_default(),
            Regex::new(r"WARNING").unwrap_or_default(),
            Regex::new(r"fatal").unwrap_or_default(),
        ];

        Self {
            last_timestamp: 0,
            patterns,
        }
    }

    /// Собирает записи журнала с момента последнего сбора
    pub fn collect_logs(&mut self) -> Result<Vec<LogEntry>> {
        debug!("Сбор журнальных записей...");

        // Используем journalctl для сбора логов
        let output = if self.last_timestamp > 0 {
            // Если это не первый запуск, собираем только новые логи
            let timestamp = format!("@{}", self.last_timestamp / 1000000);
            Command::new("journalctl")
                .args(&["-o", "json", "--since", &timestamp])
                .output()
                .context("Не удалось выполнить команду journalctl")?
        } else {
            // При первом запуске берем ограниченное количество последних логов
            Command::new("journalctl")
                .args(&["-o", "json", "-n", "1000"])
                .output()
                .context("Не удалось выполнить команду journalctl")?
        };

        let output_str = String::from_utf8_lossy(&output.stdout);
        let mut logs = Vec::new();
        let mut newest_timestamp = self.last_timestamp;

        // Обрабатываем каждую строку вывода journalctl
        for line in output_str.lines() {
            if let Ok(entry) = self.parse_journal_entry(line) {
                // Обновляем временную метку последнего лога
                if entry.timestamp > newest_timestamp {
                    newest_timestamp = entry.timestamp;
                }

                // Фильтруем логи по заданным шаблонам или уровню важности
                if entry.priority <= 4 || self.is_interesting_log(&entry) {
                    logs.push(entry);
                }
            }
        }

        // Обновляем timestamp последнего лога
        self.last_timestamp = newest_timestamp;

        // Ограничиваем количество возвращаемых логов
        if logs.len() > MAX_LOG_ENTRIES {
            logs.truncate(MAX_LOG_ENTRIES);
        }

        debug!("Собрано {} журнальных записей", logs.len());
        Ok(logs)
    }

    /// Разбирает запись журнала из формата JSON
    fn parse_journal_entry(&self, json_str: &str) -> Result<LogEntry> {
        let json: serde_json::Value = serde_json::from_str(json_str)
            .context("Не удалось разобрать JSON формат журнальной записи")?;

        // Извлекаем основные поля из JSON
        let timestamp = json["__REALTIME_TIMESTAMP"]
            .as_str()
            .unwrap_or("0")
            .parse::<i64>()
            .unwrap_or(0);

        let message = json["MESSAGE"].as_str().unwrap_or("").to_string();
        let hostname = json["_HOSTNAME"].as_str().unwrap_or("").to_string();

        let priority = json["PRIORITY"]
            .as_str()
            .unwrap_or("6") // По умолчанию INFO
            .parse::<u8>()
            .unwrap_or(6);

        let syslog_identifier = json["SYSLOG_IDENTIFIER"].as_str().unwrap_or("").to_string();

        let pid = json["_PID"]
            .as_str()
            .unwrap_or("0")
            .parse::<i32>()
            .unwrap_or(0);

        let unit = json["_SYSTEMD_UNIT"].as_str().unwrap_or("").to_string();

        // Конвертируем временную метку в читаемый формат
        let timestamp_secs = timestamp / 1000000; // микросекунды -> секунды
        let datetime = match Local.timestamp_opt(timestamp_secs, 0) {
            chrono::LocalResult::Single(dt) => dt.to_rfc3339(),
            _ => format!("{}", timestamp_secs),
        };

        Ok(LogEntry {
            timestamp,
            datetime,
            message,
            hostname,
            priority,
            syslog_identifier,
            pid,
            unit,
        })
    }

    /// Проверяет, является ли лог интересным по заданным шаблонам
    fn is_interesting_log(&self, entry: &LogEntry) -> bool {
        for pattern in &self.patterns {
            if pattern.is_match(&entry.message) {
                return true;
            }
        }
        false
    }
}
