// system-agent/src/analyzers/firewall.rs
use anyhow::{Context, Result};
use log::{debug, warn};
use std::process::Command;
use std::str::FromStr;

use crate::models::FirewallRule;

/// Анализатор правил файервола
pub struct FirewallAnalyzer {
    /// Тип используемого файервола (iptables, nftables, ufw)
    firewall_type: FirewallType,
}

/// Тип файервола
#[derive(Debug, PartialEq)]
enum FirewallType {
    Iptables,
    Nftables,
    Ufw,
    Unknown,
}

impl FirewallAnalyzer {
    /// Создает новый анализатор файервола
    pub fn new() -> Self {
        let firewall_type = Self::detect_firewall_type();
        debug!("Обнаружен файервол типа: {:?}", firewall_type);

        Self { firewall_type }
    }

    /// Сканирует правила файервола
    pub fn scan_rules(&self) -> Result<Vec<FirewallRule>> {
        debug!("Начало сканирования правил файервола");

        let rules = match self.firewall_type {
            FirewallType::Iptables => self.scan_iptables_rules(),
            FirewallType::Nftables => self.scan_nftables_rules(),
            FirewallType::Ufw => self.scan_ufw_rules(),
            FirewallType::Unknown => {
                debug!("Тип файервола не определен, попытка проверить все варианты");
                // Пробуем все варианты
                let mut rules = self.scan_iptables_rules().unwrap_or_default();
                rules.extend(self.scan_nftables_rules().unwrap_or_default());
                rules.extend(self.scan_ufw_rules().unwrap_or_default());
                Ok(rules)
            }
        }?;

        debug!(
            "Сканирование правил файервола завершено, найдено {} правил",
            rules.len()
        );
        Ok(rules)
    }

    /// Определяет тип файервола
    fn detect_firewall_type() -> FirewallType {
        // Проверяем наличие iptables
        if Command::new("iptables")
            .arg("-V")
            .output()
            .map_or(false, |output| output.status.success())
        {
            return FirewallType::Iptables;
        }

        // Проверяем наличие nftables
        if Command::new("nft")
            .arg("-v")
            .output()
            .map_or(false, |output| output.status.success())
        {
            return FirewallType::Nftables;
        }

        // Проверяем наличие ufw
        if Command::new("ufw")
            .arg("status")
            .output()
            .map_or(false, |output| output.status.success())
        {
            return FirewallType::Ufw;
        }

        FirewallType::Unknown
    }

    /// Сканирует правила iptables
    fn scan_iptables_rules(&self) -> Result<Vec<FirewallRule>> {
        debug!("Сканирование правил iptables");

        let mut rules = Vec::new();

        // Таблицы и цепочки для проверки
        let tables = ["filter", "nat", "mangle", "raw"];

        for table in &tables {
            // Запускаем iptables -t <table> -L -n -v
            let output = Command::new("iptables")
                .args(["-t", table, "-L", "-n", "-v"])
                .output()
                .context(format!(
                    "Не удалось выполнить команду iptables для таблицы {}",
                    table
                ))?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                warn!(
                    "Ошибка при выполнении iptables для таблицы {}: {}",
                    table, stderr
                );
                continue;
            }

            let output_str = String::from_utf8_lossy(&output.stdout);

            // Парсим вывод
            let mut current_chain = String::new();
            let mut priority = 0;

            for line in output_str.lines() {
                let line = line.trim();

                // Пропускаем пустые строки
                if line.is_empty() {
                    continue;
                }

                // Определяем цепочку
                if line.starts_with("Chain") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        current_chain = parts[1].to_string();
                        priority = 0;
                    }
                    continue;
                }

                // Пропускаем заголовки
                if line.starts_with("pkts") || line.starts_with("target") {
                    continue;
                }

                // Парсим правило
                let rule = self.parse_iptables_rule(line, table, &current_chain, priority);
                if let Some(rule) = rule {
                    rules.push(rule);
                    priority += 1;
                }
            }
        }

        debug!("Найдено {} правил iptables", rules.len());
        Ok(rules)
    }

    /// Парсит строку с правилом iptables
    fn parse_iptables_rule(
        &self,
        line: &str,
        table: &str,
        chain: &str,
        priority: i32,
    ) -> Option<FirewallRule> {
        let parts: Vec<&str> = line.split_whitespace().collect();

        if parts.len() < 3 {
            return None;
        }

        // Получаем действие
        let action = parts[2].to_string();

        // Инициализируем правило
        let mut rule = FirewallRule {
            firewall_type: "iptables".to_string(),
            table: table.to_string(),
            chain: chain.to_string(),
            priority,
            action,
            protocol: None,
            source: None,
            destination: None,
            source_port: None,
            destination_port: None,
            interface: None,
            raw_rule: line.to_string(),
        };

        // Парсим опции
        let mut i = 3;
        while i < parts.len() {
            match parts[i] {
                "-p" | "--protocol" if i + 1 < parts.len() => {
                    rule.protocol = Some(parts[i + 1].to_string());
                    i += 2;
                }
                "-s" | "--source" if i + 1 < parts.len() => {
                    rule.source = Some(parts[i + 1].to_string());
                    i += 2;
                }
                "-d" | "--destination" if i + 1 < parts.len() => {
                    rule.destination = Some(parts[i + 1].to_string());
                    i += 2;
                }
                "--sport" if i + 1 < parts.len() => {
                    rule.source_port = Some(parts[i + 1].to_string());
                    i += 2;
                }
                "--dport" if i + 1 < parts.len() => {
                    rule.destination_port = Some(parts[i + 1].to_string());
                    i += 2;
                }
                "-i" | "--in-interface" if i + 1 < parts.len() => {
                    rule.interface = Some(parts[i + 1].to_string());
                    i += 2;
                }
                "-o" | "--out-interface" if i + 1 < parts.len() => {
                    rule.interface = Some(parts[i + 1].to_string());
                    i += 2;
                }
                _ => {
                    i += 1;
                }
            }
        }

        Some(rule)
    }

    /// Сканирует правила nftables
    fn scan_nftables_rules(&self) -> Result<Vec<FirewallRule>> {
        debug!("Сканирование правил nftables");

        // Запускаем nft list ruleset
        let output = Command::new("nft")
            .args(["list", "ruleset"])
            .output()
            .context("Не удалось выполнить команду nft list ruleset")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("Ошибка при выполнении nft list ruleset: {}", stderr);
            return Ok(Vec::new());
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        let mut rules = Vec::new();

        // Парсим вывод
        let mut current_table = String::new();
        let mut current_chain = String::new();
        let mut priority = 0;

        for line in output_str.lines() {
            let line = line.trim();

            // Пропускаем пустые строки
            if line.is_empty() {
                continue;
            }

            // Определяем таблицу
            if line.starts_with("table") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    current_table = parts[2].trim_matches('{').to_string();
                    current_chain = String::new();
                    priority = 0;
                }
                continue;
            }

            // Определяем цепочку
            if line.starts_with("chain") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    current_chain = parts[1].trim_matches('{').to_string();
                    priority = 0;
                }
                continue;
            }

            // Парсим правило
            if !current_table.is_empty() && !current_chain.is_empty() && line.contains("return") {
                let rule = self.parse_nftables_rule(line, &current_table, &current_chain, priority);
                if let Some(rule) = rule {
                    rules.push(rule);
                    priority += 1;
                }
            }
        }

        debug!("Найдено {} правил nftables", rules.len());
        Ok(rules)
    }

    /// Парсит строку с правилом nftables
    fn parse_nftables_rule(
        &self,
        line: &str,
        table: &str,
        chain: &str,
        priority: i32,
    ) -> Option<FirewallRule> {
        // Удаляем начальный whitespace и trailing ';'
        let line = line.trim().trim_end_matches(';');

        // Получаем действие
        let action = if line.contains("accept") {
            "ACCEPT".to_string()
        } else if line.contains("drop") {
            "DROP".to_string()
        } else if line.contains("reject") {
            "REJECT".to_string()
        } else if line.contains("return") {
            "RETURN".to_string()
        } else {
            line.split_whitespace().last().unwrap_or("").to_string()
        };

        // Инициализируем правило
        let mut rule = FirewallRule {
            firewall_type: "nftables".to_string(),
            table: table.to_string(),
            chain: chain.to_string(),
            priority,
            action,
            protocol: None,
            source: None,
            destination: None,
            source_port: None,
            destination_port: None,
            interface: None,
            raw_rule: line.to_string(),
        };

        // Парсим опции (упрощенно)
        if line.contains("tcp") || line.contains("udp") || line.contains("icmp") {
            rule.protocol = line
                .split_whitespace()
                .find(|&word| word == "tcp" || word == "udp" || word == "icmp")
                .map(|s| s.to_string());
        }

        // Источник
        if line.contains("saddr") {
            let start = line.find("saddr").unwrap_or(0) + 5;
            let substr = &line[start..];
            let end = substr.find(' ').unwrap_or(substr.len());
            rule.source = Some(substr[..end].trim().to_string());
        }

        // Назначение
        if line.contains("daddr") {
            let start = line.find("daddr").unwrap_or(0) + 5;
            let substr = &line[start..];
            let end = substr.find(' ').unwrap_or(substr.len());
            rule.destination = Some(substr[..end].trim().to_string());
        }

        // Порт источника
        if line.contains("sport") {
            let start = line.find("sport").unwrap_or(0) + 5;
            let substr = &line[start..];
            let end = substr.find(' ').unwrap_or(substr.len());
            rule.source_port = Some(substr[..end].trim().to_string());
        }

        // Порт назначения
        if line.contains("dport") {
            let start = line.find("dport").unwrap_or(0) + 5;
            let substr = &line[start..];
            let end = substr.find(' ').unwrap_or(substr.len());
            rule.destination_port = Some(substr[..end].trim().to_string());
        }

        // Интерфейс
        if line.contains("iifname") {
            let start = line.find("iifname").unwrap_or(0) + 7;
            let substr = &line[start..];
            let end = substr.find(' ').unwrap_or(substr.len());
            rule.interface = Some(substr[..end].trim().to_string());
        } else if line.contains("oifname") {
            let start = line.find("oifname").unwrap_or(0) + 7;
            let substr = &line[start..];
            let end = substr.find(' ').unwrap_or(substr.len());
            rule.interface = Some(substr[..end].trim().to_string());
        }

        Some(rule)
    }

    /// Сканирует правила ufw
    fn scan_ufw_rules(&self) -> Result<Vec<FirewallRule>> {
        debug!("Сканирование правил ufw");

        // Запускаем ufw status verbose
        let output = Command::new("ufw")
            .args(["status", "verbose"])
            .output()
            .context("Не удалось выполнить команду ufw status verbose")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("Ошибка при выполнении ufw status verbose: {}", stderr);
            return Ok(Vec::new());
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        let mut rules = Vec::new();

        // Проверяем, включен ли ufw
        if output_str.contains("Status: inactive") {
            debug!("ufw неактивен, пропускаем дальнейший анализ");
            return Ok(rules);
        }

        // Парсим вывод
        let mut priority = 0;
        let lines: Vec<&str> = output_str.lines().collect();

        // Пропускаем заголовки и находим начало правил
        let mut i = 0;
        while i < lines.len() && !lines[i].contains("--") {
            i += 1;
        }

        // Пропускаем строку с --
        i += 1;

        // Парсим правила
        while i < lines.len() {
            let line = lines[i].trim();

            // Пропускаем пустые строки
            if line.is_empty() {
                i += 1;
                continue;
            }

            // Парсим правило
            let rule = self.parse_ufw_rule(line, priority);
            if let Some(rule) = rule {
                rules.push(rule);
                priority += 1;
            }

            i += 1;
        }

        debug!("Найдено {} правил ufw", rules.len());
        Ok(rules)
    }

    /// Парсит строку с правилом ufw
    fn parse_ufw_rule(&self, line: &str, priority: i32) -> Option<FirewallRule> {
        let parts: Vec<&str> = line.split_whitespace().collect();

        if parts.len() < 3 {
            return None;
        }

        // Получаем действие
        let action = if parts[0].to_lowercase() == "allow" {
            "ACCEPT".to_string()
        } else if parts[0].to_lowercase() == "deny" {
            "DROP".to_string()
        } else if parts[0].to_lowercase() == "reject" {
            "REJECT".to_string()
        } else {
            parts[0].to_uppercase()
        };

        // Инициализируем правило
        let mut rule = FirewallRule {
            firewall_type: "ufw".to_string(),
            table: "filter".to_string(),
            chain: "INPUT".to_string(), // По умолчанию
            priority,
            action,
            protocol: None,
            source: None,
            destination: None,
            source_port: None,
            destination_port: None,
            interface: None,
            raw_rule: line.to_string(),
        };

        // Определяем цепочку по направлению
        if parts.len() > 1 {
            if parts[1].to_lowercase() == "in" {
                rule.chain = "INPUT".to_string();
            } else if parts[1].to_lowercase() == "out" {
                rule.chain = "OUTPUT".to_string();
            }
        }

        // Парсим протокол и порты
        for i in 2..parts.len() {
            let part = parts[i].to_lowercase();

            if part == "tcp" || part == "udp" || part == "icmp" {
                rule.protocol = Some(part);
                continue;
            }

            // Порт или IP адрес
            if part.contains("/") {
                // Возможный формат: адрес/порт или адрес/маска
                let segments: Vec<&str> = part.split('/').collect();
                if segments.len() == 2 {
                    // Проверяем, является ли второй сегмент портом или маской
                    if segments[1].parse::<u16>().is_ok() && i > 0 && parts[i - 1].contains("from")
                    {
                        rule.source = Some(segments[0].to_string());
                        rule.source_port = Some(segments[1].to_string());
                    } else if segments[1].parse::<u16>().is_ok()
                        && i > 0
                        && parts[i - 1].contains("to")
                    {
                        rule.destination = Some(segments[0].to_string());
                        rule.destination_port = Some(segments[1].to_string());
                    } else {
                        // Вероятно, это адрес с маской
                        if i > 0 && parts[i - 1].contains("from") {
                            rule.source = Some(part);
                        } else if i > 0 && parts[i - 1].contains("to") {
                            rule.destination = Some(part);
                        }
                    }
                }
            } else if part.parse::<u16>().is_ok() {
                // Это порт
                if i > 0 && parts[i - 1].contains("port") {
                    if parts[i - 1].contains("from") {
                        rule.source_port = Some(part);
                    } else if parts[i - 1].contains("to") {
                        rule.destination_port = Some(part);
                    }
                }
            } else if i > 0 {
                // Проверка на IP адрес
                if parts[i - 1] == "from" {
                    rule.source = Some(part);
                } else if parts[i - 1] == "to" {
                    rule.destination = Some(part);
                } else if parts[i - 1] == "on" {
                    rule.interface = Some(part);
                }
            }
        }

        Some(rule)
    }

    /// Анализирует правила файервола на наличие потенциальных проблем безопасности
    pub fn analyze_security_issues(&self, rules: &[FirewallRule]) -> Vec<String> {
        debug!("Анализ правил файервола на наличие проблем безопасности");
        let mut issues = Vec::new();

        // Проверяем наличие правил, разрешающих весь трафик
        let has_allow_all = rules.iter().any(|rule| {
            rule.action == "ACCEPT"
                && rule.source.as_deref() == Some("0.0.0.0/0")
                && rule.destination.is_none()
                && rule.protocol.is_none()
        });

        if has_allow_all {
            issues.push("Обнаружено правило, разрешающее весь входящий трафик".to_string());
        }

        // Проверяем наличие правил для стандартных портов (SSH, HTTP, etc.)
        let has_ssh_rule = rules.iter().any(|rule| {
            rule.destination_port.as_deref() == Some("22")
                || rule.destination_port.as_deref() == Some("ssh")
        });

        if !has_ssh_rule {
            issues.push("Не обнаружено правил для SSH (порт 22)".to_string());
        }

        // Проверяем дублирующиеся правила
        let mut duplicate_check = std::collections::HashSet::new();
        for rule in rules {
            let key = format!(
                "{}-{}-{}-{}-{}-{}-{}",
                rule.action,
                rule.protocol.as_deref().unwrap_or(""),
                rule.source.as_deref().unwrap_or(""),
                rule.destination.as_deref().unwrap_or(""),
                rule.source_port.as_deref().unwrap_or(""),
                rule.destination_port.as_deref().unwrap_or(""),
                rule.interface.as_deref().unwrap_or("")
            );

            if !duplicate_check.insert(key) {
                issues.push(format!(
                    "Обнаружено дублирующееся правило: {}",
                    rule.raw_rule
                ));
            }
        }

        // Проверяем правила с высоким приоритетом, которые блокируют весь трафик
        let has_blocking_high_priority = rules.iter().any(|rule| {
            rule.priority < 5
                && (rule.action == "DROP" || rule.action == "REJECT")
                && rule.source.as_deref() == Some("0.0.0.0/0")
                && rule.protocol.is_none()
        });

        if has_blocking_high_priority {
            issues.push("Высокоприоритетное правило блокирует весь трафик".to_string());
        }

        debug!("Найдено {} проблем безопасности", issues.len());
        issues
    }

    /// Экспортирует правила файервола в формат JSON
    pub fn export_rules_json(&self, rules: &[FirewallRule]) -> Result<String> {
        debug!("Экспорт правил файервола в JSON");
        let json = serde_json::to_string_pretty(rules)
            .context("Не удалось сериализовать правила в JSON")?;
        Ok(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_iptables_rule() {
        let analyzer = FirewallAnalyzer::new();
        let line =
            "0     0 ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:22";
        let rule = analyzer.parse_iptables_rule(line, "filter", "INPUT", 0);

        assert!(rule.is_some());
        let rule = rule.unwrap();
        assert_eq!(rule.action, "ACCEPT");
        assert_eq!(rule.protocol, Some("tcp".to_string()));
        assert_eq!(rule.destination_port, Some("22".to_string()));
    }

    #[test]
    fn test_analyze_security_issues() {
        let analyzer = FirewallAnalyzer::new();

        let rules = vec![FirewallRule {
            firewall_type: "iptables".to_string(),
            table: "filter".to_string(),
            chain: "INPUT".to_string(),
            priority: 0,
            action: "ACCEPT".to_string(),
            protocol: None,
            source: Some("0.0.0.0/0".to_string()),
            destination: None,
            source_port: None,
            destination_port: None,
            interface: None,
            raw_rule: "ACCEPT all -- 0.0.0.0/0 0.0.0.0/0".to_string(),
        }];

        let issues = analyzer.analyze_security_issues(&rules);
        assert!(!issues.is_empty());
        assert!(issues
            .iter()
            .any(|issue| issue.contains("весь входящий трафик")));
    }
}
