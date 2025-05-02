use crate::comm::send_report;
use crate::host_info::get_host_info;
use crate::runtime_monitor::{scan_network_connections, scan_services};
use crate::static_scanner::scan_containers;
use chrono::prelude::*;
use common::Report;
use env_logger;
use log::{error, info};
use tokio;

mod comm;
mod host_info;
mod runtime_monitor;
mod static_scanner;

#[tokio::main]
async fn main() {
    env_logger::init();
    info!("Starting inventory agent");

    // Получение информации о хосте
    let host = match get_host_info() {
        Ok(host) => host,
        Err(e) => {
            error!("Failed to get host info: {}", e);
            return;
        }
    };

    // Сбор данных о контейнерах
    let containers = match scan_containers().await {
        Ok(containers) => containers,
        Err(e) => {
            error!("Failed to scan containers: {}", e);
            vec![]
        }
    };

    // Сбор сервисов
    let services = match scan_services() {
        Ok(services) => services,
        Err(e) => {
            error!("Failed to scan services: {}", e);
            vec![]
        }
    };

    // Сбор сетевых соединений
    let connections = match scan_network_connections() {
        Ok(connections) => connections,
        Err(e) => {
            error!("Failed to scan network connections: {}", e);
            vec![]
        }
    };

    // Формирование отчёта
    let report = Report {
        host,
        timestamp: Utc::now().to_rfc3339(),
        containers,
        services,
        connections,
    };

    // Отправка отчёта
    let server_url = "http://localhost:8080/report";
    match send_report(report, server_url).await {
        Ok(()) => info!("Report sent successfully"),
        Err(e) => error!("Failed to send report: {}", e),
    }
}
