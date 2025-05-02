// system-agent/src/main.rs
use anyhow::Result;
use clap::Parser;
use log::{info, warn};
use std::path::PathBuf;
use std::time::Duration;
use tokio::time;

// use crate::system_agent::collector::{Collector, CollectorConfig};
use system_agent::communication::client::Client;

#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Args {
    /// Адрес сервера для отправки данных
    #[clap(short, long, default_value = "http://0.0.0.0:8080/report")]
    server_url: String,

    /// Корневая директория для сканирования
    #[clap(short, long, default_value = "/")]
    root_path: PathBuf,

    /// Интервал между сборами данных (в секундах)
    #[clap(short, long, default_value = "60")]
    interval: u64,

    /// Детальное логгирование
    #[clap(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Инициализация логгирования
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "info"
        },
    ))
    .init();

    let args = Args::parse();
    info!("Запуск системного агента...");
    info!(
        "Конфигурация: сервер={}, интервал={}с, путь={}",
        args.server_url,
        args.interval,
        args.root_path.display()
    );

    // Инициализация клиента для отправки данных
    let client = Client::new(&args.server_url);

    // Конфигурация коллектора данных
    // let collector_config = CollectorConfig {
    //     root_path: args.root_path,
    //     collect_logs: true,
    //     collect_metrics: true,
    //     collect_network: true,
    //     collect_processes: true,
    //     detailed_scan: args.verbose,
    // };

    // Создание коллектора
    // let mut collector = Collector::new(collector_config)?;
    info!("Коллектор данных инициализирован");

    // Первичное сканирование статических данных
    info!("Выполнение первичного статического анализа...");
    // let static_data = collector.collect_static_data()?;
    let static_data = 2; // Заглушка для статических данных
    client.send_data(&static_data).await?;
    info!("Первичные данные отправлены на сервер");

    // Основной цикл сбора и отправки данных
    let mut interval = time::interval(Duration::from_secs(args.interval));
    info!(
        "Запуск основного цикла мониторинга с интервалом {} секунд",
        args.interval
    );

    loop {
        interval.tick().await;
        info!("Сбор текущих данных...");

        // match collector.collect_all_data().await {
        //     Ok(data) => {
        //         info!("Данные собраны успешно, отправка на сервер...");

        //         match client.send_data(&data).await {
        //             Ok(_) => info!("Данные успешно отправлены"),
        //             Err(e) => warn!("Ошибка при отправке данных: {}", e),
        //         }
        //     }
        //     Err(e) => warn!("Ошибка при сборе данных: {}", e),
        // }
    }
}
