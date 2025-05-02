use axum::{
    extract::State,
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use chrono::prelude::*;
use common::Report;
use env_logger;
use log::info;
use serde_json::json;
use std::{fs::OpenOptions, io::Write, net::SocketAddr};
use tokio::net::TcpListener;

#[derive(Clone)]
struct AppState {
    log_file: String,
}

#[tokio::main]
async fn main() {
    env_logger::init();
    info!("Starting mock server");

    let state = AppState {
        log_file: "received_reports.log".to_string(),
    };

    let app = Router::new()
        .route("/report", post(receive_report))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    let listener = TcpListener::bind(addr).await.unwrap();

    info!("Mock server listening on http://{}", addr);
    axum::serve(listener, app).await.unwrap();
}

async fn receive_report(
    State(state): State<AppState>,
    Json(report): Json<Report>,
) -> Result<impl IntoResponse, AppError> {
    // Логируем полученный отчёт
    info!(
        "Received report from host: {} ({})",
        report.host.mac_address, report.host.ip_address
    );

    // Сериализуем отчёт
    let log_line = serde_json::to_string(&report)
        .map_err(|e| AppError::Internal(format!("Failed to serialize report: {}", e)))?;

    // Записываем в файл с временной меткой
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(&state.log_file)
        .map_err(|e| AppError::Internal(format!("Failed to open log file: {}", e)))?;

    let log_entry = format!("[{}] {}\n", Utc::now().to_rfc3339(), log_line);
    writeln!(file, "{}", log_entry)
        .map_err(|e| AppError::Internal(format!("Failed to write to log file: {}", e)))?;

    Ok(StatusCode::OK)
}

// Кастомная ошибка для обработки
enum AppError {
    Internal(String),
    BadRequest(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AppError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
        };

        let body = json!({ "error": message }).to_string();
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("application/json"),
        );

        (status, headers, body).into_response()
    }
}

// Обработка ошибок десериализации
impl From<axum::extract::rejection::JsonRejection> for AppError {
    fn from(rejection: axum::extract::rejection::JsonRejection) -> Self {
        AppError::BadRequest(format!("Invalid JSON: {}", rejection))
    }
}
