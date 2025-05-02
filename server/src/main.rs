use axum::{routing::post, serve, Json, Router};
use serde::{Deserialize, Serialize};
use std::{fs::OpenOptions, io::Write, net::SocketAddr};
use tokio::net::TcpListener;

#[derive(Debug, Deserialize, Serialize)]
struct Report {
    host_id: String,
    timestamp: String,
    containers: Vec<ContainerInfo>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ContainerInfo {
    id: String,
    name: String,
    image: String,
    ports: Vec<String>,
    status: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let app = Router::new().route("/report", post(receive_report));

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    let listener = TcpListener::bind(addr).await.unwrap();

    println!("Mock server listening on http://{}", addr);
    serve(listener, app).await.unwrap();
}

async fn receive_report(Json(report): Json<Report>) {
    println!("Received report from host: {}", report.host_id);

    let log_line = serde_json::to_string(&report).unwrap();
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open("received_reports.log")
        .unwrap();

    writeln!(file, "{}", log_line).unwrap();
}
