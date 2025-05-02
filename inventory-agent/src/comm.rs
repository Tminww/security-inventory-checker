use common::Report;
use log::{error, info};
use reqwest::Client;
use std::error::Error;

pub async fn send_report(report: Report, server_url: &str) -> Result<(), Box<dyn Error>> {
    let client = Client::new();

    // Логируем отправляемый JSON
    let report_json = serde_json::to_string_pretty(&report)?;
    info!("Sending report to {}:\n{}", server_url, report_json);

    let response = client
        .post(server_url)
        .header("Content-Type", "application/json")
        .json(&report)
        .send()
        .await?;

    if response.status().is_success() {
        info!("Report sent successfully");
        Ok(())
    } else {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        error!("Failed to send report: {} - Response: {}", status, body);
        Err(format!("HTTP error: {} - {}", status, body).into())
    }
}
