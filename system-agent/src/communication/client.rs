
use anyhow::{Result, Context};
use log::{info, debug, warn, error};
use reqwest::{Client as HttpClient, ClientBuilder};
use serde::Serialize;
use std::time::Duration;

/// Клиент для отправки данных на сервер
pub struct Client {
    /// URL сервера
    server_url: String,
    /// HTTP клиент
    http_client: HttpClient,
}

impl Client {
    /// Создает новый клиент
    pub fn new(server_url: &str) -> Self {
        let http_client = ClientBuilder::new()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .user_agent("system-agent/0.1.0")
            .build()
            .unwrap_or_else(|_| {
                warn!("Не удалось создать HTTP клиент с настроенными таймаутами, используется клиент по умолчанию");
                HttpClient::new()
            });
        
        Self {
            server_url: server_url.to_string(),
            http_client,
        }
    }
    
    /// Отправляет данные на сервер
    pub async fn send_data<T: Serialize>(&self, data: &T) -> Result<()> {
        debug!("Подготовка данных для отправки на сервер: {}", self.server_url);
        
        // Отправка данных через HTTP POST
        let response = self.http_client.post(&self.server_url)
            .json(data)
            .send()
            .await
            .context("Ошибка при отправке данных на сервер")?;
        
        // Проверка статуса ответа
        if response.status().is_success() {
            debug!("Данные успешно отправлены на сервер");
            Ok(())
        } else {
            let status = response.status();
            let error_text = response.text().await
                .unwrap_or_else(|_| "Не удалось получить текст ошибки".to_string());
            
            error!("Сервер вернул ошибку: {} - {}", status, error_text);
            anyhow::bail!("Сервер вернул ошибку: {} - {}", status, error_text)
        }
    }
    
    /// Проверяет доступность сервера
    pub async fn check_server(&self) -> Result<bool> {
        debug!("Проверка доступности сервера: {}", self.server_url);
        
        // Отправка запроса HEAD для проверки доступности
        let response = self.http_client.head(&self.server_url)
            .send()
            .await;
        
        match response {
            Ok(resp) => {
                let available = resp.status().is_success();
                debug!("Сервер доступен: {}", available);
                Ok(available)
            },
            Err(e) => {
                warn!("Сервер недоступен: {}", e);
                Ok(false)
            }
        }
    }
    
    /// Устанавливает новый URL сервера
    pub fn set_server_url(&mut self, server_url: &str) {
        self.server_url = server_url.to_string();
    }
}