use chrono::Utc;
use log::{debug, error, info, warn};
use serde_derive::Serialize;
use std::borrow::Cow;
use std::env;
use std::sync::Arc;

// Logger structure
pub struct Logger {
    watchtower_enabled: bool,
    client: Arc<reqwest::Client>,
    watchtower_token: Option<String>,
    watchtower_app_id: Option<String>,
    watchtower_endpoint: Option<String>,
    log_types: Option<LogTypes>,
}

// Struct for log types
#[derive(Clone)]
struct LogTypes {
    info: String,
    warning: String,
    severe: String,
}

// Enum for log types
#[derive(Clone)]
#[allow(dead_code)]
pub enum LogType {
    Info,
    Warning,
    Severe,
    Debug,
}

#[derive(Serialize)]
struct LogData<'a> {
    token: &'a str,
    log: LogPayload<'a>,
}

#[derive(Serialize)]
struct LogPayload<'a> {
    app_id: &'a str,
    r#type: &'a str,
    message: Cow<'a, str>,
    timestamp: i64,
}

impl Logger {
    #![allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let watchtower_enabled =
            env::var("WATCHTOWER_ENABLED").unwrap_or_else(|_| "false".to_string()) == "true";

        let (watchtower_token, watchtower_app_id, watchtower_endpoint, log_types) =
            if watchtower_enabled {
                (
                    Some(env::var("WATCHTOWER_TOKEN").expect("WATCHTOWER_TOKEN must be set")),
                    Some(env::var("WATCHTOWER_APP_ID").expect("WATCHTOWER_APP_ID must be set")),
                    Some(env::var("WATCHTOWER_ENDPOINT").expect("WATCHTOWER_ENDPOINT must be set")),
                    Some(LogTypes {
                        info: env::var("WATCHTOWER_LOG_TYPE_INFO")
                            .expect("WATCHTOWER_LOG_TYPE_INFO must be set"),
                        warning: env::var("WATCHTOWER_LOG_TYPE_WARNING")
                            .expect("WATCHTOWER_LOG_TYPE_WARNING must be set"),
                        severe: env::var("WATCHTOWER_LOG_TYPE_SEVERE")
                            .expect("WATCHTOWER_LOG_TYPE_SEVERE must be set"),
                    }),
                )
            } else {
                (None, None, None, None)
            };

        Logger {
            watchtower_enabled,
            watchtower_token,
            watchtower_app_id,
            watchtower_endpoint,
            log_types,
            client: Arc::new(reqwest::Client::new()),
        }
    }

    async fn post_log(&self, log_type: LogType, message: Cow<'static, str>) {
        if let (
            Some(watchtower_token),
            Some(watchtower_app_id),
            Some(watchtower_endpoint),
            Some(log_types),
        ) = (
            &self.watchtower_token,
            &self.watchtower_app_id,
            &self.watchtower_endpoint,
            &self.log_types,
        ) {
            let client = Arc::clone(&self.client);

            let data = LogData {
                token: watchtower_token,
                log: LogPayload {
                    app_id: watchtower_app_id,
                    r#type: match log_type {
                        LogType::Info => &log_types.info,
                        LogType::Warning => &log_types.warning,
                        LogType::Severe => &log_types.severe,
                        LogType::Debug => panic!("Debug logs are local only"),
                    },
                    message: Cow::Owned(message.into_owned()),
                    timestamp: Utc::now().timestamp_millis(),
                },
            };

            let response = client.post(watchtower_endpoint).json(&data).send().await;

            match response {
                Ok(res) if res.status().is_success() => (),
                Ok(res) => eprintln!(
                    "Failed to post log: {:?}",
                    res.text().await.unwrap_or_default()
                ),
                Err(err) => eprintln!("Failed to post log: {:?}", err),
            }
        }
    }

    pub async fn async_info<S>(&self, message: S)
    where
        S: Into<Cow<'static, str>> + std::fmt::Display + Send + 'static,
    {
        info!("{}", &message);
        if self.watchtower_enabled {
            self.post_log(LogType::Info, message.into()).await;
        }
    }

    pub async fn async_warning<S>(&self, message: S)
    where
        S: Into<Cow<'static, str>> + std::fmt::Display + Send + 'static,
    {
        warn!("{}", &message);
        if self.watchtower_enabled {
            self.post_log(LogType::Warning, message.into()).await;
        }
    }

    pub async fn async_severe<S>(&self, message: S)
    where
        S: Into<Cow<'static, str>> + std::fmt::Display + Send + 'static,
    {
        error!("{}", &message);
        if self.watchtower_enabled {
            self.post_log(LogType::Severe, message.into()).await;
        }
    }

    pub fn info<S>(&self, message: S)
    where
        S: Into<Cow<'static, str>> + std::fmt::Display + Send + 'static,
    {
        let logger_clone = self.clone();
        tokio::spawn(async move {
            logger_clone.async_info(message).await;
        });
    }

    pub fn warning<S>(&self, message: S)
    where
        S: Into<Cow<'static, str>> + std::fmt::Display + Send + 'static,
    {
        let logger_clone = self.clone();
        tokio::spawn(async move {
            logger_clone.async_warning(message).await;
        });
    }

    pub fn severe<S>(&self, message: S)
    where
        S: Into<Cow<'static, str>> + std::fmt::Display + Send + 'static,
    {
        let logger_clone = self.clone();
        tokio::spawn(async move {
            logger_clone.async_severe(message).await;
        });
    }

    pub fn debug<S>(&self, message: S)
    where
        S: Into<Cow<'static, str>> + std::fmt::Display,
    {
        debug!("{}", &message);
    }
}

impl Clone for Logger {
    fn clone(&self) -> Self {
        Logger {
            watchtower_enabled: self.watchtower_enabled,
            watchtower_token: self.watchtower_token.clone(),
            watchtower_app_id: self.watchtower_app_id.clone(),
            watchtower_endpoint: self.watchtower_endpoint.clone(),
            log_types: self.log_types.clone(),
            client: Arc::clone(&self.client),
        }
    }
}
