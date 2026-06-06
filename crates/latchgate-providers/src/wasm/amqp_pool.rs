//! AMQP connection pool — `deadpool::managed::Manager` for lapin 4.x.
//!
//! `deadpool-lapin` has no release compatible with lapin 4.x at this time.
//! This module provides a minimal managed-pool implementation that creates
//! and health-checks lapin connections directly.
//!
//! The Manager is intentionally thin: connection configuration (URL, TLS)
//! is handled by lapin; recycling checks the broker-reported connection
//! status. No reconnect-on-recycle — a closed connection is discarded and
//! the pool creates a fresh one on the next `get()`.

use deadpool::managed;

/// Deadpool manager that creates [`lapin::Connection`]s and recycles them
/// based on broker-reported connection status.
pub(crate) struct Manager {
    url: String,
}

impl Manager {
    pub(crate) fn new(url: impl Into<String>) -> Self {
        Self { url: url.into() }
    }
}

impl managed::Manager for Manager {
    type Type = lapin::Connection;
    type Error = lapin::Error;

    async fn create(&self) -> Result<lapin::Connection, lapin::Error> {
        lapin::Connection::connect(&self.url, lapin::ConnectionProperties::default()).await
    }

    async fn recycle(
        &self,
        conn: &mut lapin::Connection,
        _metrics: &managed::Metrics,
    ) -> managed::RecycleResult<lapin::Error> {
        if conn.status().connected() {
            Ok(())
        } else {
            Err(managed::RecycleError::message(
                "AMQP connection closed by broker",
            ))
        }
    }
}

/// AMQP connection pool backed by deadpool.
pub(crate) type Pool = managed::Pool<Manager>;
