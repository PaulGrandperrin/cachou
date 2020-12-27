use std::{time::Duration};

use sqlx::{Executor, Row, mysql::{MySqlConnectOptions, MySqlPoolOptions, MySqlRow}};
use tracing::trace;

// making things generic doesn't seem very useful at this point
#[derive(Debug, Clone)]
pub struct Db {
    pool: sqlx::Pool<sqlx::MySql>
}

impl Db {
    pub async fn new() -> anyhow::Result<Self> {
        
        let options = MySqlConnectOptions::new()
        .host("localhost")
        .port(4000)
        .username("root");

        let pool = MySqlPoolOptions::new()
            .connect_timeout(Duration::from_secs(1))
            .connect_with(options.clone())
            .await?;

        sqlx::query("create database if not exists `?`").bind(common::consts::DATABASE_NAME).execute(&pool).await?;
        drop(pool);

        let pool = MySqlPoolOptions::new()
        .connect_timeout(Duration::from_secs(1))
        .connect_with(
            options.database(common::consts::DATABASE_NAME)
        )
        .await?;

        let db = Self {
            pool
        };

        db.init().await?;

        Ok(db)
    }

    pub async fn test(&self) -> anyhow::Result<()> {
        // Make a simple query to return the given parameter
        let row: (i64,) = sqlx::query_as("SELECT 1+?")
        .bind(150_i64)
        .fetch_one(&self.pool).await?;

        anyhow::ensure!(row.0 == 151, "sql test failed");
        Ok(())
    }

    async fn init(&self) -> anyhow::Result<()> {
        self.pool.execute("create table if not exists `opaque` (`user_id` binary(32) not null, `ip` varbinary(16) not null, `expiration` timestamp not null, `state` varbinary(256) not null, primary key (user_id))").await?;
        Ok(())
    }

    pub async fn save_opaque_state(&self, user_id: &[u8], ip: &str, expiration: i64, state: &[u8]) -> anyhow::Result<()> {
        sqlx::query("insert into `opaque` values (?, INET_ATON(?), FROM_UNIXTIME(?), ?)")
        .bind(user_id)
        .bind(ip)
        .bind(expiration)
        .bind(state)
        .execute(&self.pool).await?;
        Ok(())
    }

    pub async fn restore_opaque_state(&self, user_id: &[u8]) -> anyhow::Result<Vec<u8>> {
        let row: MySqlRow = sqlx::query("select state from `opaque` where `user_id` = ?")
        .bind(user_id)
        .fetch_one(&self.pool).await?;

        Ok(row.try_get(0)?)
    }
}