use std::{time::Duration};

use sqlx::{Executor, mysql::{MySqlConnectOptions, MySqlPoolOptions}};

const DATABASE_NAME: &str = "cachou";

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

        sqlx::query("create database if not exists `?`").bind(DATABASE_NAME).execute(&pool).await?;
        drop(pool);

        let pool = MySqlPoolOptions::new()
        .connect_timeout(Duration::from_secs(1))
        .connect_with(
            options.database(DATABASE_NAME)
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
        self.pool.execute("create table if not exists `opaque` (id bigint unsigned not null auto_increment, ip varbinary(16) not null, expiration timestamp not null, data varbinary(256) not null, primary key (id))").await?;
        Ok(())
    }
}