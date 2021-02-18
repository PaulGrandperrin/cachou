use std::{time::Duration};

use common::api;
use sqlx::{Executor, Row, mysql::{MySqlConnectOptions, MySqlDatabaseError, MySqlPoolOptions, MySqlRow}};
use tracing::{error, trace};

// making things generic doesn't seem very useful at this point
#[derive(Debug, Clone)]
pub struct Db {
    pool: sqlx::Pool<sqlx::MySql>
}

impl Db {
    pub async fn new() -> eyre::Result<Self> {
        
        let options = MySqlConnectOptions::new()
        .host("localhost")
        .port(4000)
        .username("root");

        let pool = MySqlPoolOptions::new()
            .connect_timeout(Duration::from_secs(1))
            .connect_with(options.clone())
            .await?;

        sqlx::query(&format!("create database if not exists `{}`", common::consts::DATABASE_NAME)).execute(&pool).await?;
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

    pub async fn drop_database(&self) -> eyre::Result<()> {
        self.pool.execute(&*format!("drop database `{}`", common::consts::DATABASE_NAME)).await?;
        Ok(())
    }

    pub async fn test(&self) -> eyre::Result<()> {
        // Make a simple query to return the given parameter
        let row: (i64,) = sqlx::query_as("SELECT 1+?")
        .bind(150_i64)
        .fetch_one(&self.pool).await?;

        eyre::ensure!(row.0 == 151, "sql test failed");
        Ok(())
    }

    async fn init(&self) -> eyre::Result<()> {

        let mut conn = self.pool.acquire().await?;

        // https://docs.pingcap.com/tidb/dev/clustered-indexes
        conn.execute("set session tidb_enable_clustered_index = 1").await?;

        conn.execute("
            create table if not exists `tmp` (
                `session_id` binary(32) not null,
                `ip` varbinary(16) not null,
                `expiration` timestamp not null,
                `field` varchar(32) not null, 
                `data` varbinary(1024) not null,
                primary key (session_id, field)
            )
        ").await?;

        conn.execute("
            create table if not exists `user` (
                `user_id` binary(32) not null,
                `username` varchar(64) not null,
                `opaque_password` varbinary(1024) not null,
                `hashed_secret_id` binary(32) not null,
                `sealed_masterkey` varbinary(256) not null,
                `sealed_private_data` varbinary(1024) not null,
                primary key (user_id),
                unique index unique_username (username),
                index hashed_secret_id (hashed_secret_id)
            )
        ").await?;

        Ok(())
    }

    #[tracing::instrument]
    pub async fn save_tmp(&self, session_id: &[u8], ip: &str, expiration: i64, field: &str, data: &[u8]) -> api::Result<()> {
        sqlx::query("replace into `tmp` values (?, INET_ATON(?), FROM_UNIXTIME(?), ?, ?)")
        .bind(session_id)
        .bind(ip)
        .bind(expiration)
        .bind(field)
        .bind(data)
        .execute(&self.pool).await.map_err(|e| eyre::eyre!(e))?;
        Ok(())
    }

    #[tracing::instrument]
    pub async fn restore_tmp(&self, session_id: &[u8], field: &str) -> api::Result<Vec<u8>> {
        let mut tx = self.pool.begin().await.map_err(|e| eyre::eyre!(e))?;
        
        let row: MySqlRow = sqlx::query("select `data` from `tmp` where `session_id` = ? and `field` = ?")
        .bind(session_id)
        .bind(field)
        .fetch_one(&mut tx).await.map_err(|e| eyre::eyre!(e))?;
        let state: Vec<u8> = row.try_get(0).map_err(|e| eyre::eyre!(e))?;

        sqlx::query("delete from `tmp` where `session_id` = ? and `field` = ?")
        .bind(session_id)
        .bind(field)
        .execute(&mut tx).await.map_err(|e| eyre::eyre!(e))?;

        tx.commit().await.map_err(|e| eyre::eyre!(e))?;

        Ok(state)
    }

    #[tracing::instrument]
    pub async fn insert_user(&self, user_id: &[u8], username: &str, opaque_password: &[u8], hashed_secret_id: &[u8], sealed_masterkey: &[u8], sealed_private_data: &[u8]) -> api::Result<()> {
        sqlx::query("insert into `user` values (?, ?, ?, ?, ?, ?)")
                .bind(user_id)
                .bind(username)
                .bind(opaque_password)
                .bind(hashed_secret_id)
                .bind(sealed_masterkey)
                .bind(sealed_private_data)
                .execute(&self.pool).await.map_err(|e| {
                    match e {
                        sqlx::Error::Database(e)
                            if e.as_error().downcast_ref::<MySqlDatabaseError>().map(|e| e.number()) == Some(1062)
                            => api::Error::UsernameConflict(username.into()),
                        _ => api::Error::ServerSideError(e.into()),
                    }
                })?;

        Ok(())
    }

    #[tracing::instrument]
    pub async fn get_userid_and_opaque_password_from_username(&self, username: &str) -> api::Result<(Vec<u8>, Vec<u8>)> {
        let row: MySqlRow = sqlx::query("select `user_id`, `opaque_password` from `user` where `username` = ?")
        .bind(username)
        .fetch_one(&self.pool).await.map_err(|e| {
            match e {
                sqlx::Error::RowNotFound => api::Error::UsernameNotFound(username.into()),
                _ => api::Error::ServerSideError(e.into()),
            }
        })?;

        Ok((
            row.try_get(0).map_err(|e| eyre::eyre!(e))?,
            row.try_get(1).map_err(|e| eyre::eyre!(e))?,
        ))
    }

    #[tracing::instrument]
    pub async fn get_user_data_from_userid(&self, user_id: &[u8]) -> api::Result<(Vec<u8>, Vec<u8>)> {
        let row: MySqlRow = sqlx::query("select `sealed_masterkey`, `sealed_private_data` from `user` where `user_id` = ?")
        .bind(user_id)
        .fetch_one(&self.pool).await.map_err(|e| eyre::eyre!(e))?; // do not leak in returned error if the user_id exists or not

        Ok((
            row.try_get(0).map_err(|e| eyre::eyre!(e))?,
            row.try_get(1).map_err(|e| eyre::eyre!(e))?,
        ))
    }
}