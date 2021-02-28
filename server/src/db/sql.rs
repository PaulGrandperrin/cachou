use std::{time::Duration};

use common::api;
use sqlx::{Executor, Row, mysql::{MySqlConnectOptions, MySqlDatabaseError, MySqlPoolOptions, MySqlRow}};
use tracing::{error, trace};
use eyre::{eyre, WrapErr};

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
                `version` bigint unsigned not null,
                `username` varbinary(32) not null,
                `opaque_password` varbinary(1024) not null,
                `username_recovery` varbinary(32) not null,
                `opaque_password_recovery` varbinary(1024) not null,
                `sealed_master_key` varbinary(256) not null,
                `sealed_private_data` varbinary(1024) not null,
                `totp_uri` varchar(256),
                primary key (user_id),
                unique index unique_username (username),
                unique index unique_username_recovery (username_recovery)
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
            .execute(&self.pool).await.map_err(|e| api::Error::ServerSideError(e.into()))?;
        Ok(())
    }

    #[tracing::instrument]
    pub async fn restore_tmp(&self, session_id: &[u8], field: &str) -> api::Result<Vec<u8>> {
        let mut tx = self.pool.begin().await.map_err(|e| api::Error::ServerSideError(e.into()))?;
        
        let row: MySqlRow = sqlx::query("select `data` from `tmp` where `session_id` = ? and `field` = ?")
            .bind(session_id)
            .bind(field)
            .fetch_one(&mut tx).await.map_err(|e| api::Error::ServerSideError(e.into()))?;
        let state: Vec<u8> = row.try_get(0).map_err(|e| api::Error::ServerSideError(e.into()))?;

        sqlx::query("delete from `tmp` where `session_id` = ? and `field` = ?")
            .bind(session_id)
            .bind(field)
            .execute(&mut tx).await.map_err(|e| api::Error::ServerSideError(e.into()))?;

        tx.commit().await.map_err(|e| api::Error::ServerSideError(e.into()))?;

        Ok(state)
    }

    #[tracing::instrument]
    pub async fn new_user(&self, user_id: &[u8], mut version: u64, username: &[u8], opaque_password: &[u8], username_recovery: &[u8], opaque_password_recovery: &[u8], sealed_master_key: &[u8], sealed_private_data: &[u8], totp_uri: &Option<String>) -> api::Result<u64> {
        version += 1;
        sqlx::query("insert into `user` (`user_id`, `version`, `username`, `opaque_password`, `username_recovery`, `opaque_password_recovery`, `sealed_master_key`, `sealed_private_data`, `totp_uri`) values (?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(user_id)
            .bind(version)
            .bind(username)
            .bind(opaque_password)
            .bind(username_recovery)
            .bind(opaque_password_recovery)
            .bind(sealed_master_key)
            .bind(sealed_private_data)
            .bind(totp_uri)
            .execute(&self.pool).await.map_err(|e| {
                match e {
                    sqlx::Error::Database(e)
                        if e.as_error().downcast_ref::<MySqlDatabaseError>().map(|e| e.number()) == Some(1062)
                        => api::Error::UsernameConflict,
                    _ => api::Error::ServerSideError(e.into()),
                }
            })?;

        Ok(version)
    }

    #[tracing::instrument]
    pub async fn change_user_credentials(&self, user_id: &[u8], mut version: u64, username: &[u8], opaque_password: &[u8], sealed_master_key: &[u8], sealed_private_data: &[u8], recovery: bool) -> api::Result<u64> {
        let mut tx = self.pool.begin().await.map_err(|e| api::Error::ServerSideError(e.into()))?;
        
        let row: MySqlRow = sqlx::query("select `version` from `user` where `user_id` = ?")
            .bind(user_id)
            .fetch_one(&mut tx).await.map_err(|e| api::Error::ServerSideError(e.into()))?;
        let db_version: u64 = row.try_get(0).map_err(|e| api::Error::ServerSideError(e.into()))?;
        
        if db_version != version { 
            return Err(api::Error::VersionConflict(db_version, version));
        };

        version +=1;

        let query = format!("update `user` set `version` = ?, `username{0}` = ?, `opaque_password{0}` = ?, `sealed_master_key` = ?, `sealed_private_data` = ? where `user_id` = ?", if recovery {"_recovery"} else {""});
        sqlx::query(&query)
            .bind(version)
            .bind(username)
            .bind(opaque_password)
            .bind(sealed_master_key)
            .bind(sealed_private_data)
            .bind(user_id)
            .execute(&mut tx).await.map_err(|e| {
                match e {
                    sqlx::Error::Database(e)
                        if e.as_error().downcast_ref::<MySqlDatabaseError>().map(|e| e.number()) == Some(1062)
                        => api::Error::UsernameConflict,
                    _ => api::Error::ServerSideError(e.into()),
                }
            })?;

        tx.commit().await.map_err(|e| api::Error::ServerSideError(e.into()))?;

        Ok(version)
    }

    #[tracing::instrument]
    pub async fn get_credentials_from_username(&self, username: &[u8], recovery: bool) -> api::Result<(Vec<u8>, u64, Vec<u8>)> {
        let query = format!("select `user_id`, `version`, `opaque_password{0}` from `user` where `username{0}` = ?", if recovery {"_recovery"} else {""});
        let row = sqlx::query(&query)
            .bind(username).fetch_one(&self.pool).await.map_err(|e| {
                match e {
                    sqlx::Error::RowNotFound => api::Error::UsernameNotFound,
                    _ => api::Error::ServerSideError(e.into()),
                }
            })?;

        Ok((
            row.try_get(0).map_err(|e| api::Error::ServerSideError(e.into()))?,
            row.try_get(1).map_err(|e| api::Error::ServerSideError(e.into()))?,
            row.try_get(2).map_err(|e| api::Error::ServerSideError(e.into()))?,
        ))
    }

    #[tracing::instrument]
    pub async fn get_user_from_userid(&self, user_id: &[u8], version: u64) -> api::Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let row: MySqlRow = sqlx::query("select `sealed_master_key`, `sealed_private_data`, `username` from `user` where `user_id` = ? and `version` = ?")
        .bind(user_id)
        .bind(version)
        .fetch_one(&self.pool).await.map_err(|e| api::Error::ServerSideError(e.into()))?; // do not leak in returned error if the user_id exists or not

        Ok((
            row.try_get(0).map_err(|e| api::Error::ServerSideError(e.into()))?,
            row.try_get(1).map_err(|e| api::Error::ServerSideError(e.into()))?,
            row.try_get(2).map_err(|e| api::Error::ServerSideError(e.into()))?,
        ))
    }

    #[tracing::instrument]
    pub async fn get_username_from_userid(&self, user_id: &[u8], version: u64) -> api::Result<Vec<u8>> {
        let row: MySqlRow = sqlx::query("select `username` from `user` where `user_id` = ? and `version` = ? ")
        .bind(user_id)
        .bind(version)
        .fetch_one(&self.pool).await.map_err(|e| api::Error::ServerSideError(e.into()))?; // do not leak in returned error if the user_id exists or not

        Ok(
            row.try_get(0).map_err(|e| api::Error::ServerSideError(e.into()))?,
        )
    }

    #[tracing::instrument]
    pub async fn change_totp(&self, user_id: &[u8], version: u64, totp_uri: &Option<String>) -> api::Result<()> {
        sqlx::query("update `user` set `totp_uri` = ? where `user_id` = ? and `version` = ?")
            .bind(totp_uri)
            .bind(user_id)
            .bind(version)
            .execute(&self.pool).await.map_err(|e| api::Error::ServerSideError(e.into()))?; 

        // TODO handle version conflict

        Ok(())
    }
    
}