use std::time::Duration;

use common::api;
use sqlx::{Database, Executor, MySql, Pool, Row, Transaction, mysql::{MySqlConnectOptions, MySqlDatabaseError, MySqlPoolOptions, MySqlRow}, pool::PoolConnection};
use async_trait::async_trait;
use tracing::error;

// making things generic over the Db implementation doesn't seem very useful at this point, but NewType are nices
#[derive(Debug)]
pub struct DbPool (Pool<MySql>);

#[derive(Debug)]
pub struct TxConn (Transaction<'static, MySql>);

#[derive(Debug)]
pub struct NormalConn (PoolConnection<MySql>);

#[derive(Debug)]
pub struct DbConn<'pool> {
    pool: &'pool Pool<MySql>,
    tx: Option<TxConn>,
    normal: Option<NormalConn>,
}

impl<'pool> DbConn<'pool> {
    fn from_pool(pool: &'pool Pool<MySql>) -> DbConn<'pool> {
        Self {
            pool,
            tx: None,
            normal: None,
        }
    }

    pub async fn commit(mut self) -> api::Result<()> {
        println!("commit");
        if let Some(tx) = self.tx.take() {
            tx.0.commit().await.map_err(|e| api::Error::ServerSideError(e.into()))?;
        }
        Ok(())
    }

    pub async fn rollback(mut self) -> api::Result<()> {
        println!("rollback");
        if let Some(tx) = self.tx.take() {
            tx.0.rollback().await.map_err(|e| api::Error::ServerSideError(e.into()))?;
        }
        Ok(())
    }

    pub async fn tx(&mut self) -> api::Result<&mut TxConn> {
        if self.tx.is_none() {
            self.tx = Some(TxConn(self.pool.begin().await.map_err(|e| api::Error::ServerSideError(e.into()))?));
        }

        Ok(self.tx.as_mut().unwrap())

        // when https://github.com/rust-lang/rust/issues/78271 is merged:
        /* Ok(
            match self.tx {
                Some(tx) => {
                    &mut tx
                }
                None => {
                    TxConn(self.pool.begin().await.map_err(|e| api::Error::ServerSideError(e.into()))?)
                }
            }
        ) */
    }

    pub async fn normal(&mut self) -> api::Result<&mut NormalConn> {
        if self.normal.is_none() {
            self.normal = Some(NormalConn(self.pool.acquire().await.map_err(|e| api::Error::ServerSideError(e.into()))?));
        }

        Ok(self.normal.as_mut().unwrap())

        // when https://github.com/rust-lang/rust/issues/78271 is merged:
        /* Ok(
            match self.normal {
                Some(normal) => {
                    &mut normal
                }
                None => {
                    NormalConn(self.pool.begin().await.map_err(|e| api::Error::ServerSideError(e.into()))?)
                }
            }
        ) */
    }
}

impl Drop for DbConn<'_> {
    fn drop(&mut self) {
        if self.tx.is_some() {
            error!("sql::DbConn was dropped without being commited or rollbacked with a transaction in progress")
        }
    }
}

impl DbPool {
    pub fn acquire<'pool>(&'pool self) -> DbConn<'pool> {
        DbConn::from_pool(&self.0)
    }

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

        let db = Self(pool);

        db.init().await?;

        Ok(db)
    }

    pub async fn drop_database(&self) -> eyre::Result<()> {
        self.0.execute(&*format!("drop database `{}`", common::consts::DATABASE_NAME)).await?;
        Ok(())
    }

    pub async fn test(&self) -> eyre::Result<()> {
        // Make a simple query to return the given parameter
        let row: (i64,) = sqlx::query_as("SELECT 1+?")
            .bind(150_i64)
            .fetch_one(&self.0).await?;

        eyre::ensure!(row.0 == 151, "sql test failed");
        Ok(())
    }

    async fn init(&self) -> eyre::Result<()> {

        let mut conn = self.0.acquire().await?;

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
            create table if not exists `users` (
                `user_id`             binary(16)      not null,
                `sealed_private_data` varbinary(1024)         ,
                `totp`                varchar(256)            ,
                primary key (`user_id`)
            )
        ").await?;

        conn.execute("
            create table if not exists `credentials` (
                `recovery`          tinyint unsigned not null,
                `username`          varbinary(32)    not null,
                `opaque_password`   varbinary(1024)  not null,
                `sealed_master_key` varbinary(256)   not null,
                `sealed_export_key` varbinary(256)   not null,
                `user_id`           binary(16)       not null,
                primary key (`recovery`, `username`)
            )
    ").await?;

        Ok(())
    }
}


// queries that are only defined on a transactionnal connection
impl TxConn {
    #[tracing::instrument]
    async fn restore_tmp(&mut self, session_id: &[u8], field: &str) -> api::Result<Vec<u8>> {        
        let row: MySqlRow = sqlx::query("select `data` from `tmp` where `session_id` = ? and `field` = ?")
            .bind(session_id)
            .bind(field)
            .fetch_one(&mut self.0).await.map_err(|e| api::Error::ServerSideError(e.into()))?;
        let state: Vec<u8> = row.try_get(0).map_err(|e| api::Error::ServerSideError(e.into()))?;

        sqlx::query("delete from `tmp` where `session_id` = ? and `field` = ?")
            .bind(session_id)
            .bind(field)
            .execute(&mut self.0).await.map_err(|e| api::Error::ServerSideError(e.into()))?;

        Ok(state)
    }
}

// queries that are defined on any kind of connection (transactionnal or not)
#[async_trait]
pub trait Queryable: std::fmt::Debug {
    fn conn(&mut self) -> &mut <MySql as Database>::Connection;

    #[tracing::instrument]
    async fn save_tmp(&mut self, session_id: &[u8], ip: &str, expiration: i64, field: &str, data: &[u8]) -> api::Result<()> {
        
        sqlx::query("replace into `tmp` values (?, INET_ATON(?), FROM_UNIXTIME(?), ?, ?)")
            .bind(session_id)
            .bind(ip)
            .bind(expiration)
            .bind(field)
            .bind(data)
            .execute(self.conn()).await.map_err(|e| api::Error::ServerSideError(e.into()))?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    #[tracing::instrument]
    async fn new_user(&mut self, user_id: &[u8]) -> api::Result<()> {
        sqlx::query("insert into `users` (`user_id`) values (?)")
            .bind(user_id)
            .execute(self.conn()).await.map_err(|e| {
                match e {
                    sqlx::Error::Database(e)
                        if e.as_error().downcast_ref::<MySqlDatabaseError>().map(|e| e.number()) == Some(1062)
                        => api::Error::Conflict,
                    _ => api::Error::ServerSideError(e.into()),
                }
            })?;

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    #[tracing::instrument]
    async fn set_credentials(&mut self, recovery: bool, username: &[u8], opaque_password: &[u8], sealed_master_key: &[u8], sealed_export_key: &[u8], user_id: &[u8], ) -> api::Result<()> {
        sqlx::query("replace into `credentials` set `recovery` = ?, `username` = ?, `opaque_password` = ?, `sealed_master_key` = ?, `sealed_export_key` = ?, `user_id` = ?")
            .bind(if recovery {1} else {0})
            .bind(username)
            .bind(opaque_password)
            .bind(sealed_master_key)
            .bind(sealed_export_key)
            .bind(user_id)
            .execute(self.conn()).await.map_err(|e| {
                match e {
                    sqlx::Error::Database(e)
                        if e.as_error().downcast_ref::<MySqlDatabaseError>().map(|e| e.number()) == Some(1062)
                        => api::Error::Conflict, // the username is already taken
                    _ => api::Error::ServerSideError(e.into()),
                }
            })?;

        Ok(())
    }

    #[tracing::instrument]
    async fn get_credentials_from_username(&mut self, recovery: bool, username: &[u8]) -> api::Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let row = sqlx::query("select `user_id`, `opaque_password`, `sealed_master_key` from `credentials` where `recovery` = ? and `username` = ?")
            .bind(if recovery {1} else {0})    
            .bind(username)
            .fetch_one(self.conn()).await.map_err(|e| {
                match e {
                    sqlx::Error::RowNotFound => api::Error::NotFound,
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
    async fn get_user_private_data(&mut self, user_id: &[u8]) -> api::Result<Vec<u8>> {
        let row: MySqlRow = sqlx::query("select `sealed_private_data` from `users` where `user_id` = ?")
        .bind(user_id)
        .fetch_one(self.conn()).await.map_err(|e| {
            match e {
                _ => api::Error::ServerSideError(e.into()),
            }
        })?;

        Ok(
            row.try_get(0).map_err(|e| api::Error::ServerSideError(e.into()))?,
        )
    }

    #[tracing::instrument]
    async fn set_user_private_data(&mut self, user_id: &[u8], sealed_private_data: &[u8]) -> api::Result<()> {
        sqlx::query("update `users` set `sealed_private_data` = ? where `user_id` = ?")
            .bind(sealed_private_data)
            .bind(user_id)
            .execute(self.conn()).await.map_err(|e| {
                match e {
                    _ => api::Error::ServerSideError(e.into()),
                }
            })?;

        Ok(())
    }
}


impl<'pool> Queryable for TxConn {
    fn conn(&mut self) -> &mut <MySql as sqlx::Database>::Connection {
        &mut self.0
    }
}

impl<'pool> Queryable for NormalConn {
    fn conn(&mut self) -> &mut <MySql as sqlx::Database>::Connection {
        &mut self.0
    }
}
