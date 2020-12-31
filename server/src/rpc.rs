use std::convert::TryInto;

use api::Rpc;
use common::api::{self, Call, GetUserIdFromEmail, SignupStart};
use serde::Serialize;
use tide::{Body, Request};
use tracing::trace;
use async_trait::async_trait;

use crate::core::auth;

pub trait RpcRetEncode {
    fn encode(&self) -> anyhow::Result<Vec<u8>>;
}

impl<T: Serialize> RpcRetEncode for T {
    fn encode(&self) -> anyhow::Result<Vec<u8>> {
        Ok(rmp_serde::to_vec_named(&self)?)
    }
}

#[async_trait]
pub trait RpcExec: Send + Sync {
    async fn exec(&self, req: Request<crate::state::State>) -> anyhow::Result<Box<dyn RpcRetEncode>>;
}

async fn exec(req: Request<crate::state::State>, c: Call) -> anyhow::Result<Vec<u8>> {
    let c: Box<dyn RpcExec> = match c {
        Call::GetUserIdFromEmail(i) => Box::new(i),
        Call::SignupStart(i) => Box::new(i),
        Call::SignupFinish(i) => Box::new(i),
        Call::LoginStart(i) => Box::new(i),
        Call::LoginFinish(i) => Box::new(i),
    };

    c.exec(req).await?.encode()
}


pub async fn rpc(mut req: Request<crate::state::State>) -> tide::Result {
    let body = req.body_bytes().await?;
    let c: api::Call = rmp_serde::from_slice(&body)?;

    let resp = exec(req, c).await?;
    Ok(Body::from_bytes(resp).into())
}