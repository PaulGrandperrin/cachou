use std::net::IpAddr;

use eyre::eyre;
use common::api::{self, Rpc};
use futures_util::TryFutureExt;
use tracing::{Instrument, error, info, info_span};
use common::api::RpcTrait;
use crate::state::State;

pub fn log_error(e: &api::Error) {
    match e {
        api::Error::ServerSideError(_) | api::Error::ClientSideError(_) => error!("{0:#?}\n{0:?}", e), // never supposed to happen
        // TODO implement ServerSideWarn
        _ => info!("{}", e)
    }
}
// TODO call a generic method instead
pub async fn rpc(state: &State, req: &Req, body: &[u8]) -> api::Result<Vec<u8>> {
    // deserialize request
    let c: api::Rpc = rmp_serde::from_slice(&body).map_err(|e| eyre!(e))?;

    // acquire a set a lazily constructed connection and transaction from the pool
    let mut conn = state.db_pool.acquire();

    // used later to commit or rollback DBConn
    let mut got_error = false;

    // this dispatch is verbose, convoluted and repetitive but factoring this requires even more complex polymorphism which is not worth it
    let resp = async { match c {
        Rpc::AddUser(args) => rmp_serde::encode::to_vec_named(&state.add_user(&args, &mut conn)
            .inspect_err(|e| {log_error(e); got_error = true})
            .instrument(info_span!(api::AddUser::DISPLAY_NAME))
            .await),

        Rpc::NewCredentials(args) => rmp_serde::encode::to_vec_named(&state.new_credentials(&args, &mut conn)
            .inspect_err(|e| {log_error(e); got_error = true})
            .instrument(info_span!(api::NewCredentials::DISPLAY_NAME))
            .await),

        Rpc::SetCredentials(args) => rmp_serde::encode::to_vec_named(&state.set_credentials(&args, &mut conn)
            .inspect_err(|e| {log_error(e); got_error = true})
            .instrument(info_span!(api::SetCredentials::DISPLAY_NAME))
            .await),

        Rpc::GetExportKeys(args) => rmp_serde::encode::to_vec_named(&state.get_export_keys(&args, &mut conn)
            .inspect_err(|e| {log_error(e); got_error = true})
            .instrument(info_span!(api::GetExportKeys::DISPLAY_NAME))
            .await),

        Rpc::RotateMasterKey(args) => rmp_serde::encode::to_vec_named(&state.rotate_master_key(&args, &mut conn)
            .inspect_err(|e| {log_error(e); got_error = true})
            .instrument(info_span!(api::RotateMasterKey::DISPLAY_NAME))
            .await),
        
        Rpc::LoginStart(args) => rmp_serde::encode::to_vec_named(&state.login_start(&args, &mut conn)
            .inspect_err(|e| {log_error(e); got_error = true})
            .instrument(info_span!(api::LoginStart::DISPLAY_NAME))
            .await),

        Rpc::LoginFinish(args) => rmp_serde::encode::to_vec_named(&state.login_finish(&args, &mut conn)
            .inspect_err(|e| {log_error(e); got_error = true})
            .instrument(info_span!(api::LoginFinish::DISPLAY_NAME))
            .await),

        Rpc::GetUserPrivateData(args) => rmp_serde::encode::to_vec_named(&state.get_user_private_data(&args, &mut conn)
            .inspect_err(|e| {log_error(e); got_error = true})
            .instrument(info_span!(api::GetUserPrivateData::DISPLAY_NAME))
            .await),

        Rpc::SetUserPrivateData(args) => rmp_serde::encode::to_vec_named(&state.set_user_private_data(&args, &mut conn)
            .inspect_err(|e| {log_error(e); got_error = true})
            .instrument(info_span!(api::SetUserPrivateData::DISPLAY_NAME))
            .await),
    }}.instrument(info_span!("rpc", %req.ip, req.port)).await.map_err(|e| eyre!(e).into());

    // commit or rollback to DbConn
    if got_error {
        conn.rollback().await?;
    } else {
        conn.commit().await?;
    }

    resp
}

pub struct Req {
    pub ip: IpAddr,
    pub port: u16,
}

