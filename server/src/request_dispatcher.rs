use std::net::IpAddr;

use eyre::eyre;
use common::api::{self, Call};
use futures_util::TryFutureExt;
use tracing::{Instrument, error, info, info_span};
use common::api::Rpc;
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
    let c: api::Call = rmp_serde::from_slice(&body).map_err(|e| eyre!(e))?;

    // acquire a set a lazily constructed connection and transaction from the pool
    let mut conn = state.db_pool.acquire();

    // this dispatch is verbose, convoluted and repetitive but factoring this requires even more complex polymorphism which is not worth it
    let resp = async { match c {
        Call::AddUser(args) => rmp_serde::encode::to_vec_named(&state.add_user(&args, &mut conn)
            .inspect_err(log_error)
            .instrument(info_span!(api::AddUser::DISPLAY_NAME))
            .await),

        Call::NewCredentials(args) => rmp_serde::encode::to_vec_named(&state.new_credentials(&args, &mut conn)
            .inspect_err(log_error)
            .instrument(info_span!(api::NewCredentials::DISPLAY_NAME))
            .await),

        Call::SetCredentials(args) => rmp_serde::encode::to_vec_named(&state.set_credentials(&args, &mut conn)
            .inspect_err(log_error)
            .instrument(info_span!(api::SetCredentials::DISPLAY_NAME))
            .await),
        
        Call::LoginStart(args) => rmp_serde::encode::to_vec_named(&state.login_start(&args, &mut conn)
            .inspect_err(log_error)
            .instrument(info_span!(api::LoginStart::DISPLAY_NAME))
            .await),

        Call::LoginFinish(args) => rmp_serde::encode::to_vec_named(&state.login_finish(&args, &mut conn)
            .inspect_err(log_error)
            .instrument(info_span!(api::LoginFinish::DISPLAY_NAME))
            .await),

        Call::GetUserPrivateData(args) => rmp_serde::encode::to_vec_named(&state.get_user_private_data(&args, &mut conn)
            .inspect_err(log_error)
            .instrument(info_span!(api::GetUserPrivateData::DISPLAY_NAME))
            .await),

        Call::SetUserPrivateData(args) => rmp_serde::encode::to_vec_named(&state.set_user_private_data(&args, &mut conn)
            .inspect_err(log_error)
            .instrument(info_span!(api::SetUserPrivateData::DISPLAY_NAME))
            .await),
    }}.instrument(info_span!("rpc", %req.ip, req.port)).await;

    // commit or rollback to Db based on result state
    match resp {
        Ok(r) => {
            conn.commit().await?;
            Ok(r)
        }
        Err(e) => {
            conn.rollback().await?;
            Err(eyre!(e).into())
        }
    }
}

pub struct Req {
    pub ip: IpAddr,
    pub port: u16,
}

