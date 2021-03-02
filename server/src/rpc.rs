use std::net::IpAddr;

use eyre::eyre;
use common::api::{self, Call};
use futures_util::TryFutureExt;
use tracing::{Instrument, error, info, info_span};

use crate::state::State;

pub fn log_error(e: &api::Error) {
    match e {
        api::Error::ServerSideError(_) | api::Error::ClientSideError(_) => error!("{0:#?}\n{0:?}", e), // never supposed to happen
        // TODO implement ServerSideWarn
        _ => info!("{}", e)
    }
}

pub async fn rpc(state: &State, req: &Req, body: &[u8]) -> api::Result<Vec<u8>> {
    let c: api::Call = rmp_serde::from_slice(&body).map_err(|e| eyre!(e))?;

    // this dispatch is verbose, convoluted and repetitive but factoring this requires even more complex polymorphism which is not worth it
    let resp = async { match c {
        Call::NewCredentials(args) => rmp_serde::encode::to_vec_named(&state.new_credentials(&args)
            .inspect_err(log_error)
            .instrument(info_span!("NewCredentials"))
            .await),
        Call::NewUser(args) => rmp_serde::encode::to_vec_named(&state.new_user(&args)
            .inspect_err(log_error)
            .instrument(info_span!("NewUser", username = %String::from_utf8_lossy(&args.username).into_owned()))
            .await),
        Call::ChangeUserCredentials(args) => rmp_serde::encode::to_vec_named(&state.change_user_credentials(&args)
            .inspect_err(log_error)
            .instrument(info_span!("UpdateUserCredentials", username = %if args.recovery {bs58::encode(&args.username).into_string()} else { String::from_utf8_lossy(&args.username).into_owned()}, recovery = %args.recovery))
            .await),
        
        Call::LoginStart(args) => rmp_serde::encode::to_vec_named(&state.login_start(&args)
            .inspect_err(log_error)
            .instrument(info_span!("LoginStart", username = %if args.recovery {bs58::encode(&args.username).into_string()} else { String::from_utf8_lossy(&args.username).into_owned()}, recovery = %args.recovery))
            .await),
        Call::LoginFinish(args) => rmp_serde::encode::to_vec_named(&state.login_finish(&args)
            .inspect_err(log_error)
            .instrument(info_span!("LoginFinish", uber = %args.uber_token))
            .await),

        Call::GetUsername(args) => rmp_serde::encode::to_vec_named(&state.get_username(&args)
            .inspect_err(log_error)
            .instrument(info_span!("GetUsername"))
            .await),

        Call::ChangeTotp(args) => rmp_serde::encode::to_vec_named(&state.change_totp(&args)
            .inspect_err(log_error)
            .instrument(info_span!("UpdateTotp"))
            .await),
    }}.instrument(info_span!("rpc", %req.ip, req.port)).await;

    Ok(resp.map_err(|e| eyre!(e))?)
}

pub struct Req {
    pub ip: IpAddr,
    pub port: u16,
}

