use serde::{Deserialize, Serialize, de::DeserializeOwned};
use crate::api;
use super::TokenKind;

#[derive(Serialize, Deserialize, Debug)]
pub struct Inner {
    pub user_id: Vec<u8>,
    pub valid_until: i64, // unix timestamp in seconds
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Token {
    Session(Inner),
    Uber(Inner),
}

impl Token {
    pub fn new(user_id: Vec<u8>, session_duration_sec: i64, token_kind: TokenKind) -> Self {
        let inner = Inner {
            user_id,
            valid_until: (chrono::Utc::now() + chrono::Duration::minutes(session_duration_sec)).timestamp(),
        };
        match token_kind {
            TokenKind::Session => {
                Token::Session(inner)
            }
            TokenKind::Uber => {
                Token::Uber(inner)
            }
        }
    }

    pub fn seal(&self, key: &[u8]) -> eyre::Result<Vec<u8>> {
        crate::crypto::sealed::Sealed::seal(key, &(), &self)
    }

    pub fn unseal(key: &[u8], sealed_session_token: &[u8], token_kind: TokenKind) -> api::Result<Self> {
        let (_, this) = crate::crypto::sealed::Sealed::<(), _>::unseal(key, sealed_session_token)?;
        match (&token_kind, &this) {
            (TokenKind::Session, Token::Session(_)) | (TokenKind::Uber, Token::Uber(_)) => Ok(this),
            _ => Err(api::Error::ServerSideError(eyre::eyre!("invalid token kind, expected {:?}", token_kind))),
        }
    }

    pub fn get_user_id(&self) -> &[u8] {
        &match self {
            Token::Session(inner) => inner,
            Token::Uber(inner) => inner,
        }.user_id
    }
}