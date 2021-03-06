use std::io::{BufRead, Cursor};
use reqwest::{Method, StatusCode};
use sha1::{Digest, Sha1};
use eyre::{WrapErr, eyre};

pub async fn check_password(password: &str) -> eyre::Result<u64>
{
    let hash = data_encoding::HEXLOWER.encode(Sha1::digest(password.as_bytes()).as_slice());
    let split_hash = hash.split_at(5);

    let url = format!("{}{}", "https://api.pwnedpasswords.com/range/", split_hash.0);

    let resp = reqwest::Client::new()
        .request( Method::GET, &url)
        .header("Add-Padding", "true")
        .send().await?;

    match resp.status() {
        StatusCode::OK => {
            let body = Cursor::new(resp.text().await?);
            for line in body.lines() {
                let lower_line = line.wrap_err("failed to parse HIBP response")?.to_lowercase();
                let mut split_line = lower_line.split(':');
                let line_hash = split_line.next().ok_or_else(|| eyre!("failed to parse HIBP response"))?;
                if line_hash == split_hash.1 {
                    let count = split_line.next().ok_or_else(|| eyre!("failed to parse HIBP response"))?;
                    return count.parse::<u64>().wrap_err("failed to parse HIBP response");
                }
            }
            Ok(0)
        },
        status => {
            Err(eyre!("HIBP responded with status code {}", status))
        }
    }
}

