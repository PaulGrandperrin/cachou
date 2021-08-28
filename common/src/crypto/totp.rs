use std::{convert::TryInto, time::SystemTime};

use data_encoding::BASE32_NOPAD;
use eyre::{eyre, ContextCompat, WrapErr, bail};
use hmac::{Hmac, Mac, NewMac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use url::Url;
use url::Host::Domain;

// from RFC6238
pub fn check_totp(uri: &str, input: &str) -> eyre::Result<()> {
    let (secret, digits, algo, period) = parse_totp_uri(uri)?;

    let time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH).unwrap()
        .as_secs();

    let counter = time / period as u64;

    for c in counter - 1 ..= counter {
        let totp = match algo.as_str() {
            "SHA1" => hotp::<Hmac<Sha1>>(&secret, digits, c),
            "SHA256" => hotp::<Hmac<Sha256>>(&secret, digits, c),
            "SHA512" => hotp::<Hmac<Sha512>>(&secret, digits, c),
            _ => bail!("unknown algorithm {:?}", algo),
        }?;

        if totp == input {
            return Ok(())
        }
    }

    bail!("invalid TOTP")
}

// from RFC4226 and RFC6238
pub fn hotp<M: NewMac + Mac>(secret: &[u8], digits: u8, counter: u64) -> eyre::Result<String>
{
    // hash the counter with the secret key
    let counter = counter.to_be_bytes();
    let mut hasher = M::new_from_slice(&secret).map_err(|_| eyre!("invalid secret length"))?;
    hasher.update(&counter);
    let hash = hasher.finalize().into_bytes().to_vec();

    // dynamic truncation
    let offset = (hash.last().unwrap() & 0xF) as usize;
    let binary = u32::from_be_bytes(hash[offset..offset+4].try_into().unwrap()) & 0x7F_FF_FF_FF;

    Ok(format!("{:01$}", binary % (10_u32.pow(digits as u32)), digits as usize))
}

// from https://github.com/google/google-authenticator/wiki/Key-Uri-Format
pub fn parse_totp_uri(uri: &str) -> eyre::Result<(Vec<u8>, u8, String, u32)> {
    let uri = Url::parse(uri)
        .wrap_err("failed to parse url")?;
    
    if uri.scheme() != "otpauth" || uri.host() != Some(Domain("totp")) { bail!("not an 'otpauth://totp/' URL") }
    
    // find, extract and parse the secret
    let secret = BASE32_NOPAD.decode(
        uri.query_pairs().find_map(|(k, v)| {
            if k == "secret" { Some(v) } else { None }
        }).wrap_err("attribute 'secret' not found")?.as_bytes()
    ).wrap_err("failed to decode 'secret'")?;

    let digits = match uri.query_pairs().find_map(|(k, v)| {
        if k == "digits" { Some(v.to_string()) } else { None }
    }).unwrap_or_else(|| "6".to_string())
    .parse::<u8>().wrap_err("failed to parse 'digits'")? {
        d @ 6 | d @ 8 => d,
        _ => bail!("'digits' must be 6 or 8")
    };

    let algo = match uri.query_pairs().find_map(|(k, v)| {
        if k == "algorithm" { Some(v.to_string()) } else { None }
    }).unwrap_or_else(|| "SHA1".to_string()).as_str() {
        a @ "SHA1" | a @ "SHA256" | a @ "SHA512" => a.to_string(),
        _ => bail!("'invalid 'algorithm'")
    };

    let period = uri.query_pairs().find_map(|(k, v)| {
        if k == "period" { Some(v.to_string()) } else { None }
    }).unwrap_or_else(|| "30".to_string())
    .parse::<u32>().wrap_err("failed to parse 'period'")?;

    Ok((secret, digits, algo, period))
}

