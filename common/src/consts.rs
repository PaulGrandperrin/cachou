pub const DATABASE_NAME: &str = "cachou";
pub const OPAQUE_ID_S: [u8; 32] = hex_literal::hex!("71a39610745b1f6601ec0699e32452175fd722f9dad797fb43276bb013c706ce"); // our domain name might change, so let's just use some random bytes
pub const OPAQUE_PRIVATE_KEY_PATH: &str = "opaque_private_key.bin";
pub const SECRET_KEY_PATH: &str = "secret_key.bin";
pub const CONFIG_PATH: &str = "config.toml";