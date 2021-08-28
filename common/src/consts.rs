pub const DATABASE_NAME: &str = "cachou";
pub const OPAQUE_S_ID: [u8; 32] =          hex_literal::hex!("71a39610745b1f6601ec0699e32452175fd722f9dad797fb43276bb013c706ce"); // our domain name might change, so let's just use some random bytes
pub const OPAQUE_S_ID_RECOVERY: [u8; 32] = hex_literal::hex!("fd11af55478d969d614923a4633a726dac709520ec90be404169a2e607d5ede1"); // our domain name might change, so let's just use some random bytes
pub const OPAQUE_SETUP_PATH: &str = "opaque_setup.toml";
pub const SECRET_KEY_PATH: &str = "secret_key.bin";
pub const CONFIG_PATH: &str = "config.toml";