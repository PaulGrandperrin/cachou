- prevent overriding of sealed masterkey if export_key has changed in between

- TOTP: 1 pass should allow only one login!

- implement ServerSideWarn

- refactor client and logged_user. and ensure to never save to disk uber token

- prevent user enumeration: https://github.com/cfrg/draft-irtf-cfrg-opaque/issues/22

- setup panic handler to trace panics. see https://github.com/tokio-rs/tracing/issues/587

- validate token TTL, and also opaque_state

- factorise sealed stuff in API

- check that replay attack are not an issue with our stateless OPAQUE negociation

- implement web of trust

- implement votes


- separate type domains with newtypes and use subtle (for constant-time cmp), zeroize and other type system tricks when useful
- unicode/ utf8 normalization

POST MVC

- MFA: backup codes, TOTP, WebAuthn
- add delay to recovery procedure
- add alterting when recovery: email