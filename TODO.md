- move out sealed_session_token outside of each requests
  - and then imbric some requests in others, like for new_user

- add reed-solomon on recovery-key

- fix insertion of new credentials, overriding old ones

- server/auth: trace more args fields

- compile both tokio and async stuff on test cfg 

- reimplement totp

- finish implementing auto_logout

- validate username client-side and server-side (alphanum only)

- TOTP: 1 pass should allow only one login!

- implement ServerSideWarn

- refactor client and logged_user. and ensure to never save to disk uber token

- prevent user enumeration: https://github.com/cfrg/draft-irtf-cfrg-opaque/issues/22

- setup panic handler to trace panics. see https://github.com/tokio-rs/tracing/issues/587

- validate sealed_opaque_state TTL 
  factorise sealed stuff in API: sealed_opaque_state and sealed_session_token

- check that replay attack are not an issue with our stateless OPAQUE negociation

- implement web of trust

- implement votes

- create a new newtype generic for constant-sized vectors / keys
- use subtle (for constant-time cmp), zeroize and other type system tricks when useful
- unicode/ utf8 normalization

POST MVC

- MFA: backup codes, TOTP, WebAuthn
- add delay to recovery procedure
- add alterting when recovery: email

- encrypt username at all time (check if possible through OPAQUE)