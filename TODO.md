- prevent user enumeration: https://github.com/cfrg/draft-irtf-cfrg-opaque/issues/22

- validate token TTL, and also opaque_state

- create client errors

- server-side, log user errors differently

- fix overriding of tracing levels from env var

- factorise sealed stuff in API

- check that replay attack are not an issue with our stateless OPAQUE negociation

- refactor DB abstraction

- implement recover from masterkey

- implement web of trust

- implement votes