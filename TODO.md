- rewrite client-common: better modules, don't reify auth status in typestate, don't loose so easily connection and auth status

- validate token TTL, and also opaque_state

- rename newcredentials and signup

- create client errors

- server-side, log user errors differently

- when updating credentials, don't change masterkey
- but allow just rotating masterkey too

- fix overriding of tracing levels from env var

- factorise sealed stuff in API

- check that replay attack are not an issue with our stateless OPAQUE negociation

- refactor DB abstraction

- allow changing login
- allow changing password
- implement recover from masterkey
- allow changing masterkey

- implement web of trust


- implement votes