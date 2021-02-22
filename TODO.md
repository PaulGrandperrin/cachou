- rewrite client-common: better modules, don't reify auth status in typestate, don't loose so easily connection and auth status

- token: check TTL, and add TTL to opaque_state

- factorise sealed stuff in API

- check that replay attack are not an issue with our stateless OPAQUE negociation

- refactor DB abstraction

- allow changing login
- allow changing password
- implement recover from masterkey
- allow changing masterkey

- implement web of trust


- implement votes