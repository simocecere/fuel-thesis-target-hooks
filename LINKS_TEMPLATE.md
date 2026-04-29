# Link Template per le Slide

Sostituisci:

- `<OWNER>` con il tuo username GitHub
- `<REPO>` con la repo in cui caricherai `target_hooks`
- `<BRANCH>` con il branch da usare, di solito `main`

Base:

```text
https://github.com/<OWNER>/<REPO>/blob/<BRANCH>
```

## OpenSSL

- Hook principale:
  - `https://github.com/<OWNER>/<REPO>/blob/<BRANCH>/openssl/statem_lib.c#L292`
- Repair `key_share`:
  - `https://github.com/<OWNER>/<REPO>/blob/<BRANCH>/openssl/statem_lib.c#L127`
- Sync `session_id`:
  - `https://github.com/<OWNER>/<REPO>/blob/<BRANCH>/openssl/statem_lib.c#L214`

## LibreSSL

- Hook helper:
  - `https://github.com/<OWNER>/<REPO>/blob/<BRANCH>/libressl/tls13_handshake.c#L29`
- Call-site nel send path:
  - `https://github.com/<OWNER>/<REPO>/blob/<BRANCH>/libressl/tls13_handshake.c#L498`

## GnuTLS

- Hook principale:
  - `https://github.com/<OWNER>/<REPO>/blob/<BRANCH>/gnutls/fuel_client_hello_hook_reference.c#L285`
- Parser del `ClientHello`:
  - `https://github.com/<OWNER>/<REPO>/blob/<BRANCH>/gnutls/fuel_client_hello_hook_reference.c#L53`
- Sync `session_id`:
  - `https://github.com/<OWNER>/<REPO>/blob/<BRANCH>/gnutls/fuel_client_hello_hook_reference.c#L237`
- Restore `key_share`:
  - `https://github.com/<OWNER>/<REPO>/blob/<BRANCH>/gnutls/fuel_client_hello_hook_reference.c#L255`

## Mapping slide -> link

- Slide OpenSSL:
  - `tls_close_construct_packet()`
  - `fuel_restore_clienthello_key_share()`
  - `fuel_sync_clienthello_state()`
- Slide LibreSSL:
  - `fuel_fuzz_handshake_msg()`
  - call dentro `tls13_handshake_send_action()`
- Slide GnuTLS:
  - `fuel_mutate_client_hello()`
  - `fuel_parse_client_hello()`
  - opzionale: `fuel_sync_client_hello_session_id()` / `fuel_restore_client_hello_key_share()`
