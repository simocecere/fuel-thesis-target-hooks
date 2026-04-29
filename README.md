# Target Hooks Package

Questa cartella contiene solo i file di codice che conviene pubblicare in una
repo separata per avere link puliti da inserire nelle slide.

## Contenuto

- `openssl/statem_lib.c`
  - hook OpenSSL lato generator
- `libressl/tls13_handshake.c`
  - hook LibreSSL lato generator
- `gnutls/fuel_client_hello_hook_reference.c`
  - copia di riferimento leggibile del blocco hook GnuTLS

## Perché questa struttura

- evita di caricare l'intero tree dei target
- mantiene i file che servono davvero al prof
- rende i path GitHub più corti e leggibili

## Come usarla

1. Carica `target_hooks/` in una repo GitHub separata.
2. Mantieni questa struttura di cartelle.
3. Usa `LINKS_TEMPLATE.md` per costruire i link definitivi da mettere nelle slide.

## Nota su GnuTLS

Il file GnuTLS qui presente è un file di riferimento pensato per review e
presentazione. Il codice reale nel progetto è ottenuto tramite injection nello
script di build, ma per linkare il hook in modo chiaro questo file è molto più
adatto.
