# ZDECHLAK Client

Public Windows x64 OTClient package and signed update channel for [zdechlak.pl](https://zdechlak.pl).

## Download

See [GitHub Releases](https://github.com/wojewodzki12/zdechlak-client/releases) for `ZDECHLAK-OTC-*-windows-x64.zip`.

Extract and run `ZDECHLAK Launcher.exe`.

## Update channel

`https://raw.githubusercontent.com/wojewodzki12/zdechlak-client/updates/v1`

- `GET .../manifest.json` — Ed25519-signed envelope
- `GET .../objects/<sha256>` — content-addressed files

Launcher auto-checks this endpoint on every start.
