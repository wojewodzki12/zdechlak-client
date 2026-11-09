# ZDECHLAK OTC — release procedure

## Channels
- `test` → `updates/v1-test` (verification only)
- `prototype` → `updates/v2` (stable for 1.0.3+)

Never publish untested builds to stable. Verify on `test` first.

## Client manifest
```bash
python3 -m updater.publisher manifest \
  --source build/windows-payload --output build/endpoint \
  --private .dev-keys/manifest-ed25519.pem \
  --version 1.0.N --sequence N --channel prototype --lifetime $((31*86400))
```

## Launcher manifest (self-update)
```bash
python3 -m updater.publisher launcher \
  --exe build/cross/launcher-rebuild/ZDECHLAK.exe --output build/endpoint \
  --private .dev-keys/manifest-ed25519.pem \
  --version 1.0.N --sequence N --channel prototype
```

Upload `manifest.json`, `launcher-manifest.json`, and new `objects/*` to the channel directory. Replace manifests **last**.

## Launcher build
Cross-link with `-static` (no libwinpthread). Verify imports are OS DLLs only.
Self-update replaces `ZDECHLAK Launcher.exe` / `ZDECHLAK.exe` via `runtime/helpers/zdechlak-apply.exe` after the parent exits.

## Player ZIP
Seed `runtime/` with the signed client release, write matching `runtime/launcher-state.json`, ship CRT DLLs, point `config/updater.json` at the stable endpoint.
