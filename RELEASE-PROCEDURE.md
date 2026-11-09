# ZDECHLAK OTC — repeatable release procedure

Signing key stays offline in `.dev-keys/manifest-ed25519.pem` (never ship it).
Public trust anchor is embedded in `ZDECHLAK Launcher.exe` via `scripts.configure_trust`.

## 1. Prepare payload

Recovered/built client tree must contain:

- `ZDECHLAK-client.exe` (+ root `*.dll`)
- `init.lua` (Server `146.59.52.154:7171`, protocol 860)
- `data/`, `modules/` (incl. vBot CaveBot/TargetBot), `layouts/`, `licenses/`
- `data/things/860/Tibia.dat` and `Tibia.spr`
- `build-info.json`

## 2. Configure launcher trust (once per key/endpoint change)

```bash
cd client-build
python3 -m scripts.configure_trust \
  --public .dev-keys/manifest-ed25519.pub \
  --endpoint 'https://raw.githubusercontent.com/wojewodzki12/zdechlak-client/updates/v1' \
  --enable-updates --purpose release
cmake -S updater/native -B build/cross/launcher-rebuild \
  -DCMAKE_TOOLCHAIN_FILE=scripts/mingw-x64.cmake -DCMAKE_BUILD_TYPE=Release
cmake --build build/cross/launcher-rebuild -j
```

## 3. Sign and publish sequence N

```bash
python3 - <<'PY'
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from updater.publisher import publish
key = serialization.load_pem_private_key(Path('.dev-keys/manifest-ed25519.pem').read_bytes(), password=None)
publish(Path('build/windows-payload'), Path('build/update-endpoint'), key, '1.0.N', N, lifetime=31*86400)
PY
```

Sequence must strictly increase. Copy `manifest.json` + new `objects/*` onto branch `updates` under `v1/`, then `git push origin updates`.
Replace `v1/manifest.json` **last** (after objects exist).

## 4. Player ZIP

Seed `runtime/` with the previous (or current) signed release, copy:

- `ZDECHLAK Launcher.exe`
- `config/updater.json` (`enabled: true`, same endpoint)

Zip as `ZDECHLAK-OTC-<version>-windows-x64.zip` and publish a GitHub Release asset.

## 5. Verify A→B

From a seeded A install, run launcher or Python `Store.install` against the live endpoint and confirm only changed files download and `build-info.json` shows the new version. Previous release remains for rollback.

## Notes

- AppData settings / bot profiles are outside `runtime/releases/` and are never updated.
- Manifest lifetime max 31 days; re-sign before expiry if no content change.
- Launcher binary itself is not auto-updated; ship a new ZIP when the launcher/trust anchor changes.

## Launcher runtime (MinGW)

Cross-build with `-static` so the launcher does **not** depend on `libwinpthread-1.dll`,
`libgcc_s_seh-1.dll`, or `libstdc++-6.dll`. Verify before shipping:

```bash
x86_64-w64-mingw32-objdump -p build/cross/launcher-rebuild/ZDECHLAK.exe | awk '/DLL Name/{print $3}'
# Must list only OS DLLs (KERNEL32, msvcrt, WINHTTP, bcrypt, SHELL32, USER32).
```

## OTC MSVC CRT

Ship these x64 DLLs next to `ZDECHLAK-client.exe` (from official `vc_redist.x64.exe`):

- `msvcp140.dll`
- `vcruntime140.dll`
- `vcruntime140_1.dll`

