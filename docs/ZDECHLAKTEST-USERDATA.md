# ZDECHLAKTEST isolated user data (test phase)

**Status:** development / test only. Stable v1.0.4 is unchanged and must not be migrated yet.

## Exact paths

Recovered OTCv8 uses `PHYSFS_getPrefDir("OTClientV8", APP_NAME)`.

| Build | `APP_NAME` | Physical user-data root |
| --- | --- | --- |
| Stable 1.0.4 | `tibiaotcv8` | `%APPDATA%\OTClientV8\tibiaotcv8\` |
| Test 1.0.5 | `ZDECHLAKTEST` | `%APPDATA%\ZDECHLAKTEST\` |

For 1.0.5-test the launcher reads `userdata_appdata=ZDECHLAKTEST` from `config/updater.json` and creates a directory symlink:

`%APPDATA%\OTClientV8\ZDECHLAKTEST` → `%APPDATA%\ZDECHLAKTEST`

so OTCv8 writes land in the requested folder. Fallback (no symlink privilege): redirect process `APPDATA` to `%APPDATA%\ZDECHLAKTEST` (nested `OTClientV8\ZDECHLAKTEST` under that root).

## What is stored there

All OTCv8 persistent data (via PHYSFS write dir), including:

- `config.otml` (window, settings)
- `hotkeys_*.otml`
- `/settings/` (profiles, actionbar, topbar, outfit, questlog, …)
- `/bot/` (CaveBot / TargetBot / vBot configs, waypoints, storage)
- minimap (`minimap*.otmm`) when created
- console exports under `/user_dir/` when used

Updater-managed files stay under install `runtime/releases/` only. User data is never in the signed payload allowlist.

## Isolation rules (this phase)

- Do **not** use `%APPDATA%\ZDECHLAK\`
- Do **not** migrate to/from `%APPDATA%\ZDECHLAK\`
- Do **not** touch other OTC profiles (`tibiaotcv8`, foreign clients)
- Stable channel `updates/v2` stays on 1.0.4

## Test package

- Release: https://github.com/wojewodzki12/zdechlak-client/releases/tag/v1.0.5-test
- Channel: https://raw.githubusercontent.com/wojewodzki12/zdechlak-client/updates/v1-test-105
- Server: `146.59.52.154:7171`, protocol `860`

## Future migration plan (NOT executed)

See `docs/ZDECHLAKTEST-TO-ZDECHLAK-MIGRATION-PLAN.md`.
